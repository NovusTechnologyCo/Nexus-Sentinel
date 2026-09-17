/**
 * @file vmx.c
 * @brief VMX support detection, VCPU allocation, and per-CPU virtualization.
 *
 * Contains the core VMX lifecycle implementation:
 *
 *   - **ShvIsVmxSupported**: Hardware capability detection via CPUID and
 *     IA32_FEATURE_CONTROL. Reads the VMX revision ID from IA32_VMX_BASIC
 *     and validates VMCS region size.
 *
 *   - **ShvAllocateVcpuArray / ShvFreeVcpuArray**: Allocates and frees the
 *     per-processor VCPU_DATA structures using physically contiguous memory.
 *     Each VCPU contains 4KB-aligned VMXON/VMCS regions, a 4KB MSR bitmap,
 *     a 16KB host stack, and state tracking fields.
 *
 *   - **ShvVirtualizeProcessor**: The per-CPU virtualization sequence executed
 *     in IPI context. Performs context capture (setjmp-like), CR0/CR4 fixed-bit
 *     adjustment, VMXON, VMCLEAR + VMPTRLD, VMCS configuration, and VMLAUNCH.
 *     On success, the CPU transparently enters VMX non-root operation.
 */

#include "shv.h"

/* ── VMX Support Detection ────────────────────────────────────────── */

BOOLEAN
ShvIsVmxSupported(void)
{
    int cpuInfo[4] = { 0 };

    /* Check CPUID.1:ECX.VMX (bit 5) */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 5))) {
        SHV_ERR("CPUID: VMX not supported");
        return FALSE;
    }
    SHV_LOG("CPUID: VMX supported");

    /* Check IA32_FEATURE_CONTROL MSR */
    ULONG64 featureControl = __readmsr(IA32_FEATURE_CONTROL);

    if (!(featureControl & FEATURE_CONTROL_LOCK)) {
        /* Feature control not locked — in theory we could lock it ourselves,
         * but this indicates BIOS hasn't enabled VT-x. */
        SHV_ERR("IA32_FEATURE_CONTROL: not locked (BIOS VT-x not enabled)");
        return FALSE;
    }

    if (!(featureControl & FEATURE_CONTROL_VMXON_OUTSIDE)) {
        SHV_ERR("IA32_FEATURE_CONTROL: VMXON outside SMX not enabled");
        return FALSE;
    }
    SHV_LOG("IA32_FEATURE_CONTROL: VMX enabled and locked");

    /* Read IA32_VMX_BASIC for revision ID and capabilities */
    ULONG64 vmxBasic = __readmsr(IA32_VMX_BASIC);
    g_Shv.VmxRevisionId = (ULONG32)(vmxBasic & 0x7FFFFFFF);

    BOOLEAN trueControlsSupported = (vmxBasic >> 55) & 1;
    SHV_LOG("VMX revision ID: 0x%08X, true controls: %s",
            g_Shv.VmxRevisionId,
            trueControlsSupported ? "yes" : "no");

    /* Verify VMCS region size fits in 4KB */
    ULONG32 vmcsSize = (ULONG32)((vmxBasic >> 32) & 0x1FFF);
    if (vmcsSize > 4096) {
        SHV_ERR("VMCS region size %lu exceeds 4KB", vmcsSize);
        return FALSE;
    }

    return TRUE;
}

/* ── VCPU Allocation ──────────────────────────────────────────────── */

NTSTATUS
ShvAllocateVcpuArray(void)
{
    g_Shv.ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    SHV_LOG("Active processor count: %lu", g_Shv.ProcessorCount);

    /* Allocate the pointer array */
    #pragma warning(suppress: 4996)
    g_Shv.VcpuArray = (PVCPU_DATA*)ExAllocatePoolWithTag(
        NonPagedPool,
        g_Shv.ProcessorCount * sizeof(PVCPU_DATA),
        'eSmM'
    );
    if (!g_Shv.VcpuArray) {
        SHV_ERR("Failed to allocate VcpuArray");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_Shv.VcpuArray, g_Shv.ProcessorCount * sizeof(PVCPU_DATA));

    /* Allocate each VCPU using contiguous memory (PA must be 4KB-aligned) */
    for (ULONG i = 0; i < g_Shv.ProcessorCount; i++) {
        PVCPU_DATA vcpu = (PVCPU_DATA)ShvAllocateContiguousMemory(sizeof(VCPU_DATA));
        if (!vcpu) {
            SHV_ERR("Failed to allocate VCPU for CPU %lu", i);
            ShvFreeVcpuArray();
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(vcpu, sizeof(VCPU_DATA));
        vcpu->ProcessorIndex = i;
        vcpu->Launched = FALSE;
        vcpu->VmxActive = FALSE;

        /* Get physical addresses */
        vcpu->VmxonRegionPa = MmGetPhysicalAddress(&vcpu->VmxonRegion).QuadPart;
        vcpu->VmcsRegionPa = MmGetPhysicalAddress(&vcpu->VmcsRegion).QuadPart;
        vcpu->MsrBitmapPa = MmGetPhysicalAddress(&vcpu->MsrBitmap).QuadPart;
        /* Item #9 — #VE info area: zeroed at allocation (RtlZeroMemory on
         * the whole VCPU_DATA above), PA captured here for VMCS write. */
        vcpu->VeInfoAreaPa = MmGetPhysicalAddress(&vcpu->VeInfoArea).QuadPart;

        /* Host stack top = base + size (stack grows downward) */
        vcpu->HostStackTop = (ULONG64)&vcpu->HostStack[SHV_HOST_STACK_SIZE];

        /* Initialize VMXON region with revision ID */
        vcpu->VmxonRegion.RevisionId = g_Shv.VmxRevisionId;
        vcpu->VmxonRegion.AbortIndicator = 0;

        /* Initialize VMCS region with revision ID */
        vcpu->VmcsRegion.RevisionId = g_Shv.VmxRevisionId;
        vcpu->VmcsRegion.AbortIndicator = 0;

        /* MSR bitmap: all zeros = passthrough all MSRs */
        RtlZeroMemory(vcpu->MsrBitmap, sizeof(vcpu->MsrBitmap));

        g_Shv.VcpuArray[i] = vcpu;

        SHV_LOG("CPU %lu: VCPU @ %p, VMXON PA 0x%llX, VMCS PA 0x%llX, MSR bitmap PA 0x%llX",
                i, vcpu, vcpu->VmxonRegionPa, vcpu->VmcsRegionPa, vcpu->MsrBitmapPa);
    }

    return STATUS_SUCCESS;
}

void
ShvFreeVcpuArray(void)
{
    if (!g_Shv.VcpuArray) {
        return;
    }

    for (ULONG i = 0; i < g_Shv.ProcessorCount; i++) {
        if (g_Shv.VcpuArray[i]) {
            ShvFreeContiguousMemory(g_Shv.VcpuArray[i], sizeof(VCPU_DATA));
            g_Shv.VcpuArray[i] = NULL;
        }
    }

    ExFreePoolWithTag(g_Shv.VcpuArray, 'eSmM');
    g_Shv.VcpuArray = NULL;
}

/* ── Per-CPU Virtualization ───────────────────────────────────────── */

NTSTATUS
ShvVirtualizeProcessor(
    _In_ PVCPU_DATA Vcpu
    )
{
    NTSTATUS status;
    ULONG cpuIndex = Vcpu->ProcessorIndex;

    SHV_LOG("CPU %lu: Starting virtualization...", cpuIndex);
    ShvCmosWrite(SHV_CMOS_CPU_IDX, (UCHAR)cpuIndex);

    /*
     * Step 1: Capture current context.
     * ShvCaptureContext saves GPRs, RSP, RIP (return address), RFLAGS.
     * Returns 0 on first call. After VMLAUNCH, guest resumes here and
     * ShvCaptureContext returns 1.
     */
    ULONG64 resumed = ShvCaptureContext(&Vcpu->CapturedContext);
    if (resumed != 0) {
        /* We're now running as a guest! VMLAUNCH succeeded. */
        SHV_LOG("CPU %lu: Running as VMX guest", cpuIndex);
        Vcpu->VmxActive = TRUE;
        return STATUS_SUCCESS;
    }

    /* First call — proceed with VMX setup */

    /* Save original state for devirtualization */
    Vcpu->OriginalCr0 = __readcr0();
    Vcpu->OriginalCr3 = __readcr3();
    Vcpu->OriginalCr4 = __readcr4();

    ShvSgdt(&Vcpu->OriginalGdtr);
    ShvSidt(&Vcpu->OriginalIdtr);

    /*
     * Step 2: Adjust CR0 and CR4 per VMX fixed-bit MSRs.
     * Bits in fixed0 MUST be 1; bits NOT in fixed1 MUST be 0.
     */
    ULONG64 cr0Fixed0 = __readmsr(IA32_VMX_CR0_FIXED0);
    ULONG64 cr0Fixed1 = __readmsr(IA32_VMX_CR0_FIXED1);
    ULONG64 cr4Fixed0 = __readmsr(IA32_VMX_CR4_FIXED0);
    ULONG64 cr4Fixed1 = __readmsr(IA32_VMX_CR4_FIXED1);

    ULONG64 cr0 = (__readcr0() | cr0Fixed0) & cr0Fixed1;
    ULONG64 cr4 = (__readcr4() | cr4Fixed0) & cr4Fixed1;

    /* CR4.VMXE must be set before VMXON */
    cr4 |= CR4_VMXE;

    __writecr0(cr0);
    __writecr4(cr4);

    /*
     * Step 3: VMXON
     */
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_CPU_VMXON | (cpuIndex & 0x0F));
    int vmxResult = __vmx_on(&Vcpu->VmxonRegionPa);
    if (vmxResult != 0) {
        SHV_ERR("CPU %lu: VMXON failed (result=%d)", cpuIndex, vmxResult);
        /* Restore original CR4 (remove VMXE) */
        __writecr4(Vcpu->OriginalCr4);
        return STATUS_UNSUCCESSFUL;
    }
    SHV_LOG("CPU %lu: VMXON successful", cpuIndex);

    /*
     * Step 4: VMCLEAR + VMPTRLD (activate our VMCS)
     */
    vmxResult = __vmx_vmclear(&Vcpu->VmcsRegionPa);
    if (vmxResult != 0) {
        SHV_ERR("CPU %lu: VMCLEAR failed (result=%d)", cpuIndex, vmxResult);
        __vmx_off();
        __writecr4(Vcpu->OriginalCr4);
        return STATUS_UNSUCCESSFUL;
    }

    vmxResult = __vmx_vmptrld(&Vcpu->VmcsRegionPa);
    if (vmxResult != 0) {
        SHV_ERR("CPU %lu: VMPTRLD failed (result=%d)", cpuIndex, vmxResult);
        __vmx_off();
        __writecr4(Vcpu->OriginalCr4);
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Step 5: Configure VMCS fields
     */
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_CPU_VMCS | (cpuIndex & 0x0F));
    status = ShvSetupVmcs(Vcpu, &Vcpu->CapturedContext);
    if (!NT_SUCCESS(status)) {
        SHV_ERR("CPU %lu: VMCS setup failed 0x%08X", cpuIndex, status);
        __vmx_off();
        __writecr4(Vcpu->OriginalCr4);
        return status;
    }

    /*
     * Step 6: VMLAUNCH
     * Guest RIP was set to the return address from ShvCaptureContext.
     * On success, execution resumes at ShvCaptureContext which returns 1.
     */
    SHV_LOG("CPU %lu: Executing VMLAUNCH...", cpuIndex);
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_CPU_LAUNCH | (cpuIndex & 0x0F));
    {
        UCHAR lc = ShvCmosRead(SHV_CMOS_LAUNCH_CNT);
        if (lc < 0xFF) ShvCmosWrite(SHV_CMOS_LAUNCH_CNT, lc + 1);
    }
    ULONG64 launchResult = ShvVmxLaunch(&Vcpu->CapturedContext);

    /* If we get here, VMLAUNCH failed */
    SIZE_T errorCode = 0;
    __vmx_vmread(VMCS_RO_VM_INSTRUCTION_ERROR, &errorCode);
    ShvCmosWrite(SHV_CMOS_FATAL, SHV_FATAL_LAUNCH_FAIL);
    ShvCmosWrite(SHV_CMOS_VMERR_LO, (UCHAR)errorCode);
    ShvCmosWrite(SHV_CMOS_VMERR_HI, (UCHAR)(errorCode >> 8));
    SHV_ERR("CPU %lu: VMLAUNCH failed! RFLAGS=0x%llX, error=%llu",
            cpuIndex, launchResult, (ULONG64)errorCode);

    __vmx_off();
    __writecr4(Vcpu->OriginalCr4);
    return STATUS_UNSUCCESSFUL;
}
