/**
 * @file TpmTrace.c
 * @brief Read-only observation of TPM device-control traffic. See TpmTrace.h for why.
 */

#include <ntddk.h>
#include <intrin.h>

#include "../../Include/NexusCommand.h"

/* ⚠ NXC_NT_API_TYPED FIRST. Without it NexusNtApi.h emits only the LIST macro, the struct stays
 * undeclared, and every redirected call reports itself as an undeclared identifier -- which is
 * exactly what this file did on its first build. */
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"
#include "TpmTrace.h"
#include "Arena.h"
#include "MapModule.h"      /* NxcResolveNtExport -- for the two symbols the nt table cannot hold */

/* The host's resolved nt table. Declared before the redirect header, which rewrites every call
 * below into a field reference on it. */
extern volatile NXC_NT_API NexusNtApi;

/* ⚠ THE PAYLOAD CARRIES NO IMPORT TABLE. Included LAST so it rewrites only our own call sites. */
#include "../../Include/NexusNtApiRedirect.h"

#define TPM_TRACE_MAX_SLOTS   4096u
#define TPM_TRACE_MIN_SLOTS   16u

static NXCMD_TPM_REC* volatile gRing    = NULL;
static LONG                    gSlots   = 0;
static ULONG                   gExtent  = 0;
static volatile LONG64         gTicket  = 0;   /* monotonic; a read never resets it   */
static volatile LONG64         gDropped = 0;   /* producer could not record, with cause */

/* \Driver\TPM's own device objects. The dispatch VA is shared with every other KMDF driver;
 * these are what make a record OURS. Empty means unbound -- see the filter in NxcTpmTraceRecord. */
#define TPM_MAX_DEVICES 8
static PVOID                   gDevices[TPM_MAX_DEVICES];
static ULONG                   gDeviceCount = 0;


/*
 * Resolve \Driver\TPM's IRP_MJ_DEVICE_CONTROL dispatch -- the VA to hook with --tpm.
 *
 * ⚠ WITHOUT THIS THE FEATURE IS UNUSABLE, which is why it is here rather than left to the
 * operator. `hook <va> --tpm` needs a VA, and there is no other way to obtain a driver object's
 * dispatch entry from usermode. Shipping the ring without the resolver would have been a working
 * mechanism nobody could point at anything.
 *
 * ⚠ BOTH SYMBOLS COME FROM NxcResolveNtExport, NOT THE nt TABLE. IoDriverObjectType is a DATA
 * export (the table carries functions only -- the same reason Regions.c resolves PsProcessType
 * this way), and ObReferenceObjectByName is resolved beside it rather than added to
 * NXC_NT_API_LIST: an entry the mapper resolves at every boot for one optional diagnostic is a
 * bind that can fail on a future kernel for no benefit, which is exactly what the note above
 * ObfDereferenceObject warns against.
 *
 * Returns 0 on any failure, with a reason in OutWhy. Never fatal: the ring works whether or not
 * this resolves, and the operator can always hook a VA obtained another way.
 */
typedef NTSTATUS (*t_ObReferenceObjectByName)(
	PUNICODE_STRING, ULONG, PVOID, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, PVOID*);

UINT64
NxcTpmResolveDispatch(
	_Out_ UINT32* OutWhy
	)
{
	if (OutWhy != NULL)
		*OutWhy = NXCMD_TPM_RESOLVE_OK;

	void** CONST TypeSlot = (void**)NxcResolveNtExport("IoDriverObjectType");
	t_ObReferenceObjectByName CONST Fn =
		(t_ObReferenceObjectByName)NxcResolveNtExport("ObReferenceObjectByName");

	if (TypeSlot == NULL || *TypeSlot == NULL || Fn == NULL)
	{
		if (OutWhy != NULL)
			*OutWhy = NXCMD_TPM_RESOLVE_NO_EXPORT;
		return 0;
	}

	UNICODE_STRING Name;
	RtlInitUnicodeString(&Name, L"\\Driver\\TPM");

	PDRIVER_OBJECT Drv = NULL;
	CONST NTSTATUS St = Fn(&Name, OBJ_CASE_INSENSITIVE, NULL, 0,
	                       (POBJECT_TYPE)*TypeSlot, KernelMode, NULL, (PVOID*)&Drv);
	if (!NT_SUCCESS(St) || Drv == NULL)
	{
		if (OutWhy != NULL)
			*OutWhy = NXCMD_TPM_RESOLVE_NO_DRIVER;
		return 0;
	}

	CONST UINT64 Va = (UINT64)(ULONG_PTR)Drv->MajorFunction[IRP_MJ_DEVICE_CONTROL];

	/*
	 * ⚠ BIND THE DEVICE OBJECTS, OR THE RING IS USELESS.
	 *
	 * measured: tpm.sys is a KMDF driver, so MajorFunction[IRP_MJ_DEVICE_CONTROL]
	 * points into Wdf01000.sys -- the dispatcher EVERY KMDF driver in the system shares. Hooking
	 * it captured device-control traffic from chrome, EADesktop, svchost, WUDFHost and
	 * OCControl.Service, wrapped a 512-slot ring in seconds, and EVICTED the three PCR_Reads we
	 * were actually looking for. The instrument was measuring the whole machine.
	 *
	 * The dispatch is shared; the DEVICE is not. arg1 is the target DEVICE_OBJECT, so matching it
	 * against this driver's own device chain is an IDENTITY test -- not a content test, and
	 * therefore not classification creeping into the capture path. Nothing is decoded to decide
	 * whether to record.
	 */
	gDeviceCount = 0;
	for (PDEVICE_OBJECT Dev = Drv->DeviceObject;
	     Dev != NULL && gDeviceCount < TPM_MAX_DEVICES;
	     Dev = Dev->NextDevice)
	{
		gDevices[gDeviceCount++] = (PVOID)Dev;
	}

	ObfDereferenceObject(Drv);

	if (Va == 0 && OutWhy != NULL)
		*OutWhy = NXCMD_TPM_RESOLVE_NO_DISPATCH;
	return Va;
}


/* How many of \Driver\TPM's device objects the filter is bound to. ZERO means the filter is OPEN
 * and the ring will carry every KMDF driver's device control -- reported so that is never a
 * surprise discovered halfway through reading a noisy dump. */
UINT32
NxcTpmBoundDeviceCount(
	void
	)
{
	return (UINT32)gDeviceCount;
}


NTSTATUS
NxcTpmTraceInit(
	_In_  UINT32 Slots,
	_Out_ UINT32* OutDetail
	)
{
	if (OutDetail != NULL)
		*OutDetail = 0;

	if (Slots < TPM_TRACE_MIN_SLOTS || Slots > TPM_TRACE_MAX_SLOTS)
	{
		if (OutDetail != NULL)
			*OutDetail = NXCMD_TPM_INIT_BAD_SLOTS;
		return STATUS_INVALID_PARAMETER;
	}

	if (gRing != NULL)
	{
		//
		// Already armed. Report it rather than silently re-allocating: a second ring would orphan
		// the first extent and split the sequence numbers across two stores, so a gap in the
		// output would stop meaning "records were lost".
		//
		if (OutDetail != NULL)
			*OutDetail = NXCMD_TPM_INIT_ALREADY;
		return STATUS_SUCCESS;
	}

	ULONG Extent = 0;
	void* CONST Mem = NxcArenaAlloc((ULONG)((SIZE_T)Slots * sizeof(NXCMD_TPM_REC)), &Extent);
	if (Mem == NULL)
	{
		if (OutDetail != NULL)
			*OutDetail = NXCMD_TPM_INIT_NO_ARENA;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(Mem, (SIZE_T)Slots * sizeof(NXCMD_TPM_REC));
	gExtent = Extent;
	gSlots  = (LONG)Slots;
	gRing   = (NXCMD_TPM_REC*)Mem;
	return STATUS_SUCCESS;
}


void
NxcTpmTraceRecord(
	_In_ UINT64 DeviceObject,
	_In_ UINT64 Irp
	)
{
	NXCMD_TPM_REC* CONST Ring = gRing;
	if (Ring == NULL || gSlots <= 0)
		return;                       /* not armed -- not an error, and not a drop */

	if (Irp == 0)
	{
		InterlockedIncrement64(&gDropped);
		return;
	}

	/*
	 * ⚠ IS THIS EVEN THE TPM? The hooked dispatch belongs to Wdf01000.sys and serves every KMDF
	 * driver on the machine, so without this the ring fills with unrelated device control and the
	 * signal is evicted before it can be read -- MEASURED, and it buried three PCR_Reads under 256
	 * records from chrome, svchost and friends.
	 *
	 * NOT counted as a drop. A drop means "we could not record something that was ours"; this is
	 * traffic that was never ours to begin with, and conflating the two would make the drop counter
	 * meaningless exactly when it matters.
	 *
	 * If binding failed (gDeviceCount == 0) the filter is OPEN rather than closed: recording
	 * everything is noisy, recording nothing looks identical to a target that never touched the
	 * TPM -- the one conclusion this tool must never fabricate.
	 */
	if (gDeviceCount != 0)
	{
		BOOLEAN Ours = FALSE;
		for (ULONG i = 0; i < gDeviceCount; i++)
		{
			if ((PVOID)(ULONG_PTR)DeviceObject == gDevices[i])
			{
				Ours = TRUE;
				break;
			}
		}
		if (!Ours)
			return;
	}

	//
	// ⚠ NO SEH IS AVAILABLE IN A MAPPED IMAGE, so every dereference below has to be safe by
	// construction rather than by catching a fault.
	//
	// It is. The IRP pointer is the dispatch's own argument 2, so it is the real IRP by
	// definition; its current stack location is a field inside it; and for METHOD_BUFFERED the
	// I/O manager allocated SystemBuffer from non-paged pool before the dispatch was entered.
	// The one pointer that is NOT safe is METHOD_NEITHER's Type3InputBuffer -- a raw usermode
	// address, at an IRQL and in a context we do not control -- and that case is REFUSED below
	// with a stated reason instead of touched.
	//
	PIRP CONST p = (PIRP)(ULONG_PTR)Irp;
	PIO_STACK_LOCATION CONST Sl = IoGetCurrentIrpStackLocation(p);

	UINT32 Why = NXCMD_TPM_WHY_OK;
	CONST UINT8* Src = NULL;
	UINT32 InLen = 0;
	UINT32 Ioctl = 0;

	if (Sl == NULL)
	{
		Why = NXCMD_TPM_WHY_NO_STACK;
	}
	else if (Sl->MajorFunction != IRP_MJ_DEVICE_CONTROL &&
	         Sl->MajorFunction != IRP_MJ_INTERNAL_DEVICE_CONTROL)
	{
		//
		// Recorded rather than dropped. A hook that is firing on the wrong major function is a
		// fact worth seeing in the output; silently ignoring it would look identical to a target
		// that never talks to the TPM, which is the exact conclusion this tool exists to support.
		//
		Why = NXCMD_TPM_WHY_NOT_DEVCTL;
	}
	else
	{
		Ioctl = (UINT32)Sl->Parameters.DeviceIoControl.IoControlCode;
		InLen = (UINT32)Sl->Parameters.DeviceIoControl.InputBufferLength;

		if ((Ioctl & 3u) != METHOD_BUFFERED)
			Why = NXCMD_TPM_WHY_NOT_BUFFERED;
		else if (p->AssociatedIrp.SystemBuffer == NULL)
			Why = NXCMD_TPM_WHY_NO_BUFFER;
		else if (InLen < NXCMD_TPM_HDR_BYTES)
			Why = NXCMD_TPM_WHY_TOO_SHORT;
		else
			Src = (CONST UINT8*)p->AssociatedIrp.SystemBuffer;
	}

	CONST LONG64 Ticket = InterlockedIncrement64(&gTicket);
	NXCMD_TPM_REC* CONST Rec = &Ring[(Ticket - 1) % (LONG64)gSlots];

	//
	// Sequence is cleared FIRST and written LAST. A reader that sees 0 is looking at a slot being
	// overwritten right now and skips it, so a torn record is never mistaken for a real one.
	//
	Rec->Sequence = 0;

	LARGE_INTEGER Pc;
	Pc.QuadPart = 0;
	Pc = KeQueryPerformanceCounter(NULL);
	Rec->TimeStamp = (NXCMD_U64)Pc.QuadPart;

	Rec->Irp           = Irp;
	Rec->Pid           = (NXCMD_U32)(ULONG_PTR)PsGetCurrentProcessId();
	Rec->Tid           = (NXCMD_U32)(ULONG_PTR)PsGetCurrentThreadId();
	Rec->IoControlCode = Ioctl;
	Rec->InputLength   = InLen;
	Rec->Why           = Why;
	Rec->Captured      = 0;
	RtlZeroMemory(Rec->Cmd, sizeof(Rec->Cmd));

	if (Src != NULL)
	{
		UINT32 Take = InLen;
		if (Take > sizeof(Rec->Cmd))
			Take = (UINT32)sizeof(Rec->Cmd);
		RtlCopyMemory(Rec->Cmd, Src, Take);
		Rec->Captured = Take;
	}

	Rec->Sequence = (NXCMD_U64)Ticket;
}


NTSTATUS
NxcTpmTraceRead(
	_Out_writes_bytes_(Cap) void* Out,
	_In_  UINT32 Cap,
	_Out_ UINT32* OutCount,
	_Out_ UINT32* OutTotal,
	_Out_ UINT32* OutDropped
	)
{
	if (OutCount != NULL)   *OutCount = 0;
	if (OutTotal != NULL)   *OutTotal = 0;
	if (OutDropped != NULL) *OutDropped = (UINT32)InterlockedCompareExchange64(&gDropped, 0, 0);

	NXCMD_TPM_REC* CONST Ring = gRing;
	if (Ring == NULL || gSlots <= 0)
		return STATUS_DEVICE_NOT_READY;

	CONST LONG64 Written = InterlockedCompareExchange64(&gTicket, 0, 0);
	CONST UINT32 Live = (UINT32)((Written < (LONG64)gSlots) ? Written : (LONG64)gSlots);
	if (OutTotal != NULL)
		*OutTotal = Live;

	if (Out == NULL || Cap < sizeof(NXCMD_TPM_REC))
		return STATUS_BUFFER_TOO_SMALL;

	CONST UINT32 Room = Cap / (UINT32)sizeof(NXCMD_TPM_REC);
	NXCMD_TPM_REC* CONST Dst = (NXCMD_TPM_REC*)Out;
	UINT32 n = 0;

	for (UINT32 i = 0; i < Live && n < Room; i++)
	{
		CONST NXCMD_TPM_REC* CONST Src = &Ring[i];
		if (Src->Sequence == 0)
			continue;                 /* torn or never written -- skipped, and the gap is visible */
		RtlCopyMemory(&Dst[n], Src, sizeof(NXCMD_TPM_REC));
		n++;
	}

	if (OutCount != NULL)
		*OutCount = n;
	return STATUS_SUCCESS;
}


void
NxcTpmTraceTeardown(
	void
	)
{
	/*
	 * ⚠ THE EXTENT IS NOT FREED HERE, DELIBERATELY. Arena.h records that the id-based free is gone
	 * and that a module's extents are released together by NxcArenaFreeOwner at teardown -- so
	 * calling a per-extent free here would either not compile or, worse, release memory the owner
	 * teardown will release again. Calls.c reserves its ring the same way and likewise never frees
	 * it individually.
	 *
	 * What this DOES do is stop the producer: once gRing is NULL, NxcTpmTraceRecord returns
	 * immediately, so no hit can be servicing the ring while the owner tears the arena down.
	 */
	gRing = NULL;
	gSlots = 0;
}
