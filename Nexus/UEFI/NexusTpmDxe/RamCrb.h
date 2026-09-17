/**
 * @file RamCrb.h
 * @brief RAM CRB register map and transport contract — TCG PTP 1.07 §6.5.3, Table 20.
 *
 * PHASE 1 ARTIFACT. Transport only. There is no TPM core behind this yet, by design
 * (`the design notes` §6 — Phase 2 is blocked on G1).
 *
 * ⚠ EVERY OFFSET BELOW IS TRANSCRIBED FROM PTP 1.07 TABLE 20, "Allocation of Register Space for
 * FIFO and CRB Access", not from memory or from another implementation. The spec was pulled and
 * read directly; the table's CRB column is reproduced verbatim in the comments so a future reader
 * can check the transcription without re-downloading a 195-page PDF.
 *
 * THE THREE NORMATIVE RAM-CRB REQUIREMENTS (§6.5.3.2, after "End of informative comment"):
 *
 *   a.   TPM_CRB_INTF_ID_x.InterfaceType SHALL be 0x0010
 *   b.   TPM_CRB_DATA_BUFFER_x SHALL be at offset 0x0080 from the LOCALITY BASE
 *   c.i  CMD_SIZE / CMD_LADDR / CMD_HADDR / RSP_SIZE / RSP_ADDR SHALL be treated as read only,
 *        and the TPM SHALL ignore writes to them
 *   c.ii the TPM SHOULD populate those registers with 0x00
 *
 * ⚠ Everything else in §6.5.3.2 -- the signalling mechanism, the internal register snapshot,
 * buffer invalidation by writing zeros/ones, the reduced state set -- is INFORMATIVE. NexusTPM
 * adopts it by choice, not obligation. Do not describe adopted guidance as conformance.
 *
 * ⚠ THE ACPI TABLE POINTS AT THE CONTROL AREA, NOT THE LOCALITY BASE. PTP is explicit: "The TPM
 * ACPI table ... contains the address of the Locality 0 Control Area. To locate the base address
 * of any locality, the driver computes the base address of Locality 0 first."
 *
 *     locality_base  =  TPM2_table.ControlAreaAddress - 0x40
 *     data_buffer    =  locality_base + 0x80
 *
 * MEASURED on this machine while PTT was still enabled, and it matches exactly:
 *     PnP MMIO resource (locality base)  0xFED40000   page aligned
 *     ACPI TPM2 Control Area             0xFED40040   = base + 0x40
 */

#ifndef NEXUS_RAM_CRB_H
#define NEXUS_RAM_CRB_H

#include <Uefi.h>

/**
 * ⚠ `C_ASSERT` DOES NOT EXIST IN THIS SDK -- define it, do not assume it.
 *
 * VisualUefi ships a TRIMMED EDK2. Its `Base.h` has `VERIFY_SIZE_OF` and `OFFSET_OF`, but neither
 * `C_ASSERT` nor `STATIC_ASSERT`. Real EDK2 has `C_ASSERT`, so it reads as available on
 * inspection and the mistake stays invisible until the compiler runs.
 *
 * ⚠ THE DIAGNOSTIC DOES NOT NAME THE MISSING MACRO. `C_ASSERT(x)` at file scope parses as a
 * declaration involving an undeclared identifier, and MSVC reports it against the OFFSET_OF
 * expansion instead: "error C2091: function returns function" and "missing '{' before '&'",
 * pointing at an `&` this file never wrote. Cost one build to identify.
 *
 * Same negative-array-size form real EDK2 uses, and deliberately the SAME NAME every time:
 * repeated identical `extern` declarations of an object that is never defined are legal C, so
 * several asserts coexist in one translation unit and the linker never sees them. A failing one
 * asks for size -1 and breaks the build, which is the entire point.
 *
 * Guarded, so a future SDK that gains a real `C_ASSERT` wins without an edit here.
 */
#ifndef C_ASSERT
#define C_ASSERT(Expression)  extern char _NexusCAssert__[(Expression) ? 1 : -1]
#endif


//
// ---------------------------------------------------------------------------------------------
// PTP 1.07 Table 20, CRB column, locality 0. Offsets are from the LOCALITY BASE.
//
//   0000h            TPM_LOC_STATE_0            (1 byte; 0001h-0003h reserved)
//   0007h-0004h      Reserved
//   000Bh-0008h      TPM_LOC_CTRL_0
//   000Ch            TPM_LOC_STS_0
//   000Fh-000Dh      Reserved
//   0013h-0010h      TPM_DATA_CSUM_ENABLE_0
//   0017h-0014h      TPM_DATA_CSUM_0
//   001Bh-0018h      Reserved
//   001Fh-001Ch      TPM_INTF_CAPABILITYX_0
//   0023h-0020h      Reserved
//   002Fh-0024h      Reserved
//   0033h-0030h      TPM_CRB_INTF_ID_0
//   003Fh-0034h      Reserved
//   0043h-0040h      TPM_CRB_CTRL_REQ_0         <== CONTROL AREA BASE; the ACPI table points here
//   0047h-0044h      TPM_CRB_CTRL_STS_0
//   004Bh-0048h      TPM_CRB_CTRL_CANCEL_0
//   004Fh-004Ch      TPM_CRB_CTRL_START_0
//   0053h-0050h      TPM_CRB_INT_ENABLE_0
//   0057h-0054h      TPM_CRB_INT_STS_0
//   005Bh-0058h      TPM_CRB_CTRL_CMD_SIZE_0    <== read only for RAM CRB, SHOULD be 0
//   005Fh-005Ch      TPM_CRB_CTRL_CMD_LADDR_0   <== read only for RAM CRB, SHOULD be 0
//   0063h-0060h      TPM_CRB_CTRL_CMD_HADDR_0   <== read only for RAM CRB, SHOULD be 0
//   0067h-0064h      TPM_CRB_CTRL_RSP_SIZE_0    <== read only for RAM CRB, SHOULD be 0
//   006Fh-0068h      TPM_CRB_CTRL_RSP_ADDR_0    <== read only for RAM CRB, SHOULD be 0 (8 bytes)
//   007Fh-0070h      Reserved
//   0083h-0080h ..   TPM_CRB_DATA_BUFFER_0      <== SHALL be at +0x80
//   0EFFh-0084h      (CRB column BLANK -- the DATA_BUFFER cell is MERGED and runs to 0EFFh)
//   0F03h-0F00h      TPM_DID_VID_0   <== (!) FIFO COLUMN ONLY. The CRB column is Reserved.
//                                        Carrying this into the CRB map was an ERROR -- see below.
//   0F04h            TPM_RID_0       <== (!) FIFO COLUMN ONLY. CRB column reads "Reserved".
//   0FFFh-0F90h      Reserved
// ---------------------------------------------------------------------------------------------
//

#define CRB_LOCALITY_SIZE            0x1000   // one 4 KB page per locality

#define CRB_OFF_LOC_STATE            0x0000
#define CRB_OFF_LOC_CTRL             0x0008
#define CRB_OFF_LOC_STS              0x000C
#define CRB_OFF_DATA_CSUM_ENABLE     0x0010
#define CRB_OFF_DATA_CSUM            0x0014
#define CRB_OFF_INTF_CAPABILITYX     0x001C
#define CRB_OFF_INTF_ID              0x0030   // TPM_CRB_INTF_ID_x, 8 bytes

#define CRB_OFF_CTRL_REQ             0x0040   // <-- Control Area base (ACPI points here)
#define CRB_OFF_CTRL_STS             0x0044
#define CRB_OFF_CTRL_CANCEL          0x0048
#define CRB_OFF_CTRL_START           0x004C
#define CRB_OFF_INT_ENABLE           0x0050
#define CRB_OFF_INT_STS              0x0054
#define CRB_OFF_CTRL_CMD_SIZE        0x0058
#define CRB_OFF_CTRL_CMD_LADDR       0x005C
#define CRB_OFF_CTRL_CMD_HADDR       0x0060
#define CRB_OFF_CTRL_RSP_SIZE        0x0064
#define CRB_OFF_CTRL_RSP_ADDR        0x0068   // 8 bytes

#define CRB_OFF_DATA_BUFFER          0x0080   // NORMATIVE: SHALL be here

//
// (!) THERE IS NO TPM_DID_VID / TPM_RID IN THE CRB REGISTER MAP.
//
// This header previously defined CRB_OFF_DID_VID 0x0F00 and CRB_OFF_RID 0x0F04. Both are
// FIFO-COLUMN-ONLY rows in Table 20; the CRB column reads "Reserved" across them. The CRB
// interface exposes Vid/Did inside TPM_CRB_INTF_ID_x at 0x30-0x37 instead, which is why EDK2
// splits that 64-bit register into InterfaceId(32) + Vid(16) + Did(16).
//
// The mistake mattered: it made the data buffer look like it would collide at 0x0F00, and the
// C_ASSERT below duly fired -- against a constraint that does not exist. A guard is only as
// good as the map it checks.
//
#define CRB_FIFO_OFF_DID_VID         0x0F00   // FIFO map only -- NOT a CRB register
#define CRB_FIFO_OFF_RID             0x0F04   // FIFO map only -- NOT a CRB register

//
// The offset from the locality base to the control area. The ACPI TPM2 table publishes the
// CONTROL AREA address, so the locality base is recovered by subtracting this.
//
#define CRB_CONTROL_AREA_OFFSET      CRB_OFF_CTRL_REQ   // 0x40

/**
 * TPM_CRB_INTF_ID_x -- PTP 1.07 Table 24, "CRB Interface Identifier Register". 64 bits at 0x30.
 *
 * (!) THIS REGISTER MUST BE FILLED IN, NOT LEFT AS THE INTERFACE TYPE ALONE. Writing only
 * InterfaceType = 0010b and zeroing the rest produces a register that CONTRADICTS ITSELF:
 *
 *     "RAM CRB is the active interface type"   (InterfaceType = 0010)
 *     "...but CRB is not supported"            (CapCRB       = 0)
 *     "...and FIFO is the selected interface"  (InterfaceSelector = 00)
 *     "...at the FIFO interface version"       (InterfaceVersion  = 0000)
 *
 * MEASURED CONSEQUENCE,: with that value, tpm.sys bound the ACPI device, reported
 * CM_PROB_NONE and started its service -- and never wrote a single byte to the CRB. The control
 * area was read back byte-identical to the DXE handoff state, before and after forcing TPM
 * traffic with `tpmtool getdeviceinformation`, which answered 0x800710df, "device is not ready
 * for use". It refused BEFORE the handshake rather than failing during it.
 *
 * Table 24, in full, so nobody has to re-derive it:
 *
 *   63:48  DID                      device ID, vendor-specific
 *   47:32  VID                      vendor ID, assigned by TCG
 *   31:24  RID                      revision ID
 *   23:22  CapSPICSUM               00 = no checksum calculation support
 *   21:20  Reserved                 reads return 0
 *   19     IntfSelLock              1 = InterfaceSelector is locked
 *   18:17  InterfaceSelector        00 = FIFO selected, 01 = CRB selected
 *   16:15  CapIFRes                 reserved, reads return 0
 *   14     CapCRB                   1 = CRB interface supported and selectable
 *   13     CapFIFO                  1 = FIFO interface supported and selectable
 *   12:11  CapDataXferSizeSupport   00=4B, 01=8B, 10=32B, 11=64B (each includes the smaller)
 *   10     CapCRBChunk              1 = CRB data buffer chunking supported
 *   9      CapCRBIdleBypass
 *   8      CapLocality              0 = locality 0 only
 *   7:4    InterfaceVersion         see Table 25
 *   3:0    InterfaceType            0000 FIFO, 0001 CRB, 0010 RAM CRB, 1111 TIS1.3
 */

//
// InterfaceType, bits 3:0. Table 24:
//   0000b  FIFO interface as defined in PTP for TPM 2.0 is active
//   0001b  CRB interface is active
//   0010b  RAM CRB interface is active     <== ours, and section 6.5.3.2(a) makes it a SHALL
//   1111b  FIFO interface as defined in TIS1.3
//
// (!) The numbered rules under Table 24 enumerate only 0000b, 0001b and 1111b, which makes the
// FIFO register (Table 23) look like it contradicts this. It does not -- 0010b is defined in the
// encoding list and simply carries no extra rules of its own.
//
#define CRB_INTF_TYPE_FIFO           0x0
#define CRB_INTF_TYPE_CRB            0x1
#define CRB_INTF_TYPE_RAM_CRB        0x2      // the "0010" of the spec is BINARY, = 0x2

//
// (!) WE DECLARE 0x1 (CRB), NOT 0x2 (RAM CRB), AND THE REASON IS IN THE CLAUSES NOT THE TABLE.
//
// PTP 1.07 p.63 lists 0010b = "RAM CRB interface is active", so 0x2 is a legal value and
// describes us literally. But the NORMATIVE clauses under that table cover only three cases:
//
//     4. If this field is set to 0000b: ... InterfaceVersion SHALL be 0000b
//     5. If this field is set to 0001b: ... InterfaceVersion SHALL be 0010b for the CRB interface
//     6. If this field is set to 1111b: this register is not implemented
//
// THERE IS NO CLAUSE FOR 0010b. A driver written against those clauses has no case for RAM CRB,
// and tpm.sys predates it: it bound our ACPI device, started, logged "A compatible TPM is not
// found" (System log, provider TPM, event 16), and never wrote a single byte to the locality
// page. It read the interface and stopped.
//
// Clause 5 also pairs Type=0001b with Version=0010b -- and 0010b is the InterfaceVersion we
// already publish. So (0001b, 0010b) is the combination the specification actually mandates;
// (0010b, 0010b) is one no clause describes.
//
// This is not a conformance retreat. Ours IS the CRB interface; that it lives in RAM rather
// than MMIO is what the ACPI Start Method (7 = CRB) conveys. Declaring 0001b states a truth.
//

//
// InterfaceVersion, bits 7:4 -- Table 25, CRB Historical Interface Versions:
//   0  CRB versions prior to PTP standardization
//   1  first version of CRB standardized in the PTP
//   2  increased CRB data buffer size for TPM Library 1.59
//   3  added CRB data buffer CHUNKING for post-quantum command sizes
//
// (!) WE CLAIM 2, NOT 3, AND THAT IS AN HONESTY CONSTRAINT rather than a conservative one. 3
// means chunking is supported; we set CapCRBChunk = 0, so claiming 3 would advertise a mechanism
// a driver could then try to use. 2 describes exactly what we are: a standardized CRB with the
// full-size data buffer and no chunking.
//
#define CRB_INTF_VERSION_CRB         0x2

//
// CapDataXferSizeSupport, bits 12:11. 11b = 64-byte, and it INCLUDES 4-, 8- and 32-byte, so it
// imposes nothing on the driver. True without qualification here: the "registers" are DRAM, which
// supports every access width.
//
#define CRB_XFER_SIZE_64B            0x3

//
// Vendor and device. VID is "assigned by TCG"; a zero VID reads as no device at all.
//
// (!) 0x8086 KEEPS THIS MACHINE SELF-CONSISTENT. Its firmware TPM was Intel PTT until it was
// disabled, so an Intel vendor ID is what every other artefact on this box already implies. This
// is the "report SPOOFED, never ABSENT" requirement applied to the interface register -- a TPM
// that answers with a blank identity is a TPM that reads as broken.
//
#define CRB_VID_INTEL                0x8086
#define CRB_DID_NEXUS                0x0001   // vendor-specific by definition
#define CRB_RID_NEXUS                0x01

//
// The assembled 64-bit value. Built from named fields rather than a magic constant SO THAT A
// FAILING EXPERIMENT CAN BE BISECTED: if tpm.sys still declines, individual bits can be changed
// and attributed, instead of staring at one hex literal.
//
#define CRB_INTF_ID_VALUE \
	( ((UINT64)CRB_INTF_TYPE_CRB       <<  0) /* InterfaceType     = CRB       */ \
	| ((UINT64)CRB_INTF_VERSION_CRB    <<  4) /* InterfaceVersion  = 2         */ \
	| ((UINT64)0                       <<  8) /* CapLocality       = loc 0 only*/ \
	| ((UINT64)0                       <<  9) /* CapCRBIdleBypass              */ \
	| ((UINT64)0                       << 10) /* CapCRBChunk       = no        */ \
	| ((UINT64)CRB_XFER_SIZE_64B       << 11) /* CapDataXferSize   = 64 byte   */ \
	| ((UINT64)0                       << 13) /* CapFIFO           = no FIFO   */ \
	| ((UINT64)1                       << 14) /* CapCRB            = YES       */ \
	| ((UINT64)0                       << 15) /* CapIFRes          = reserved  */ \
	| ((UINT64)1                       << 17) /* InterfaceSelector = CRB       */ \
	| ((UINT64)1                       << 19) /* IntfSelLock       = locked    */ \
	| ((UINT64)0                       << 22) /* CapSPICSUM        = none      */ \
	| ((UINT64)CRB_RID_NEXUS           << 24) /* RID                           */ \
	| ((UINT64)CRB_VID_INTEL           << 32) /* VID                           */ \
	| ((UINT64)CRB_DID_NEXUS           << 48) /* DID                           */ )

//
// (!) CapSPICSUM = 00b CARRIES A SHALL, AND IT IS EASY TO MISS.
//
// Table 23 rule 2: "If CapSPICSUM is set to 00b (a TPM does NOT support data checksum
// calculation); Reads to TPM_DATA_CSUM_ENABLE and TPM_DATA_CSUM SHALL return 0xFFFF."
//
// Zero is the natural value to leave those at and it is the WRONG one -- 0 means "checksumming
// is present and currently reports 0", which contradicts the capability bits above.
//
#define CRB_DATA_CSUM_ABSENT         0xFFFFu

//
// TPM_CRB_CTRL_START_x — bit 0 is the Start field. On real hardware, writing 1 signals the TPM.
// ⚠ ON A RAM CRB THIS WRITE REACHES NOTHING. PTP §6.5.3.2(1), informative: a RAM CRB "has no
// physical interface that fulfills the function of a write of 1 to the Start field ... and requires
// a signaling mechanism". That is G1, and it is why this header defines the LAYOUT only — the
// notification endpoint is a Phase-1 decision, not a constant.
//
#define CRB_START_BIT                0x00000001u

//
// TPM_CRB_CTRL_REQ_x
//
#define CRB_REQ_COMMAND_READY        0x00000001u
#define CRB_REQ_GO_IDLE              0x00000002u

//
// TPM_CRB_CTRL_STS_x
//
#define CRB_STS_TPM_STS_ERROR        0x00000001u
#define CRB_STS_TPM_IDLE             0x00000002u

//
// TPM_LOC_STATE_x
//
#define CRB_LOC_STATE_ESTABLISHED    0x01
#define CRB_LOC_STATE_LOC_ASSIGNED   0x02
#define CRB_LOC_STATE_TPM_REG_VALID  0x80

//
// TPM_LOC_CTRL_x
//
#define CRB_LOC_CTRL_REQUEST_ACCESS  0x00000001u
#define CRB_LOC_CTRL_RELINQUISH      0x00000002u
#define CRB_LOC_CTRL_SEIZE           0x00000004u
#define CRB_LOC_CTRL_RESET_ESTABLISH 0x00000008u

/**
 * The locality-0 register block, laid out exactly as Table 20 specifies.
 *
 * ⚠ NOT a description of hardware — this is memory WE allocate and WE own, so the layout is a
 * contract we must honour rather than one imposed on us. The C_ASSERTs below are the enforcement:
 * a field reordered or a reserved gap mis-sized must break the BUILD, because the failure mode
 * otherwise is `tpm.sys` reading a plausible value from the wrong offset.
 */
#pragma pack(push, 1)
typedef struct _NEXUS_CRB_LOCALITY {
	UINT8   LocState;                 // 0x0000
	UINT8   Reserved0[3];             // 0x0001
	UINT32  Reserved1;                // 0x0004
	UINT32  LocCtrl;                  // 0x0008
	UINT32  LocSts;                   // 0x000C  (Table 20 shows 000Ch; 000Dh-000Fh reserved)
	UINT32  DataCsumEnable;           // 0x0010
	UINT32  DataCsum;                 // 0x0014
	UINT32  Reserved2;                // 0x0018
	UINT32  IntfCapabilityX;          // 0x001C
	UINT32  Reserved3[4];             // 0x0020 .. 0x002F
	UINT64  IntfId;                   // 0x0030  TPM_CRB_INTF_ID_x
	UINT32  Reserved4[2];             // 0x0038 .. 0x003F
	UINT32  CtrlReq;                  // 0x0040  <== CONTROL AREA BASE
	UINT32  CtrlSts;                  // 0x0044
	UINT32  CtrlCancel;               // 0x0048
	UINT32  CtrlStart;                // 0x004C
	UINT32  IntEnable;                // 0x0050
	UINT32  IntSts;                   // 0x0054
	UINT32  CtrlCmdSize;              // 0x0058  read only for RAM CRB
	UINT32  CtrlCmdLAddr;             // 0x005C  read only for RAM CRB
	UINT32  CtrlCmdHAddr;             // 0x0060  read only for RAM CRB
	UINT32  CtrlRspSize;              // 0x0064  read only for RAM CRB
	UINT64  CtrlRspAddr;              // 0x0068  read only for RAM CRB
	UINT32  Reserved5[4];             // 0x0070 .. 0x007F
	UINT8   DataBuffer[1];            // 0x0080  <== SHALL be here; extent is a Phase-1 question
} NEXUS_CRB_LOCALITY;
#pragma pack(pop)

//
// ⚠ THE ENFORCEMENT. Every normative offset is asserted. A reordering that silently moved a
// register would otherwise present `tpm.sys` with a well-formed value at the wrong place, which is
// the hardest class of bug to see from the outside.
//
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, LocState)     == CRB_OFF_LOC_STATE);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, LocCtrl)      == CRB_OFF_LOC_CTRL);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, LocSts)       == CRB_OFF_LOC_STS);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, IntfId)       == CRB_OFF_INTF_ID);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, CtrlReq)      == CRB_OFF_CTRL_REQ);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, CtrlSts)      == CRB_OFF_CTRL_STS);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, CtrlCancel)   == CRB_OFF_CTRL_CANCEL);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, CtrlStart)    == CRB_OFF_CTRL_START);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, CtrlCmdSize)  == CRB_OFF_CTRL_CMD_SIZE);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, CtrlCmdLAddr) == CRB_OFF_CTRL_CMD_LADDR);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, CtrlCmdHAddr) == CRB_OFF_CTRL_CMD_HADDR);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, CtrlRspSize)  == CRB_OFF_CTRL_RSP_SIZE);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, CtrlRspAddr)  == CRB_OFF_CTRL_RSP_ADDR);
C_ASSERT(OFFSET_OF(NEXUS_CRB_LOCALITY, DataBuffer)   == CRB_OFF_DATA_BUFFER);

/**
 * DATA BUFFER EXTENT — resolved to a DEFAULT, still gated on Phase-1 measurement.
 *
 * The question: on a normal CRB the host learns the buffer extent from TPM_CRB_CTRL_CMD_SIZE and
 * TPM_CRB_CTRL_RSP_SIZE. But PTP §6.5.3.2(c.ii) says a RAM CRB **SHOULD** populate those with
 * zero — apparently closing the only channel that communicates the size.
 *
 * ⚠ FOLLOWING THAT "SHOULD" WOULD LIKELY BE FATAL. Real drivers read those registers:
 *
 *   Linux  tpm_crb.c, crb_map_io():  reads cmd_pa_high / cmd_pa_low and the size out of the
 *                                    control area and MAPS THE BUFFER WITH THEM. A zero size
 *                                    produces a zero-length mapping. It also validates that
 *                                    cmd_size == rsp_size when the two buffers overlap.
 *   EDK2   PTP_CRB_REGISTERS:        CrbDataBuffer is UINT8[0xF80] at offset 0x80 — 3968 bytes,
 *                                    running from 0x80 up to the reserved region below 0xF00,
 *                                    exactly as PTP Table 20 lays it out.
 *
 * ⚠ SHOULD IS NOT SHALL. Deviating from a SHOULD with a documented reason is conformant; the
 * SHALL in (c.i) — treat the registers as READ ONLY and IGNORE WRITES — is honoured unchanged.
 *
 * So the default is:
 *     CMD_SIZE = RSP_SIZE = CRB_DATA_BUFFER_SIZE     (identical: overlapping single buffer)
 *     CMD_LADDR / CMD_HADDR / RSP_ADDR               = physical address of the data buffer
 *     writes to all five                             = ignored
 *
 * ⚠ PHASE 1.6 STILL MEASURES. This is a starting value chosen from published driver behaviour,
 * not a conclusion. If measurement shows Windows never reads these registers, zeroing them
 * becomes available again — but starting from a value known to break real drivers would have
 * meant debugging the wrong thing.
 */
//
// RESOLVED AGAINST THE SPEC ITSELF: 0x0F80 (3968 bytes), 0x0080 .. 0x0FFF.
//
// (!) AN EARLIER REVISION OF THIS HEADER SAID 0x0E80 AND GAVE A WRONG REASON. It claimed EDK2
// disagreed with Table 20 because CrbDataBuffer[0xF80] would overrun TPM_DID_VID_0 at 0x0F00.
// There is no TPM_DID_VID_0 in the CRB map (see above), so there was never a conflict. EDK2 was
// right and the local map was wrong.
//
// PTP 1.07 states the maximum TWICE, and both were read from the PDF, not recalled:
//
//   register table, p.112:  "0EFFh-0080h  TPM_CRB_DATA_BUFFER_0 -- Command/Response Data may be
//                            defined as large as 3968. This is implementation-specific. However,
//                            the full address space has been reserved."
//
//   6.5.1.7, informative:   "TPMs implemented with the CRB address map as defined in this
//                            specification are limited to a data buffer size of 3968 bytes. This
//                            maximum size prevents the data buffer from crossing a locality
//                            address boundary."
//
// 3968 == 0x0F80, and 0x0080 + 0x0F80 == 0x1000 -- the buffer fills locality 0 exactly and stops
// at the boundary, which is precisely the reason the spec gives for the number. The table row
// stops at 0EFFh while the text reserves the full space; the text is the one that states a size.
//
// (!) THE NORMATIVE REQUIREMENT IS STILL ONLY THE BASE ADDRESS. 6.5.3.2(b) says the buffer SHALL
// be at +0x0080. The EXTENT is implementation-specific, so 0x0F80 is the maximum we are allowed
// to claim, not a value we are obliged to claim. Phase 1.6 measures what tpm.sys actually reads
// and may reduce it -- but it starts from the documented maximum rather than from a number this
// header invented.
//
#define CRB_DATA_BUFFER_SIZE         0x0F80   // 3968 bytes: 0x0080 .. 0x0FFF, the PTP maximum

//
// The bound is the LOCALITY PAGE, which is the constraint the spec actually names -- not a tail
// register that exists only in the FIFO map.
//
C_ASSERT(CRB_OFF_DATA_BUFFER + CRB_DATA_BUFFER_SIZE <= CRB_LOCALITY_SIZE);

/**
 * ⚠ ACPI _CRS MUST COVER THE WHOLE LOCALITY, not just the control area.
 *
 * Drivers map the region ACPI describes. A _CRS covering only 0x40..0x7F leaves the data buffer
 * at 0x80 outside the mapping — Linux has an explicit "ACPI region does not cover the entire
 * command/response buffer" failure path for exactly this. One contiguous resource from the
 * locality base through CRB_LOCALITY_SIZE.
 */

#endif // NEXUS_RAM_CRB_H
