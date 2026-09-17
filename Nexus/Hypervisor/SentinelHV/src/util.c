/**
 * @file util.c
 * @brief Shared utility functions: GDT segment descriptor parsing.
 *
 * Implements the segment descriptor helper functions used during VMCS
 * configuration to translate GDT entries into the formats required by
 * VMCS guest and host state fields.
 *
 * These functions parse the x86/x64 GDT segment descriptor format:
 *   - Base address: assembled from BaseLow (16b) + BaseMiddle (8b) +
 *     BaseHigh (8b), plus BaseUpper (32b) for 64-bit system descriptors.
 *   - Access rights: AccessByte + Flags nibble, converted to VMCS format
 *     with the unusable bit (bit 16) for null/not-present segments.
 *   - Limit: LimitLow (16b) + LimitHigh nibble (4b), with G-bit scaling.
 *
 * This file compiles under both NT and UEFI builds (platform-independent).
 * Platform-specific memory allocation is in platform_nt.c.
 */

#include "shv.h"

/* ── Segment Descriptor Parsing ───────────────────────────────────── */

/**
 * @brief Extract the base address from a GDT segment descriptor.
 *
 * Assembles the base address from the three base fields in the GDT entry.
 * For system descriptors (S bit = 0) in 64-bit mode -- specifically TSS
 * and LDT descriptors -- the descriptor is 16 bytes and contains a 32-bit
 * upper base extension, producing a full 64-bit base address.
 *
 * Returns 0 for null selectors (selector value 0 or index 0).
 *
 * @param GdtBase   Linear address of the Global Descriptor Table.
 * @param Selector  Segment selector (bits [15:3] = GDT index).
 * @return 64-bit segment base address.
 */
ULONG64
ShvGetSegmentBase(
    _In_ ULONG64 GdtBase,
    _In_ USHORT Selector
    )
{
    USHORT index;
    PSEGMENT_DESCRIPTOR desc;
    ULONG64 base;

    /* NULL selector has base 0 */
    if (Selector == 0 || (Selector & 0xFFF8) == 0) {
        return 0;
    }

    index = Selector & 0xFFF8;  /* Mask off RPL and TI bits */
    desc = (PSEGMENT_DESCRIPTOR)(GdtBase + index);

    /* Assemble 32-bit base */
    base = desc->BaseLow |
           ((ULONG64)desc->BaseMiddle << 16) |
           ((ULONG64)desc->BaseHigh << 24);

    /*
     * System descriptors (S bit = 0) in 64-bit mode are 16 bytes.
     * This includes TSS and LDT descriptors.
     */
    if (!(desc->AccessByte & 0x10)) {
        /* S=0 → system descriptor, extend to 64-bit base */
        PSEGMENT_DESCRIPTOR_64 desc64 = (PSEGMENT_DESCRIPTOR_64)desc;
        base |= ((ULONG64)desc64->BaseUpper << 32);
    }

    return base;
}

/**
 * @brief Convert a GDT descriptor's access byte and flags to VMCS access rights format.
 *
 * The VMCS segment access rights field has a specific layout:
 *   - Bits [3:0]: Segment type (from AccessByte bits [3:0])
 *   - Bit [4]: S flag (0=system, 1=code/data)
 *   - Bits [6:5]: DPL (Descriptor Privilege Level)
 *   - Bit [7]: P (Present)
 *   - Bits [11:8]: Reserved (must be 0)
 *   - Bit [12]: AVL (Available for OS use)
 *   - Bit [13]: L (64-bit code segment)
 *   - Bit [14]: D/B (Default operation size)
 *   - Bit [15]: G (Granularity)
 *   - Bit [16]: Unusable (set for null or not-present segments)
 *
 * @param GdtBase   Linear address of the Global Descriptor Table.
 * @param Selector  Segment selector to look up.
 * @return VMCS-format access rights, or 0x10000 for unusable segments.
 */
ULONG32
ShvGetSegmentAccessRights(
    _In_ ULONG64 GdtBase,
    _In_ USHORT Selector
    )
{
    USHORT index;
    PSEGMENT_DESCRIPTOR desc;
    ULONG32 ar;

    /* NULL/zero selector → unusable */
    if (Selector == 0 || (Selector & 0xFFF8) == 0) {
        return 0x10000;  /* Unusable bit set */
    }

    index = Selector & 0xFFF8;
    desc = (PSEGMENT_DESCRIPTOR)(GdtBase + index);

    /*
     * Build VMCS access rights:
     *   Bits [3:0]  = Type (from AccessByte[3:0])
     *   Bit  [4]    = S (descriptor type: 0=system, 1=code/data)
     *   Bits [6:5]  = DPL
     *   Bit  [7]    = P (present)
     *   Bits [11:8] = reserved (0)
     *   Bit  [12]   = AVL
     *   Bit  [13]   = L (64-bit code segment)
     *   Bit  [14]   = D/B (default operation size)
     *   Bit  [15]   = G (granularity)
     *   Bit  [16]   = Unusable
     */
    ar = desc->AccessByte & 0xFF;   /* Type + S + DPL + P */
    ar |= ((ULONG32)(desc->Flags_LimitHigh >> 4) & 0x0F) << 12;  /* G, D/B, L, AVL */

    /* If not present, mark unusable */
    if (!(ar & 0x80)) {
        ar |= 0x10000;
    }

    return ar;
}

/**
 * @brief Extract the segment limit from a GDT descriptor with granularity scaling.
 *
 * Assembles the 20-bit limit from the descriptor's LimitLow (16 bits) and
 * the lower nibble of Flags_LimitHigh (4 bits). If the granularity (G) bit
 * is set, the limit is in 4KB-page units: left-shift by 12 and OR with
 * 0xFFF to produce the byte-granularity limit.
 *
 * Returns 0 for null selectors.
 *
 * @param GdtBase   Linear address of the Global Descriptor Table.
 * @param Selector  Segment selector to look up.
 * @return Segment limit in bytes.
 */
ULONG32
ShvGetSegmentLimit(
    _In_ ULONG64 GdtBase,
    _In_ USHORT Selector
    )
{
    USHORT index;
    PSEGMENT_DESCRIPTOR desc;
    ULONG32 limit;

    if (Selector == 0 || (Selector & 0xFFF8) == 0) {
        return 0;
    }

    index = Selector & 0xFFF8;
    desc = (PSEGMENT_DESCRIPTOR)(GdtBase + index);

    limit = desc->LimitLow | ((ULONG32)(desc->Flags_LimitHigh & 0x0F) << 16);

    /* If G (granularity) bit is set, limit is in 4KB pages */
    if (desc->Flags_LimitHigh & 0x80) {
        limit = (limit << 12) | 0xFFF;
    }

    return limit;
}
