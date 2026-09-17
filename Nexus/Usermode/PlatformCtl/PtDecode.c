/**
 * @file PtDecode.c
 * @brief Intel PT packet decoder. Opcodes checked against libipt's pt_opcodes.h, not recalled.
 */

#include <string.h>
#include "PtDecode.h"

/*
 * ============================================================================================
 * OPCODES -- every constant here is from libipt `pt_opcodes.h` (Intel's own decoder).
 * ============================================================================================
 *
 * ⚠ WRITTEN OUT RATHER THAN REFERENCED, and checked one at a time, because a wrong mask in this
 * table does not produce an error. It produces ADDRESSES -- plausible, well-formed, and never
 * executed by anything. That is the single worst output this project can generate, and it is why
 * the decoder below would rather stop than guess.
 */
#define PT_OPC_PAD          0x00
#define PT_OPC_EXT          0x02        /* two-byte opcode; second byte selects           */
#define PT_EXT_PSB          0x82
#define PT_EXT_PSBEND       0x23
#define PT_EXT_TNT64        0xA3
#define PT_EXT_PIP          0x43
#define PT_EXT_OVF          0xF3
#define PT_EXT_CBR          0x03
#define PT_EXT_TMA          0x73
#define PT_EXT_STOP         0x83
#define PT_EXT_VMCS         0xC8
#define PT_EXT_MNT_HI       0xC3        /* MNT is 02 C3 88, a three-byte opcode           */
#define PT_EXT_PTW          0x12        /* low bits vary; masked below                    */

#define PT_OPM_TNT8         0x01        /* short TNT: bit 0 clear                         */
#define PT_OPM_IP           0x1F        /* TIP-family opcode lives in the low 5 bits      */
#define PT_OPC_TIP          0x0D
#define PT_OPC_TIP_PGE      0x11
#define PT_OPC_TIP_PGD      0x01
#define PT_OPC_FUP          0x1D
#define PT_OPM_IPC          0xE0        /* IPBytes: bits 7:5                              */
#define PT_OPM_IPC_SHR      5

#define PT_OPC_MODE         0x99
#define PT_OPC_TSC          0x19
#define PT_OPC_MTC          0x59
#define PT_OPM_CYC          0x03        /* CYC: low 2 bits == 0b11                        */

static const char* const kNames[PT_PK_COUNT] = {
    "PAD", "PSB", "PSBEND", "TNT8", "TNT64",
    "TIP", "TIP.PGE", "TIP.PGD", "FUP",
    "MODE", "PIP", "TSC", "MTC", "CYC", "CBR",
    "OVF", "STOP", "VMCS", "TMA", "MNT", "PTW"
};

const char*
PtPacketName(
    unsigned Kind
    )
{
    return (Kind < PT_PK_COUNT) ? kNames[Kind] : "?";
}

/**
 * Rebuild an IP from a TIP-family packet.
 *
 * ⚠ PT COMPRESSES IPs AGAINST THE PREVIOUS ONE, so this is stateful and the state is load-bearing.
 * IPBytes says how many bytes are present and where the rest come from:
 *
 *   0  no IP at all -- the packet is still a real event, the address is just not provided
 *   1  2 bytes, upper 48 bits from the last IP
 *   2  4 bytes, upper 32 bits from the last IP
 *   3  6 bytes, SIGN-EXTENDED from bit 47
 *   4  6 bytes, upper 16 bits from the last IP
 *   6  8 bytes, the whole thing
 *
 * ⚠ 5 AND 7 ARE RESERVED AND ARE TREATED AS A DECODE FAILURE, not as something to skip. A reserved
 * value means the byte was not the opcode this decoder took it for, so everything after it is
 * misaligned -- and continuing would emit addresses assembled from the middle of other packets.
 *
 * @return bytes of payload consumed, or -1 if IPBytes was reserved
 */
static int
DecodeIp(
    const uint8_t* P,
    unsigned Ipc,
    uint64_t* LastIp,
    int* OutSuppressed
    )
{
    *OutSuppressed = 0;

    switch (Ipc)
    {
    case 0:
        *OutSuppressed = 1;
        return 0;

    case 1:
        *LastIp = (*LastIp & 0xFFFFFFFFFFFF0000ull) | (uint64_t)P[0] | ((uint64_t)P[1] << 8);
        return 2;

    case 2:
        *LastIp = (*LastIp & 0xFFFFFFFF00000000ull) |
                  (uint64_t)P[0] | ((uint64_t)P[1] << 8) |
                  ((uint64_t)P[2] << 16) | ((uint64_t)P[3] << 24);
        return 4;

    case 3:
    {
        uint64_t V = 0;
        for (int i = 0; i < 6; i++) V |= (uint64_t)P[i] << (8 * i);
        /* Sign-extend from bit 47 -- canonical-address form, so a kernel IP comes back with its
         * high bits set rather than as a 48-bit number that looks like a usermode address. */
        if (V & (1ull << 47)) V |= 0xFFFF000000000000ull;
        *LastIp = V;
        return 6;
    }

    case 4:
    {
        uint64_t V = 0;
        for (int i = 0; i < 6; i++) V |= (uint64_t)P[i] << (8 * i);
        *LastIp = (*LastIp & 0xFFFF000000000000ull) | V;
        return 6;
    }

    case 6:
    {
        uint64_t V = 0;
        for (int i = 0; i < 8; i++) V |= (uint64_t)P[i] << (8 * i);
        *LastIp = V;
        return 8;
    }

    default:
        return -1;      /* 5 and 7 are reserved */
    }
}

/**
 * Resolve a TNT payload field into branch results in APPLICATION ORDER.
 *
 * SDM vol 3, Table 34-16: the valid bits are the ones BELOW a trailing Stop bit, and a partial
 * packet moves the Stop bit down rather than padding the count. So the number of results is not
 * given anywhere -- it is the position of the highest set bit, and there is no other way to know it.
 *
 * @param Field  the payload bits, Stop bit included, right-aligned:
 *               short TNT -> the opcode byte >> 1 (7 bits)
 *               long  TNT -> the 6 payload bytes as one 48-bit value, LAST byte most significant
 * @param Width  how many bits of @p Field are meaningful (7 or 48)
 * @param OutBits receives B1 (OLDEST, applied first) in bit 0
 * @return the number of valid results, 0 if the field held only zeroes
 *
 * ⚠ A ZERO FIELD IS A DECODE FAILURE, NOT AN EMPTY PACKET. Every TNT carries at least one result,
 * so a payload with no Stop bit anywhere means this byte was not a TNT -- the stream is misaligned
 * and the caller must stop rather than contribute nothing and walk on.
 */
static unsigned
DecodeTnt(
    uint64_t Field,
    unsigned Width,
    uint64_t* OutBits
    )
{
    unsigned Stop = 0;
    unsigned Found = 0;

    *OutBits = 0;

    for (unsigned b = 0; b < Width; b++)
    {
        if (Field & (1ull << b)) { Stop = b; Found = 1; }
    }
    if (!Found || Stop == 0)
        return 0;                   /* no Stop bit, or a Stop bit with nothing under it */

    /*
     * B1 sits directly under the Stop bit and Bn descends from there, so bit (Stop - i) of the
     * field is B_i. Re-indexed to bit (i - 1) here so consumers read bit 0 first and never have to
     * know where the Stop bit was.
     */
    for (unsigned i = 1; i <= Stop; i++)
    {
        if (Field & (1ull << (Stop - i)))
            *OutBits |= (1ull << (i - 1));
    }
    return Stop;
}

/** The 16-byte PSB pattern: 02 82 repeated eight times. */
static int
IsPsbAt(
    const uint8_t* B,
    uint32_t Len,
    uint32_t At
    )
{
    if (At + 16 > Len)
        return 0;
    for (int i = 0; i < 16; i += 2)
    {
        if (B[At + i] != 0x02 || B[At + i + 1] != 0x82)
            return 0;
    }
    return 1;
}

int
PtDecode(
    const uint8_t* Buf,
    uint32_t Len,
    PT_DECODE_RESULT* Out
    )
{
    return PtDecodeEx(Buf, Len, Out, NULL, NULL);
}

int
PtDecodeEx(
    const uint8_t* Buf,
    uint32_t Len,
    PT_DECODE_RESULT* Out,
    PT_PACKET_SINK Sink,
    void* SinkCtx
    )
{
    memset(Out, 0, sizeof(*Out));
    /* ⚠ 0 IS A VALID MTC CTC VALUE, so "none seen" cannot be 0. Set after the memset rather than
     * relying on it -- a zeroed struct and "no MTC packet present" are different facts, and
     * conflating a valid value with the unset sentinel already cost a hardware run today. */
    Out->MtcFirst = 0x100u;
    Out->MtcLast  = 0x100u;

    if (Buf == NULL || Len == 0)
        return 0;

    /*
     * ⚠ FIND A PSB AND START THERE. On a wrapped region byte 0 is mid-packet, and the first
     * plausible-looking opcode found there would send everything after it down a misaligned stream.
     * PSB is the architecture's answer: a 16-byte pattern that cannot occur inside another packet,
     * emitted periodically for exactly this purpose.
     */
    uint32_t Start = 0;
    int Found = 0;
    for (uint32_t i = 0; i + 16 <= Len; i++)
    {
        if (IsPsbAt(Buf, Len, i)) { Start = i; Found = 1; break; }
    }
    if (!Found)
    {
        /* Not an error. An all-zero region (nothing traced) and a region of pure PAD both land
         * here, and both are true answers about the buffer. */
        Out->FoundPsb = 0;
        Out->Ok = 1;
        return 0;
    }

    Out->FoundPsb  = 1;
    Out->StartedAt = Start;

    uint64_t LastIp = 0;
    uint32_t P = Start;

    /*
     * ⚠ PSB..PSBEND IS STATUS, NOT HISTORY. The packets inside a PSB+ sequence restate the current
     * state -- a FUP there gives where the machine IS, not a branch that was taken. A reconstructor
     * that treats that FUP as an asynchronous event invents an interrupt at every PSB, and PSBs are
     * emitted periodically forever. Flagged here because only the parser knows the boundary.
     */
    int InPsb = 0;
    uint64_t TntBitsOut = 0;
    unsigned TntCountOut = 0;
    uint64_t PktPayload = 0;
    unsigned PktFlags = 0;

    while (P < Len)
    {
        const uint8_t B0 = Buf[P];
        uint32_t Size = 0;
        unsigned Kind = PT_PK_COUNT;

        TntBitsOut  = 0;
        TntCountOut = 0;
        PktPayload  = 0;
        PktFlags    = InPsb ? PT_PKF_IN_PSB : 0u;

        if (IsPsbAt(Buf, Len, P))
        {
            Kind = PT_PK_PSB; Size = 16; InPsb = 1;
        }
        else if (B0 == PT_OPC_PAD)
        {
            Kind = PT_PK_PAD; Size = 1;
        }
        else if (B0 == PT_OPC_EXT)
        {
            if (P + 1 >= Len) break;
            const uint8_t B1 = Buf[P + 1];

            if      (B1 == PT_EXT_PSBEND) { Kind = PT_PK_PSBEND; Size = 2; InPsb = 0; }
            else if (B1 == PT_EXT_OVF)    { Kind = PT_PK_OVF;    Size = 2; }
            else if (B1 == PT_EXT_STOP)   { Kind = PT_PK_STOP;   Size = 2; }
            else if (B1 == PT_EXT_CBR)
            {
                Kind = PT_PK_CBR; Size = 4;
                /* CBR: 02 03 <ratio:8> <reserved:8>. The ratio is what converts CYC counts into
                 * time, so it is kept rather than counted. */
                if (P + 2 < Len) Out->CbrLast = Buf[P + 2];
            }
            else if (B1 == PT_EXT_TMA)    { Kind = PT_PK_TMA;    Size = 7; }
            else if (B1 == PT_EXT_TNT64)
            {
                /*
                 * Long TNT: 02 A3 then 6 payload bytes. SDM vol 3 Table 34-16 lays the results out
                 * with B1 in the LAST byte's bit 6 and B47 in the FIRST payload byte's bit 0, so
                 * the six bytes assemble with byte 7 most significant -- the reverse of the
                 * little-endian order every other payload in this format uses. Getting that
                 * backwards does not fail; it silently reverses the program's branch history.
                 */
                Kind = PT_PK_TNT64; Size = 8;
                if (P + 8 <= Len)
                {
                    uint64_t Field = 0;
                    for (uint32_t k = 0; k < 6; k++)
                        Field |= (uint64_t)Buf[P + 2 + k] << (8 * k);

                    TntCountOut = DecodeTnt(Field, 48, &TntBitsOut);
                    if (TntCountOut == 0)
                    {
                        /* No Stop bit in 48 bits. Every TNT carries at least one result, so this
                         * was not a TNT and the stream is misaligned -- stop, do not contribute. */
                        Out->StopByte = B1;
                        break;
                    }
                    Out->TntBitsSeen += TntCountOut;
                }
            }
            else if (B1 == PT_EXT_PIP)    { Kind = PT_PK_PIP;    Size = 8; }
            else if (B1 == PT_EXT_VMCS)   { Kind = PT_PK_VMCS;   Size = 7; }
            else if (B1 == PT_EXT_MNT_HI) { Kind = PT_PK_MNT;    Size = 11; }
            else if ((B1 & 0x1F) == PT_EXT_PTW)
            {
                /*
                 * PTW: 02 <PayloadBytes:2 | IP:1 | 0x12>. Bits 6:5 select the operand width --
                 * 0 = 4 bytes, 1 = 8 bytes. Bit 7 (IP) says a FUP follows carrying the address of
                 * the PTWRITE itself; that FUP is decoded as an ordinary FUP by the IP path below,
                 * so nothing special is needed for it here.
                 */
                const unsigned PtwW = (unsigned)((B1 >> 5) & 3);
                const uint32_t PtwBytes = (PtwW == 0) ? 4u : 8u;
                Kind = PT_PK_PTW;
                Size = 2 + PtwBytes;
                if (P + 2 + PtwBytes <= Len)
                {
                    uint64_t V = 0;
                    for (uint32_t k = 0; k < PtwBytes; k++)
                        V |= (uint64_t)Buf[P + 2 + k] << (8 * k);
                    PktPayload = V;
                    /* D3: SEEN and STORED are different numbers and both are reported. */
                    Out->PtwSeen++;
                    if (Out->PtwCount < PT_MAX_PTW)
                        Out->PtwValues[Out->PtwCount++] = V;
                }
            }
            else
            {
                Out->StopByte = B1;
                break;
            }
        }
        else if ((B0 & PT_OPM_TNT8) == 0)
        {
            /* Short TNT: any byte with bit 0 clear that is not PAD. PAD is checked first, above,
             * which is why this ordering is not interchangeable. */
            Kind = PT_PK_TNT8; Size = 1;

            /* Bit 0 is the opcode marker, so the 7-bit field starts one bit up. */
            TntCountOut = DecodeTnt((uint64_t)(B0 >> 1), 7, &TntBitsOut);
            if (TntCountOut == 0)
            {
                Out->StopByte = B0;
                break;
            }
            Out->TntBitsSeen += TntCountOut;
        }
        else if (B0 == PT_OPC_MODE) { Kind = PT_PK_MODE; Size = 2; }
        else if (B0 == PT_OPC_TSC)
        {
            /* TSC: 0x19 followed by a 7-byte (56-bit) timestamp, little-endian. */
            Kind = PT_PK_TSC; Size = 8;
            if (P + 8 <= Len)
            {
                uint64_t T = 0;
                for (uint32_t k = 0; k < 7; k++) T |= (uint64_t)Buf[P + 1 + k] << (8 * k);
                PktPayload = T;
                if (Out->Counts[PT_PK_TSC] == 0) Out->TscFirst = T;
                Out->TscLast = T;

                /* The OFFSET is the half that makes this an anchor rather than a timestamp: it is
                 * what lets a PEBS record's TSC be resolved to a position in this buffer. */
                Out->TscAnchorsSeen++;
                if (Out->TscAnchorCount < PT_MAX_TSC)
                {
                    Out->TscAnchors[Out->TscAnchorCount].Tsc    = T;
                    Out->TscAnchors[Out->TscAnchorCount].Offset = P;
                    Out->TscAnchorCount++;
                }
            }
        }
        else if (B0 == PT_OPC_MTC)
        {
            /* MTC: 0x59 followed by one CTC byte. 0 IS A VALID CTC VALUE, which is why "none seen"
             * is 0x100 rather than 0 -- the same sentinel mistake that cost a hardware run on
             * `trace alloc 0` earlier today. */
            Kind = PT_PK_MTC; Size = 2;
            if (P + 2 <= Len)
            {
                if (Out->Counts[PT_PK_MTC] == 0) Out->MtcFirst = Buf[P + 1];
                Out->MtcLast = Buf[P + 1];
            }
        }
        else if ((B0 & PT_OPM_CYC) == PT_OPM_CYC)
        {
            /*
             * ⚠ THE CONTINUATION BIT IS NOT IN THE SAME PLACE IN EVERY BYTE, and this loop used to
             * assume it was. It read `Buf[P + Size - 1] & 0x04` for every byte -- correct for the
             * FIRST byte and wrong for every one after it.
             *
             *   byte 0 :  bits 1:0 = 11 (opcode), bit 2 = EXP, bits 7:3 = counter[4:0]
             *   byte n :  bit 0    = EXP,                      bits 7:1 = the next 7 counter bits
             *
             * libipt names them separately for exactly this reason (pt_opm_cyc_ext = 0x04,
             * pt_opm_cycx_ext = 0x01). A multi-byte CYC was therefore mis-sized, and the decoder
             * would resume mid-packet and stop on "an unknown opcode" some bytes later -- failing
             * closed, so it was never going to invent addresses, but it would have reported the
             * trace as corrupt and the real cause would have been here.
             *
             * ⚠ IT WAS UNREACHABLE UNTIL NOW. Nothing this project armed had ever set CYCEn, so no
             * CYC packet had ever existed to mis-size. Enabling a feature is also how you find out
             * what the code that handles it was doing wrong.
             */
            Size = 1;
            int More = (B0 & 0x04) != 0;
            while (More && (P + Size) < Len && Size < 16)
            {
                More = (Buf[P + Size] & 0x01) != 0;
                Size++;
            }
            Kind = PT_PK_CYC;

            /*
             * CYC payload: the first byte carries 5 bits (7:3) and each continuation byte adds 7
             * more (7:1), little-endian by significance. Summed rather than stored per packet --
             * the useful figure is total cycles the trace accounts for, and one entry per CYC
             * packet would dwarf the trace itself.
             */
            uint64_t Cyc = (uint64_t)(B0 >> 3);
            unsigned Shift = 5;
            for (uint32_t k = 1; k < Size && Shift < 64; k++)
            {
                Cyc |= (uint64_t)(Buf[P + k] >> 1) << Shift;
                Shift += 7;
            }
            Out->CycTotal += Cyc;
        }
        else
        {
            const uint8_t Low = (uint8_t)(B0 & PT_OPM_IP);
            if (Low == PT_OPC_TIP || Low == PT_OPC_TIP_PGE ||
                Low == PT_OPC_TIP_PGD || Low == PT_OPC_FUP)
            {
                const unsigned Ipc = (unsigned)((B0 & PT_OPM_IPC) >> PT_OPM_IPC_SHR);
                int Suppressed = 0;
                if (P + 1 > Len) break;

                const int Payload = DecodeIp(Buf + P + 1, Ipc, &LastIp, &Suppressed);
                if (Payload < 0 || (P + 1 + (uint32_t)Payload) > Len)
                {
                    Out->StopByte = B0;
                    break;
                }

                Kind = (Low == PT_OPC_TIP)     ? PT_PK_TIP
                     : (Low == PT_OPC_TIP_PGE) ? PT_PK_TIP_PGE
                     : (Low == PT_OPC_TIP_PGD) ? PT_PK_TIP_PGD
                                               : PT_PK_FUP;
                Size = 1 + (uint32_t)Payload;

                if (Suppressed)
                {
                    /* ⚠ THE PACKET IS REAL AND THE ADDRESS IS NOT. LastIp is deliberately left
                     * alone (the SDM keeps it unchanged on a suppressed IP), so the payload here
                     * would be the PREVIOUS packet's address wearing this packet's name. The flag
                     * is what stops a consumer reading it as an address this packet supplied. */
                    PktFlags |= PT_PKF_IP_SUPPRESSED;
                    Out->IpsSuppressed++;
                }
                else
                {
                    PktPayload = LastIp;
                    /* D3 again: IpsSeen counts what was RECOVERED, IpCount what FIT. A caller that
                     * saw only the array would read a truncated list as the whole trace. */
                    Out->IpsSeen++;
                    if (Out->IpCount < PT_MAX_IPS)
                        Out->Ips[Out->IpCount++] = LastIp;
                }
            }
            else
            {
                Out->StopByte = B0;
                break;
            }
        }

        if (Size == 0 || P + Size > Len)
            break;

        Out->Counts[Kind]++;

        /*
         * ⚠ EMITTED AFTER THE SIZE CHECK, so a consumer never sees a packet that ran off the end of
         * the buffer. A truncated last packet is not half a packet -- it is not a packet, and the
         * summary above deliberately does not count it either.
         */
        if (Sink != NULL)
        {
            PT_PACKET Pk;
            memset(&Pk, 0, sizeof(Pk));
            Pk.Offset  = P;
            Pk.Size    = (uint16_t)Size;
            Pk.Kind    = (uint8_t)Kind;
            Pk.Flags   = (uint8_t)PktFlags;
            Pk.Payload = (Kind == PT_PK_TNT8 || Kind == PT_PK_TNT64) ? TntBitsOut : PktPayload;
            Pk.TntBits = (uint8_t)TntCountOut;

            if (Sink(SinkCtx, &Pk) != 0)
            {
                P += Size;
                break;
            }
        }

        P += Size;
    }

    Out->StoppedAt    = P;
    Out->BytesDecoded = P - Start;
    Out->Ok           = (uint8_t)((P >= Len) ? 1 : 0);
    return 0;
}
