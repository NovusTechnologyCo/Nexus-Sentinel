/**
 * @file Tpm2PeHash.c
 * @brief Authenticode PE/COFF image hash. Read Tpm2PeHash.h first — it records why this exists
 *        and what happened without it.
 *
 * ⚠ PE STRUCTURES ARE READ FIELD BY FIELD AT DOCUMENTED OFFSETS rather than through a struct cast.
 * Two reasons, and both have bitten this project already:
 *
 *   - A cast to a packed struct over an unvalidated buffer reads whatever is there. Every offset
 *     below is bounds-checked BEFORE the read, which a struct cast makes impossible to express.
 *   - It keeps this file dependency-free, so it compiles on the host and can be checked against an
 *     independent oracle. `pe.h` in the DXE would drag in the firmware build.
 *
 * The offsets are from the PE/COFF specification and are stated in the code, so a reader can check
 * them without a header to hand.
 */

#include "Tpm2PeHash.h"

//
// DOS header
//
#define PE_DOS_MAGIC              0x5A4D      /* 'MZ' */
#define PE_DOS_LFANEW_OFFSET      0x3C

//
// NT headers: Signature (4) + FileHeader (20) + OptionalHeader
//
#define PE_NT_SIGNATURE           0x00004550  /* 'PE\0\0' */
#define PE_FILE_HEADER_SIZE       20
#define PE_OPT_HEADER_OFFSET      (4 + PE_FILE_HEADER_SIZE)

//
// FileHeader fields, from the start of the NT headers.
//
#define PE_FH_NUMBER_OF_SECTIONS  (4 + 2)
#define PE_FH_SIZE_OF_OPT_HEADER  (4 + 16)

//
// OptionalHeader magic.
//
#define PE_OPT_MAGIC_PE32         0x010B
#define PE_OPT_MAGIC_PE32PLUS     0x020B

//
// ⚠ CheckSum and SizeOfHeaders sit at the SAME optional-header offset in PE32 and PE32+, because
// everything that differs in width comes after them. The data directories do NOT -- PE32+ widens
// ImageBase and the four stack/heap fields, pushing them 16 bytes later.
//
#define PE_OPT_SIZE_OF_HEADERS    60
#define PE_OPT_CHECKSUM           64
#define PE_OPT_NUMRVA_PE32        92
#define PE_OPT_DATADIR_PE32       96
#define PE_OPT_NUMRVA_PE32PLUS    108
#define PE_OPT_DATADIR_PE32PLUS   112

//
// Data directory 4 is the Certificate Table (the attribute certificate / Authenticode signature).
//
#define PE_DIR_SECURITY           4
#define PE_DATA_DIRECTORY_SIZE    8           /* RVA (4) + Size (4) */

//
// Section header
//
#define PE_SECTION_HEADER_SIZE    40
#define PE_SEC_SIZE_OF_RAW_DATA   16
#define PE_SEC_POINTER_TO_RAW     20

//
// A hard cap on sections. NumberOfSections is a UINT16 read from an unvalidated image, and the
// sort below is O(n^2); 96 is well above anything a real boot image has (bootmgfw has ~8) and
// bounds both the loop and the on-stack index table.
//
#define PE_MAX_SECTIONS           96

STATIC
UINT16
Rd16(
	IN CONST UINT8* P
	)
{
	return (UINT16)((UINT16)P[0] | ((UINT16)P[1] << 8));
}

STATIC
UINT32
Rd32(
	IN CONST UINT8* P
	)
{
	return (UINT32)P[0] | ((UINT32)P[1] << 8) | ((UINT32)P[2] << 16) | ((UINT32)P[3] << 24);
}

/**
 * TRUE if [Off, Off+Len) lies wholly inside [0, Size). Written so that neither addition can wrap.
 */
STATIC
BOOLEAN
InBounds(
	IN UINT64 Off,
	IN UINT64 Len,
	IN UINT64 Size
	)
{
	if (Off > Size)
		return FALSE;
	if (Len > Size - Off)
		return FALSE;
	return TRUE;
}

BOOLEAN
Tpm2HashPeImage(
	IN  CONST UINT8* Image,
	IN  UINT64       Size,
	OUT UINT8        Digest[TPM2_SHA256_DIGEST_SIZE]
	)
{
	SHA256_CONTEXT Ctx;
	UINT32         Lfanew;
	UINT32         OptOff;          /* file offset of the optional header      */
	UINT16         OptMagic;
	UINT16         OptSize;
	UINT16         NumSections;
	UINT32         SizeOfHeaders;
	UINT32         NumRva;
	UINT32         DirOff;          /* file offset of DataDirectory[0]         */
	UINT32         SecDirOff;       /* file offset of the Certificate entry    */
	UINT32         CertRva;
	UINT32         CertSize;
	UINT32         SectionTableOff;
	UINT64         SumHashed;
	UINT32         HashBase;
	UINT32         HashSize;
	UINT16         Order[PE_MAX_SECTIONS];
	UINT16         i, j;

	if (Image == NULL || Digest == NULL)
		return FALSE;

	//
	// --- DOS header -----------------------------------------------------------------------
	//
	if (!InBounds(0, PE_DOS_LFANEW_OFFSET + 4, Size))
		return FALSE;
	if (Rd16(Image) != PE_DOS_MAGIC)
		return FALSE;

	Lfanew = Rd32(Image + PE_DOS_LFANEW_OFFSET);

	//
	// --- NT headers -----------------------------------------------------------------------
	//
	if (!InBounds(Lfanew, PE_OPT_HEADER_OFFSET, Size))
		return FALSE;
	if (Rd32(Image + Lfanew) != PE_NT_SIGNATURE)
		return FALSE;

	NumSections = Rd16(Image + Lfanew + PE_FH_NUMBER_OF_SECTIONS);
	OptSize     = Rd16(Image + Lfanew + PE_FH_SIZE_OF_OPT_HEADER);
	OptOff      = Lfanew + PE_OPT_HEADER_OFFSET;

	if (NumSections == 0 || NumSections > PE_MAX_SECTIONS)
		return FALSE;
	if (!InBounds(OptOff, OptSize, Size))
		return FALSE;
	if (OptSize < PE_OPT_CHECKSUM + 4)
		return FALSE;

	OptMagic = Rd16(Image + OptOff);
	if (OptMagic == PE_OPT_MAGIC_PE32)
	{
		DirOff = OptOff + PE_OPT_DATADIR_PE32;
		if (OptSize < PE_OPT_NUMRVA_PE32 + 4)
			return FALSE;
		NumRva = Rd32(Image + OptOff + PE_OPT_NUMRVA_PE32);
	}
	else if (OptMagic == PE_OPT_MAGIC_PE32PLUS)
	{
		DirOff = OptOff + PE_OPT_DATADIR_PE32PLUS;
		if (OptSize < PE_OPT_NUMRVA_PE32PLUS + 4)
			return FALSE;
		NumRva = Rd32(Image + OptOff + PE_OPT_NUMRVA_PE32PLUS);
	}
	else
	{
		return FALSE;
	}

	SizeOfHeaders = Rd32(Image + OptOff + PE_OPT_SIZE_OF_HEADERS);
	if (!InBounds(0, SizeOfHeaders, Size))
		return FALSE;

	//
	// The section table follows the optional header.
	//
	SectionTableOff = OptOff + OptSize;
	if (!InBounds(SectionTableOff, (UINT64)NumSections * PE_SECTION_HEADER_SIZE, Size))
		return FALSE;

	//
	// Is there a Certificate directory entry at all? A directory count of 5 or more means index 4
	// exists. An image with fewer simply has no signature slot, which is step 6's case.
	//
	SecDirOff = 0;
	CertRva   = 0;
	CertSize  = 0;
	if (NumRva > PE_DIR_SECURITY)
	{
		SecDirOff = DirOff + (PE_DIR_SECURITY * PE_DATA_DIRECTORY_SIZE);
		if (!InBounds(SecDirOff, PE_DATA_DIRECTORY_SIZE, Size))
			return FALSE;
		CertRva  = Rd32(Image + SecDirOff);
		CertSize = Rd32(Image + SecDirOff + 4);
	}

	Sha256Init(&Ctx);

	//
	// --- steps 3-4: base .. CheckSum ------------------------------------------------------
	//
	HashBase = 0;
	HashSize = OptOff + PE_OPT_CHECKSUM;
	if (!InBounds(HashBase, HashSize, Size))
		return FALSE;
	Sha256Update(&Ctx, Image + HashBase, HashSize);

	//
	// --- step 5: SKIP CheckSum (4 bytes) --------------------------------------------------
	//
	HashBase = OptOff + PE_OPT_CHECKSUM + 4;

	if (SecDirOff == 0)
	{
		//
		// --- step 6: no Certificate directory, hash straight on to the end of the headers ---
		//
		if (SizeOfHeaders < HashBase)
			return FALSE;
		HashSize = SizeOfHeaders - HashBase;
		if (HashSize != 0)
		{
			if (!InBounds(HashBase, HashSize, Size))
				return FALSE;
			Sha256Update(&Ctx, Image + HashBase, HashSize);
		}
	}
	else
	{
		//
		// --- step 7: on to the start of the Certificate directory ENTRY -------------------
		//
		if (SecDirOff < HashBase)
			return FALSE;
		HashSize = SecDirOff - HashBase;
		if (HashSize != 0)
		{
			if (!InBounds(HashBase, HashSize, Size))
				return FALSE;
			Sha256Update(&Ctx, Image + HashBase, HashSize);
		}

		//
		// --- step 8: SKIP the entry. A signature cannot be part of what it signs. ---------
		//
		HashBase = SecDirOff + PE_DATA_DIRECTORY_SIZE;

		//
		// --- step 9: from after it to the end of the headers ------------------------------
		//
		if (SizeOfHeaders < HashBase)
			return FALSE;
		HashSize = SizeOfHeaders - HashBase;
		if (HashSize != 0)
		{
			if (!InBounds(HashBase, HashSize, Size))
				return FALSE;
			Sha256Update(&Ctx, Image + HashBase, HashSize);
		}
	}

	//
	// --- step 10 -------------------------------------------------------------------------
	//
	SumHashed = SizeOfHeaders;

	//
	// --- steps 11-12: index the sections and sort by PointerToRawData ---------------------
	//
	// ⚠ THE SORT IS NOT OPTIONAL. The section table is not required to be in file order, and
	// hashing in table order yields a digest that happens to be right for most images. Insertion
	// sort on an index table: n is bounded above by PE_MAX_SECTIONS and is single digits in
	// practice, and it keeps the section headers themselves untouched.
	//
	for (i = 0; i < NumSections; i++)
		Order[i] = i;

	for (i = 1; i < NumSections; i++)
	{
		CONST UINT16 Key = Order[i];
		CONST UINT32 KeyPtr =
			Rd32(Image + SectionTableOff + (UINT32)Key * PE_SECTION_HEADER_SIZE + PE_SEC_POINTER_TO_RAW);
		j = i;
		while (j > 0)
		{
			CONST UINT32 PrevPtr =
				Rd32(Image + SectionTableOff + (UINT32)Order[j - 1] * PE_SECTION_HEADER_SIZE + PE_SEC_POINTER_TO_RAW);
			if (PrevPtr <= KeyPtr)
				break;
			Order[j] = Order[j - 1];
			j--;
		}
		Order[j] = Key;
	}

	//
	// --- steps 13-15: hash each section's raw data ----------------------------------------
	//
	for (i = 0; i < NumSections; i++)
	{
		CONST UINT32 SecOff = SectionTableOff + (UINT32)Order[i] * PE_SECTION_HEADER_SIZE;
		CONST UINT32 RawSize = Rd32(Image + SecOff + PE_SEC_SIZE_OF_RAW_DATA);
		CONST UINT32 RawPtr  = Rd32(Image + SecOff + PE_SEC_POINTER_TO_RAW);

		//
		// A zero-length section contributes nothing and is skipped -- including from the running
		// total, which is what the algorithm specifies.
		//
		if (RawSize == 0)
			continue;

		if (!InBounds(RawPtr, RawSize, Size))
			return FALSE;

		Sha256Update(&Ctx, Image + RawPtr, RawSize);
		SumHashed += RawSize;
	}

	//
	// --- step 16: trailing data, EXCLUDING the certificate table --------------------------
	//
	// ⚠ THE EXCLUSION IS THE POINT. The attribute certificate lives at the end of the file, and
	// hashing it would make the digest depend on the signature that is computed over the digest.
	//
	if (Size > SumHashed)
	{
		UINT64 Trailing = Size - SumHashed;

		if (CertSize != 0 && CertRva != 0)
		{
			if (Trailing < CertSize)
			{
				//
				// The certificate is bigger than what is left. The header is inconsistent with the
				// buffer; refuse rather than hash a negative length.
				//
				return FALSE;
			}
			Trailing -= CertSize;
		}

		if (Trailing != 0)
		{
			if (!InBounds(SumHashed, Trailing, Size))
				return FALSE;
			Sha256Update(&Ctx, Image + SumHashed, (UINTN)Trailing);
		}
	}

	Sha256Final(&Ctx, Digest);
	return TRUE;
}
