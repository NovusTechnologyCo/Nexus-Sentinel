/*
 * FileCapture.c -- B-01's second half: the CONTENT of a file that is about to be deleted.
 *
 * ==================================================================================================
 * THE SHAPE, AND WHY IT IS A QUEUE AND A WORKER (D110)
 * ==================================================================================================
 *
 * B-01 is "file capture between create and delete". The visibility half is verified in silicon --
 * `hook nt NtSetInformationFile` reports the delete as `a5 = 0x40`
 * (FileDispositionInformationEx). This is the part that keeps the bytes.
 *
 * ⚠ THE HOOK DOES ALMOST NOTHING, AND THAT IS THE DESIGN, NOT AN OPTIMISATION.
 *
 * v1 read the file inside its minifilter's pre-operation callback. We do not, because our hook runs
 * on the CALLER'S OWN THREAD inside NtSetInformationFile for that very file. Issuing file I/O there
 * means re-entering the filesystem underneath an operation that is about to take its own locks.
 *
 * So the hook does exactly one thing: ObReferenceObjectByHandle. That is object-manager work -- a
 * lookup in the handle table and an interlocked increment. No FS IRP, no allocation, no name query.
 * It converts the caller's HANDLE (process-relative, dies with the process, meaningless to a worker
 * in System) into a FILE_OBJECT pointer that is context-independent and held alive by our reference.
 *
 * ⚠ AND THE HOOK IS AT THE FUNCTION *ENTRY*, WHICH IS WHY EVEN THAT IS SAFE. NtSetInformationFile
 * has not executed a single instruction of its own body when we run, so it holds no FCB lock, no
 * resource, nothing. We are exactly where its caller was one instruction earlier. A post-operation
 * hook would be a completely different risk.
 *
 * Everything expensive -- resolving the name, opening, sizing, reading -- happens on a system thread
 * that holds nothing and can afford to block.
 *
 * ==================================================================================================
 * ⚠ THE RACE IS REAL, IS BOUNDED, AND IS REPORTED (D3/D6)
 * ==================================================================================================
 *
 * Setting delete disposition only MARKS the file; it is not unlinked until the last handle closes.
 * So a prompt worker usually reads a file that still exists. USUALLY. If the caller closes its
 * handle before the worker gets there, the open fails and that is recorded as
 * NXC_FCAP_GONE -- a distinct outcome from "too large", from "access denied", and from "we never
 * tried". A capture COUNT on its own would make a lost race indistinguishable from a quiet system,
 * which is the defect the seven-way name vocabulary in Calls.c exists to prevent, one subsystem
 * over (an earlier finding).
 *
 * Our FILE_OBJECT reference keeps the OBJECT alive so the name stays resolvable; it does NOT keep
 * the FILE alive, because delete-on-close fires on handle count, not object reference count. That
 * distinction is why the race exists at all and why it is not closed by holding the reference.
 */

#include <ntddk.h>

#include "../../Include/NexusCoreBoot.h"
#include "../../Include/NexusCommand.h"

#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"
#include "Arena.h"
#include "MapModule.h"
#include "FileCapture.h"

extern volatile NXC_NT_API NexusNtApi;
extern void NxcLogExt(_In_z_ PCSTR Format, ...);

#include "../../Include/NexusNtApiRedirect.h"

/* ---------------------------------------------------------------------------------------------
 * State. All of it is reserved once by `capture file init` and never freed -- the image does not
 * unload, so a leak is not a failure mode, but an unbounded allocation would be.
 * --------------------------------------------------------------------------------------------- */

typedef struct _NXC_FCAP_PENDING
{
	void*     FileObject;    /* referenced by the hook, dereferenced by the worker -- for the NAME */
	void*     DupHandle;     /* kernel handle duplicated by the hook -- for the BYTES              */
	/* PATH JOBS (FILE_DELETE_ON_CLOSE at create) carry the name instead: the handle does not exist
	 * yet at the entry we hook, and the path is live because the delete has not fired. */
	NXCMD_U16 Path[NXCMD_FCAP_NAME_CHARS];
	NXCMD_U32 PathChars;
	NXCMD_U32 Pid;
	NXCMD_U32 Tid;
	NXCMD_U64 TimeStamp;
	NXCMD_U32 InfoClass;     /* which disposition class triggered this            */
} NXC_FCAP_PENDING;

#define NXC_FCAP_QUEUE_SLOTS 64u

static NXC_FCAP_PENDING gQueue[NXC_FCAP_QUEUE_SLOTS];
static volatile LONG    gQueueHead = 0;   /* producer claims here */
static volatile LONG    gQueueTail = 0;   /* worker consumes here */
static KSPIN_LOCK       gQueueLock;

static NXCMD_FCAP_ENTRY* volatile gRecords    = NULL;
static LONG                       gRecordSlots = 0;
static volatile LONG64            gRecordNext  = 0;

static UINT8*  gByteArena     = NULL;   /* one flat block; captures are packed into it */
static UINT64  gByteArenaSize = 0;
static volatile LONG64 gByteArenaUsed = 0;

static KEVENT  gWakeEvent;
static void*   gWorkerThread  = NULL;
static volatile LONG gWorkerStop = 0;
static volatile LONG gInitDone   = 0;

/* Counters. Every one of these answers a question a capture count alone cannot. */
static volatile LONG64 gQueued      = 0;
static volatile LONG64 gQueueFull   = 0;   /* producer had nowhere to put it       */
static volatile LONG64 gRefFailed   = 0;   /* the handle would not reference        */
static volatile LONG64 gCaptured    = 0;
static volatile LONG64 gGone        = 0;   /* lost the race -- file already unlinked */

/* IoFileObjectType is a DATA export, resolved the same way PsProcessType is -- by name, in ring 0,
 * per boot. Cached because the value cannot change during a boot and the resolve walks an export
 * directory. */
static void* gFileObjectType = NULL;

static void*
FcapFileObjectType(void)
{
	if (gFileObjectType == NULL)
	{
		/* ⚠ THE EXPORT IS A POINTER TO THE TYPE, SO IT IS DEREFERENCED ONCE. `IoFileObjectType` is
		 * declared `extern POBJECT_TYPE IoFileObjectType;` -- the export's ADDRESS is where that
		 * pointer variable lives, not the type itself. Passing the export address straight to
		 * ObReferenceObjectByHandle would compare against a pointer-to-a-pointer and reject every
		 * handle, which is a refusal that would have looked like an access problem. */
		void** CONST Slot = (void**)NxcResolveNtExport("IoFileObjectType");
		if (Slot != NULL)
			gFileObjectType = *Slot;
	}
	return gFileObjectType;
}

/* ---------------------------------------------------------------------------------------------
 * THE PRODUCER -- runs inside the hook, on the caller's thread. Bounded, lock-brief, no I/O.
 * --------------------------------------------------------------------------------------------- */

void
NxcFileCaptureOnDelete(
	_In_ UINT64 Handle,
	_In_ UINT32 InfoClass
	)
{
	if (gInitDone == 0)
		return;   /* not armed -- record nothing rather than reference objects nobody will release */

	void* CONST Type = FcapFileObjectType();
	if (Type == NULL)
		return;

	/*
	 * ⚠ REFERENCE FIRST, QUEUE SECOND, AND RELEASE IF THE QUEUE IS FULL. The reference is what makes
	 * the pointer safe to hold; dropping a queued entry without dereferencing would leak a
	 * FILE_OBJECT reference per lost delete, and a leaked reference on a file object keeps a volume
	 * from dismounting -- a failure that shows up nowhere near here.
	 */
	void* FileObject = NULL;
	CONST NTSTATUS RSt = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)Handle, 0, Type,
	                                               KernelMode, &FileObject, NULL);
	if (!NT_SUCCESS(RSt) || FileObject == NULL)
	{
		InterlockedIncrement64(&gRefFailed);
		return;
	}

	/*
	 * ⚠⚠ AND DUPLICATE THE HANDLE, WHICH IS THE PART THAT ACTUALLY KEEPS THE BYTES.
	 *
	 * The reference above keeps the OBJECT alive so its name stays resolvable. It does NOT keep the
	 * FILE readable: measured, the first run resolved the path perfectly and then failed
	 * to reopen it with STATUS_OBJECT_NAME_NOT_FOUND. Class 64 is FileDispositionInformationEx with
	 * POSIX semantics -- the NAME is unlinked the moment the call completes, while the data stays
	 * reachable through handles already open. No worker is fast enough, because there is no window.
	 *
	 * A duplicated handle is immune to exactly that, by design, and it also defers a CLASSIC (class
	 * 13) delete, which fires on the last handle close. One primitive covers both dispositions.
	 *
	 * ⚠ FILE_READ_DATA IS REQUESTED EXPLICITLY RATHER THAN DUPLICATE_SAME_ACCESS. Remove-Item opens
	 * with DELETE and little else, so SAME_ACCESS would hand us a handle that cannot read and the
	 * failure would arrive much later, as an ACCESS_DENIED from ZwReadFile, looking like a
	 * permissions problem rather than a duplication choice. Calling from kernel mode means the
	 * access check is bypassed, so asking for what we need is both honest and cheaper.
	 *
	 * ⚠ SAME_ACCESS IS STILL THE FALLBACK, because "we could not get read access" and "we could not
	 * duplicate at all" are different facts and only the second is fatal here.
	 */
	HANDLE Dup = NULL;
	NTSTATUS DSt = ZwDuplicateObject(ZwCurrentProcess(), (HANDLE)(ULONG_PTR)Handle,
	                                 ZwCurrentProcess(), &Dup,
	                                 FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
	                                 OBJ_KERNEL_HANDLE, 0);
	if (!NT_SUCCESS(DSt))
	{
		DSt = ZwDuplicateObject(ZwCurrentProcess(), (HANDLE)(ULONG_PTR)Handle,
		                        ZwCurrentProcess(), &Dup, 0,
		                        OBJ_KERNEL_HANDLE, DUPLICATE_SAME_ACCESS);
	}
	if (!NT_SUCCESS(DSt))
		Dup = NULL;   /* recorded as a reason later; the name is still worth having */

	KIRQL Old;
	KeAcquireSpinLock(&gQueueLock, &Old);

	CONST LONG Head = gQueueHead;
	CONST LONG Next = (Head + 1) % (LONG)NXC_FCAP_QUEUE_SLOTS;
	BOOLEAN Accepted = FALSE;

	if (Next != gQueueTail)          /* one slot always left empty: full and empty must differ */
	{
		gQueue[Head].FileObject = FileObject;
		gQueue[Head].DupHandle  = Dup;
		gQueue[Head].Pid        = (NXCMD_U32)(ULONG_PTR)PsGetCurrentProcessId();
		gQueue[Head].Tid        = (NXCMD_U32)(ULONG_PTR)PsGetCurrentThreadId();
		gQueue[Head].InfoClass  = InfoClass;
		{
			LARGE_INTEGER Pc = KeQueryPerformanceCounter(NULL);
			gQueue[Head].TimeStamp = (NXCMD_U64)Pc.QuadPart;
		}
		gQueueHead = Next;
		Accepted   = TRUE;
	}

	KeReleaseSpinLock(&gQueueLock, Old);

	if (!Accepted)
	{
		/* ⚠ COUNTED, and the count is REPORTED. A silently dropped delete is a file that vanished
		 * with no record that we ever saw it go -- indistinguishable from a delete that never
		 * happened, which is the worst possible reading for this particular subsystem. */
		InterlockedIncrement64(&gQueueFull);
		/* ⚠ BOTH are released. The handle leak would be worse than the reference leak: a kernel
		 * handle on a file marked for deletion DEFERS that deletion for the life of the boot. */
		if (Dup != NULL)
			ZwClose(Dup);
		ObfDereferenceObject(FileObject);
		return;
	}

	InterlockedIncrement64(&gQueued);
	KeSetEvent(&gWakeEvent, 0, FALSE);
}

/*
 * The OTHER delete, and the one the disposition hook is structurally blind to.
 *
 * ⚠ A FILE CREATED WITH FILE_DELETE_ON_CLOSE NEVER REACHES NtSetInformationFile. It is unlinked when
 * the last handle closes, with no disposition call anywhere on the system. Covering only the
 * disposition path would have been a capture that claims "between create and delete" while missing
 * an entire class of deletes -- the feature-scale version of
 * An earlier finding.
 *
 * ⚠ AND THIS ONE QUEUES A PATH, NOT A HANDLE, FOR THE EXACT OPPOSITE REASON. At the NtCreateFile
 * entry the handle DOES NOT EXIST -- arg1 is an out-parameter and the syscall body has not run -- so
 * there is nothing to duplicate. The path, meanwhile, is unambiguously live: delete-on-close cannot
 * have fired on a file that is only now being opened. Each trigger uses the route the other cannot.
 *
 * ⚠ THE WORKER MAY THEREFORE READ A FILE THAT IS STILL BEING WRITTEN, and that is honest rather than
 * wrong: what it captures is the content at the moment it looked. A capture taken at CLOSE would be
 * the final content, and reaching that means hooking NtClose -- one of the hottest calls in the
 * system -- which is a much larger cost for a difference this feature does not yet need.
 */
void
NxcFileCaptureOnCreateDeleteOnClose(
	_In_reads_(NameChars) CONST UINT16* Name,
	_In_ UINT32 NameChars,
	_In_ UINT32 CreateOptions
	)
{
	if (gInitDone == 0 || Name == NULL || NameChars == 0)
		return;

	UINT32 Chars = NameChars;
	if (Chars > NXCMD_FCAP_NAME_CHARS)
		Chars = NXCMD_FCAP_NAME_CHARS;

	KIRQL Old;
	KeAcquireSpinLock(&gQueueLock, &Old);

	CONST LONG Head = gQueueHead;
	CONST LONG Next = (Head + 1) % (LONG)NXC_FCAP_QUEUE_SLOTS;
	BOOLEAN Accepted = FALSE;

	if (Next != gQueueTail)
	{
		gQueue[Head].FileObject = NULL;   /* nothing referenced -- there was nothing to reference */
		gQueue[Head].DupHandle  = NULL;
		gQueue[Head].PathChars  = Chars;
		for (UINT32 i = 0; i < Chars; i++)
			gQueue[Head].Path[i] = Name[i];
		gQueue[Head].Pid       = (NXCMD_U32)(ULONG_PTR)PsGetCurrentProcessId();
		gQueue[Head].Tid       = (NXCMD_U32)(ULONG_PTR)PsGetCurrentThreadId();
		gQueue[Head].InfoClass = CreateOptions;   /* the CreateOptions that triggered it */
		{
			LARGE_INTEGER Pc = KeQueryPerformanceCounter(NULL);
			gQueue[Head].TimeStamp = (NXCMD_U64)Pc.QuadPart;
		}
		gQueueHead = Next;
		Accepted   = TRUE;
	}

	KeReleaseSpinLock(&gQueueLock, Old);

	if (!Accepted)
	{
		InterlockedIncrement64(&gQueueFull);
		return;   /* nothing to release: this job never held a reference or a handle */
	}

	InterlockedIncrement64(&gQueued);
	KeSetEvent(&gWakeEvent, 0, FALSE);
}

/* ---------------------------------------------------------------------------------------------
 * THE WORKER -- a system thread. Holds nothing, may block, does all the real work.
 * --------------------------------------------------------------------------------------------- */

/* Pull one entry, or return FALSE. */
static BOOLEAN
FcapDequeue(
	_Out_ NXC_FCAP_PENDING* Out
	)
{
	KIRQL Old;
	BOOLEAN Got = FALSE;

	KeAcquireSpinLock(&gQueueLock, &Old);
	if (gQueueTail != gQueueHead)
	{
		*Out = gQueue[gQueueTail];
		gQueueTail = (gQueueTail + 1) % (LONG)NXC_FCAP_QUEUE_SLOTS;
		Got = TRUE;
	}
	KeReleaseSpinLock(&gQueueLock, Old);
	return Got;
}

/*
 * Read the whole buffer, waiting properly if the I/O goes asynchronous.
 *
 * ⚠ THE HANDLE IS SOMEBODY ELSE'S AND WE DID NOT CHOOSE ITS FLAGS. It was duplicated from whatever
 * the caller opened, so it may or may not be FILE_SYNCHRONOUS_IO_*. On a non-synchronous handle
 * ZwReadFile returns STATUS_PENDING and the IO_STATUS_BLOCK is not yet valid -- reading Information
 * at that point yields a number that means nothing, which would be recorded as a successful short
 * read. Waiting on the FILE handle is only correct when it is synchronous, so an explicit event is
 * used: it is right in both cases and costs one object.
 *
 * ⚠ NON-CACHED IS NOT REQUESTED HERE, deliberately, and this is a change from v1. v1 opened its own
 * handle and could ask for FLTFL_IO_OPERATION_NON_CACHED; we inherited this one. Forcing non-cached
 * on a handle opened for cached access means sector-aligned offsets and lengths, and this file is
 * about to be deleted -- the cache holds the same bytes the disk does, and a partial read for
 * alignment reasons would be worse than a cached one.
 */
static NTSTATUS
FcapReadAll(
	_In_  HANDLE           File,
	_Out_writes_bytes_(Bytes) void* Buffer,
	_In_  ULONG            Bytes,
	_Out_ IO_STATUS_BLOCK* Iosb
	)
{
	HANDLE Event = NULL;
	OBJECT_ATTRIBUTES Oa;
	InitializeObjectAttributes(&Oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	CONST NTSTATUS ESt = ZwCreateEvent(&Event, EVENT_ALL_ACCESS, &Oa, SynchronizationEvent, FALSE);
	if (!NT_SUCCESS(ESt))
		Event = NULL;   /* fall back to the handle-wait below; still better than misreading Iosb */

	LARGE_INTEGER Offset;
	Offset.QuadPart = 0;
	RtlZeroMemory(Iosb, sizeof(*Iosb));

	NTSTATUS St = ZwReadFile(File, Event, NULL, NULL, Iosb, Buffer, Bytes, &Offset, NULL);

	if (St == STATUS_PENDING)
	{
		St = ZwWaitForSingleObject(Event != NULL ? Event : File, FALSE, NULL);
		if (NT_SUCCESS(St))
			St = Iosb->Status;   /* the REAL outcome; the wait only says the I/O finished */
	}

	if (Event != NULL)
		ZwClose(Event);
	return St;
}

/*
 * Capture one file. Every exit records a REASON, including the successful one.
 */
static void
FcapCaptureOne(
	_In_ CONST NXC_FCAP_PENDING* Job
	)
{
	/*
	 * ⚠⚠ FUNCTION SCOPE, AND THE REASON IS A HANDLE LEAK THAT SUPPRESSED A DELETE.
	 *
	 * A PATH job opens its own handle. That handle used to be a local inside the block below, while
	 * the teardown at `done:` closed only Job->DupHandle -- which is NULL for exactly those jobs. So
	 * every create-side capture LEAKED A KERNEL HANDLE, permanently.
	 *
	 * measured, and the symptom was not "a handle count": the probe file created with
	 * FILE_DELETE_ON_CLOSE was still on disk 3 seconds after its owner closed. Delete-on-close fires
	 * on the LAST handle, and ours never went away -- so the capture was SUPPRESSING the deletion it
	 * exists to observe.
	 *
	 * ⚠ An independent usermode oracle separated the two candidate causes before a line was changed:
	 *     A  no second open                      -> deleted
	 *     B  second open, CLOSED before caller   -> deleted
	 *     C  second open, STILL OPEN at close    -> NOT deleted
	 * B is what the worker was believed to do and it does not suppress; the run matched C. That made
	 * "our handle is still open" a measurement rather than a theory.
	 *
	 * ⚠ AND THIS WAS INTRODUCED BY THE FIX THAT CONSOLIDATED OWNERSHIP. Moving every close to one
	 * site was right; leaving a SECOND owner outside it was the defect -- a teardown that is a list
	 * of one, which is the same shape as the flag mask that silently dropped new flags.
	 */
	HANDLE Opened = NULL;

	NXCMD_FCAP_ENTRY* CONST Records = gRecords;
	if (Records == NULL)
	{
		if (Job->DupHandle != NULL)
			ZwClose((HANDLE)Job->DupHandle);
		if (Job->FileObject != NULL)
			ObfDereferenceObject(Job->FileObject);
		return;
	}

	CONST LONG64 Ticket = InterlockedIncrement64(&gRecordNext);
	NXCMD_FCAP_ENTRY* CONST Rec = &Records[(UINT64)(Ticket - 1) % (UINT64)gRecordSlots];

	*(volatile UINT64*)&Rec->Sequence = 0;
	Rec->Pid        = Job->Pid;
	Rec->Tid        = Job->Tid;
	Rec->TimeStamp  = Job->TimeStamp;
	Rec->InfoClass  = Job->InfoClass;
	Rec->NameChars  = 0;
	Rec->BytesCaptured = 0;
	Rec->FileSize   = 0;
	Rec->ByteOffset = 0;
	Rec->Why        = NXC_FCAP_NAME_FAILED;

	/*
	 * ==============================================================================================
	 * TWO KINDS OF JOB, AND EACH USES THE ROUTE THE OTHER CANNOT.
	 * ==============================================================================================
	 *
	 * HANDLE JOBS come from NtSetInformationFile with a delete disposition. The name may ALREADY BE
	 * GONE by the time we run -- class 64 is a POSIX unlink -- so the duplicated handle is the only
	 * way in, and the name is recorded for the operator rather than used to open anything.
	 *
	 * PATH JOBS come from NtCreateFile carrying FILE_DELETE_ON_CLOSE. There the situation is exactly
	 * inverted: the handle DOES NOT EXIST YET (arg1 is an out-parameter, unwritten at the entry we
	 * hook), while the path is unambiguously live -- delete-on-close cannot have fired, because the
	 * file is only now being opened. So the path is the only way in, and it is a good one.
	 *
	 * ⚠ THE SECOND TRIGGER EXISTS BECAUSE THE FIRST CANNOT SEE THAT DELETE AT ALL. A file created
	 * with FILE_DELETE_ON_CLOSE never reaches NtSetInformationFile: it is unlinked when the last
	 * handle closes, with no disposition call anywhere. Covering only the disposition path would have
	 * been a capture claiming "between create and delete" while missing an entire class of deletes --
	 * An earlier finding, at feature scale.
	 */
	CONST BOOLEAN PathJob = (Job->PathChars != 0);

	UCHAR NameBuf[1024];
	ULONG NameLen = 0;
	NTSTATUS QSt = STATUS_SUCCESS;

	if (PathJob)
	{
		/* The name was captured at the hook, from the OBJECT_ATTRIBUTES the caller supplied. */
		UNICODE_STRING* CONST Us = (UNICODE_STRING*)NameBuf;
		WCHAR* CONST Buf = (WCHAR*)(NameBuf + sizeof(UNICODE_STRING));
		for (UINT32 i = 0; i < Job->PathChars; i++)
			Buf[i] = (WCHAR)Job->Path[i];
		Us->Buffer        = Buf;
		Us->Length        = (USHORT)(Job->PathChars * sizeof(WCHAR));
		Us->MaximumLength = Us->Length;
	}
	else
	{
		QSt = ObQueryNameString(Job->FileObject, NameBuf, sizeof(NameBuf), &NameLen);
	}
	if (!NT_SUCCESS(QSt))
	{
		NxcLogExt("fcap: ObQueryNameString failed 0x%08X -- no path, nothing to open\n", QSt);
		goto done;
	}

	{
		/* OBJECT_NAME_INFORMATION { UNICODE_STRING Name; WCHAR Buffer[]; } -- Name.Buffer points
		 * inside NameBuf, so the string is already contiguous with its descriptor. */
		CONST UNICODE_STRING* CONST Name = (CONST UNICODE_STRING*)NameBuf;
		if (Name->Buffer == NULL || Name->Length == 0)
			goto done;

		UINT32 Chars = Name->Length / (UINT32)sizeof(WCHAR);
		Rec->NameCharsAvail = (NXCMD_U16)((Chars > 0xFFFFu) ? 0xFFFFu : Chars);
		if (Chars > NXCMD_FCAP_NAME_CHARS)
			Chars = NXCMD_FCAP_NAME_CHARS;
		for (UINT32 i = 0; i < Chars; i++)
			Rec->Name[i] = (NXCMD_U16)Name->Buffer[i];
		Rec->NameChars = (NXCMD_U16)Chars;

		/*
		 * 2. USE THE DUPLICATED HANDLE. NOTHING IS REOPENED.
		 *
		 * ⚠ THE FIRST VERSION REOPENED BY PATH AND COULD NEVER HAVE WORKED. It resolved this exact
		 * name correctly and then got STATUS_OBJECT_NAME_NOT_FOUND, which reads like a lost race and
		 * is not one: class 64 is FileDispositionInformationEx with POSIX semantics, so the name is
		 * unlinked as the call completes while the data stays reachable through open handles. A
		 * faster worker would have failed identically. The handle the hook duplicated is immune by
		 * construction, and holding it also defers a classic class-13 delete.
		 *
		 * The name resolved above is still recorded -- it is what makes the record readable -- but
		 * nothing depends on it being openable any more.
		 */
		IO_STATUS_BLOCK Iosb;
		RtlZeroMemory(&Iosb, sizeof(Iosb));

		HANDLE File = (HANDLE)Job->DupHandle;   /* `Opened` is at function scope -- see the top */

		if (PathJob)
		{
			/*
			 * ⚠ SHARE EVERYTHING INCLUDING DELETE. The caller is opening this file RIGHT NOW with
			 *    FILE_DELETE_ON_CLOSE; a restrictive share mode here would make OUR open the thing
			 *    that fails, and we would have broken the operation we exist to observe.
			 * ⚠ FILE_OPEN, never FILE_OPEN_IF -- a capture that CREATES its subject is not a capture,
			 *    and with FILE_SUPERSEDE/OPEN_IF in play the caller may not have created it yet.
			 */
			OBJECT_ATTRIBUTES Oa;
			InitializeObjectAttributes(&Oa, (UNICODE_STRING*)NameBuf,
			                           OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

			CONST NTSTATUS OSt = ZwCreateFile(&Opened,
			                                  FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
			                                  &Oa, &Iosb, NULL, FILE_ATTRIBUTE_NORMAL,
			                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			                                  FILE_OPEN,
			                                  FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			                                  NULL, 0);
			if (!NT_SUCCESS(OSt))
			{
				/* ⚠ GONE is still possible here, for a different reason than on the handle path: the
				 * caller's create may have FAILED, so there is no file to read and never was. */
				Rec->Why = (OSt == STATUS_OBJECT_NAME_NOT_FOUND ||
				            OSt == STATUS_OBJECT_PATH_NOT_FOUND ||
				            OSt == STATUS_DELETE_PENDING)
				         ? NXC_FCAP_GONE : NXC_FCAP_OPEN_FAILED;
				Rec->NtStatus = (NXCMD_U64)(ULONG_PTR)OSt;
				if (Rec->Why == NXC_FCAP_GONE)
					InterlockedIncrement64(&gGone);
				goto done;
			}
			File = Opened;
		}

		if (File == NULL)
		{
			/* The duplication itself failed at the hook. Distinct from every read-time failure:
			 * nothing was ever attempted here. */
			Rec->Why      = NXC_FCAP_OPEN_FAILED;
			Rec->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_HANDLE;
			goto done;
		}

		/* 3. SIZE IT, and refuse rather than truncate silently. */
		FILE_STANDARD_INFORMATION Fsi;
		RtlZeroMemory(&Fsi, sizeof(Fsi));
		CONST NTSTATUS SSt = ZwQueryInformationFile(File, &Iosb, &Fsi, sizeof(Fsi),
		                                            FileStandardInformation);
		if (!NT_SUCCESS(SSt))
		{
			Rec->Why      = NXC_FCAP_OPEN_FAILED;
			Rec->NtStatus = (NXCMD_U64)(ULONG_PTR)SSt;
			goto done;
		}

		Rec->FileSize = (NXCMD_U64)Fsi.EndOfFile.QuadPart;

		if (Fsi.EndOfFile.QuadPart <= 0)
		{
			Rec->Why = NXC_FCAP_EMPTY;
			goto done;
		}
		if ((UINT64)Fsi.EndOfFile.QuadPart > NXCMD_FCAP_MAX_BYTES)
		{
			/* ⚠ REFUSED, NOT CLIPPED. A partial file recorded as a capture is a file nobody can
			 * tell is partial later; FileSize is reported so the operator knows exactly how far
			 * over the bound it was. */
			Rec->Why = NXC_FCAP_TOO_LARGE;
			goto done;
		}

		/* 4. RESERVE SPACE. The byte arena is a bump allocator: captures are never individually
		 *    freed, so there is nothing to fragment and nothing to double-free. */
		CONST UINT64 Want = (UINT64)Fsi.EndOfFile.QuadPart;
		CONST LONG64 Base = InterlockedExchangeAdd64(&gByteArenaUsed, (LONG64)Want);
		if ((UINT64)Base + Want > gByteArenaSize)
		{
			/* Put it back so a later, smaller capture can still fit. */
			InterlockedExchangeAdd64(&gByteArenaUsed, -(LONG64)Want);
			Rec->Why = NXC_FCAP_NO_ROOM;
			goto done;
		}

		/* 5. READ IT. NON-CACHED so what lands is what is on disk, not what the cache is holding --
		 *    v1 made the same choice for the same reason. */
		LARGE_INTEGER Offset;
		Offset.QuadPart = 0;
		RtlZeroMemory(&Iosb, sizeof(Iosb));
		CONST NTSTATUS RdSt = FcapReadAll(File, gByteArena + Base, (ULONG)Want, &Iosb);

		if (!NT_SUCCESS(RdSt))
		{
			InterlockedExchangeAdd64(&gByteArenaUsed, -(LONG64)Want);
			Rec->Why      = NXC_FCAP_READ_FAILED;
			Rec->NtStatus = (NXCMD_U64)(ULONG_PTR)RdSt;
			goto done;
		}

		/* ⚠ WHAT WAS ACTUALLY READ, NOT WHAT WAS ASKED FOR (D3). A short read is a real outcome and
		 * Information is the only field that reports it. */
		Rec->ByteOffset    = (NXCMD_U64)Base;
		Rec->BytesCaptured = (NXCMD_U64)Iosb.Information;
		Rec->Why           = (Iosb.Information == Want) ? NXC_FCAP_OK : NXC_FCAP_SHORT_READ;
		Rec->NtStatus      = 0;
		InterlockedIncrement64(&gCaptured);
	}

done:
	/*
	 * ⚠ ONE OWNER, ONE CLOSE, ON EVERY PATH. The duplicated handle belongs to the JOB, so it is
	 * released exactly here rather than at each of the five places that used to bail out. Those
	 * scattered closes became a double-close hazard the moment the handle stopped being opened
	 * locally, and a double close on a kernel handle is a bugcheck, not a leak.
	 *
	 * ⚠ AND CLOSING IT IS WHAT LETS A CLASSIC DELETE COMPLETE. For class 13 the unlink fires on the
	 * last handle close, and ours is deliberately one of them -- holding it forever would mean this
	 * capture silently prevented the deletion it was only supposed to observe.
	 */
	/* ⚠ BOTH OWNERS, EVERY PATH. A handle job carries DupHandle; a path job opened its own. Exactly
	 * one of these is non-NULL per job, and closing the wrong one only was the leak that kept a
	 * delete-on-close file alive forever. */
	if (Job->DupHandle != NULL)
		ZwClose((HANDLE)Job->DupHandle);
	if (Opened != NULL)
		ZwClose(Opened);
	/* ⚠ A PATH JOB HAS NO FileObject -- nothing was referenced, because nothing existed to
	 * reference. Dereferencing NULL here would bugcheck on the very path added to make the feature
	 * complete. */
	if (Job->FileObject != NULL)
		ObfDereferenceObject(Job->FileObject);
	*(volatile UINT64*)&Rec->Sequence = (UINT64)Ticket;
}

static void
FcapWorker(
	_In_ void* Context
	)
{
	UNREFERENCED_PARAMETER(Context);

	NxcLogExt("fcap: worker running\n");

	for (;;)
	{
		/*
		 * ⚠ A TIMEOUT, NOT AN INDEFINITE WAIT. An indefinite wait means a stop request that arrives
		 * while the queue is empty is never noticed -- the thread would sit in KeWaitForSingleObject
		 * forever and the image, which never unloads, would carry it for the life of the boot. One
		 * second is short enough to be responsive and long enough to cost nothing.
		 */
		LARGE_INTEGER Timeout;
		Timeout.QuadPart = -10000000LL;   /* 1 s, relative */
		(void)KeWaitForSingleObject(&gWakeEvent, Executive, KernelMode, FALSE, &Timeout);

		NXC_FCAP_PENDING Job;
		while (FcapDequeue(&Job))
			FcapCaptureOne(&Job);

		if (gWorkerStop != 0)
			break;
	}

	NxcLogExt("fcap: worker exiting\n");
}

/* ---------------------------------------------------------------------------------------------
 * Setup and reporting.
 * --------------------------------------------------------------------------------------------- */

NTSTATUS
NxcFileCaptureInit(
	_In_  UINT32  Slots,
	_In_  UINT32  ByteBudgetKb,
	_Out_ UINT32* OutSlots
	)
{
	*OutSlots = 0;

	if (gInitDone != 0)
	{
		*OutSlots = (UINT32)gRecordSlots;
		return STATUS_SUCCESS;   /* already armed; report rather than re-arm and strand the first */
	}

	if (Slots == 0 || Slots > 512)
		return STATUS_INVALID_PARAMETER;
	if (ByteBudgetKb == 0 || ByteBudgetKb > 8192)
		return STATUS_INVALID_PARAMETER;

	ULONG Extent = 0;
	void* CONST Recs = NxcArenaAlloc((ULONG)((SIZE_T)Slots * sizeof(NXCMD_FCAP_ENTRY)), &Extent);
	if (Recs == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	RtlZeroMemory(Recs, (SIZE_T)Slots * sizeof(NXCMD_FCAP_ENTRY));

	ULONG ByteExtent = 0;
	void* CONST Bytes = NxcArenaAlloc((ULONG)ByteBudgetKb * 1024u, &ByteExtent);
	if (Bytes == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	gByteArena     = (UINT8*)Bytes;
	gByteArenaSize = (UINT64)ByteBudgetKb * 1024ull;
	gByteArenaUsed = 0;
	gRecordSlots   = (LONG)Slots;

	KeInitializeSpinLock(&gQueueLock);
	KeInitializeEvent(&gWakeEvent, SynchronizationEvent, FALSE);

	/* ⚠ RECORDS PUBLISHED BEFORE THE THREAD EXISTS, AND gInitDone LAST. The producer tests
	 * gInitDone and the worker tests gRecords; setting the flag first would open a window where a
	 * delete is referenced and queued with nothing able to consume or release it. */
	InterlockedExchangePointer((void* volatile*)&gRecords, Recs);

	HANDLE ThreadHandle = NULL;
	OBJECT_ATTRIBUTES Oa;
	InitializeObjectAttributes(&Oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	CONST NTSTATUS TSt = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, &Oa,
	                                          NULL, NULL, FcapWorker, NULL);
	if (!NT_SUCCESS(TSt))
	{
		InterlockedExchangePointer((void* volatile*)&gRecords, NULL);
		NxcLogExt("fcap: PsCreateSystemThread failed 0x%08X -- nothing is armed\n", TSt);
		return TSt;
	}

	/* The handle is closed immediately; the THREAD keeps running. Nothing here ever joins it -- the
	 * image does not unload, so there is no teardown that would need to. */
	gWorkerThread = ThreadHandle;
	ZwClose(ThreadHandle);

	InterlockedExchange(&gInitDone, 1);

	*OutSlots = Slots;
	NxcLogExt("fcap: armed -- %u record slot(s), %u KB of byte budget\n", Slots, ByteBudgetKb);
	return STATUS_SUCCESS;
}

NTSTATUS
NxcFileCaptureRead(
	_Out_writes_(Cap) NXCMD_FCAP_ENTRY* Out,
	_In_  UINT32  Cap,
	_Out_ UINT32* OutGot,
	_Out_ UINT64* OutTotal
	)
{
	*OutGot   = 0;
	*OutTotal = (UINT64)gRecordNext;

	NXCMD_FCAP_ENTRY* CONST Records = gRecords;
	if (Records == NULL || gRecordSlots <= 0)
		return STATUS_INVALID_DEVICE_STATE;
	if (Cap == 0)
		return STATUS_BUFFER_TOO_SMALL;

	CONST UINT64 Total = (UINT64)gRecordNext;
	CONST UINT64 Held  = (Total < (UINT64)gRecordSlots) ? Total : (UINT64)gRecordSlots;
	CONST UINT64 Want  = (Held < (UINT64)Cap) ? Held : (UINT64)Cap;

	UINT32 Got = 0;
	for (UINT64 i = 0; i < Want; i++)
	{
		CONST UINT64 Seq = Total - i;
		CONST NXCMD_FCAP_ENTRY* CONST Src = &Records[(Seq - 1) % (UINT64)gRecordSlots];
		CONST UINT64 Have = *(volatile UINT64*)&Src->Sequence;
		if (Have == 0 || Have != Seq)
			continue;              /* being written right now, or wrapped past us mid-drain */
		Out[Got] = *Src;
		Got++;
	}

	*OutGot = Got;
	return STATUS_SUCCESS;
}

NTSTATUS
NxcFileCapturePull(
	_In_  UINT64  ByteOffset,
	_In_  UINT32  Bytes,
	_Out_writes_bytes_(Bytes) void* Out,
	_Out_ UINT32* OutCopied
	)
{
	*OutCopied = 0;

	if (gByteArena == NULL)
		return STATUS_INVALID_DEVICE_STATE;
	/* ⚠ BOUNDS CHECKED AGAINST WHAT HAS BEEN WRITTEN, not against the arena size -- reading past
	 * gByteArenaUsed would hand back uninitialised arena as if it were captured content. */
	if (ByteOffset >= (UINT64)gByteArenaUsed)
		return STATUS_INVALID_PARAMETER;

	CONST UINT64 Avail = (UINT64)gByteArenaUsed - ByteOffset;
	CONST UINT32 Take  = (Bytes < Avail) ? Bytes : (UINT32)Avail;

	RtlCopyMemory(Out, gByteArena + ByteOffset, Take);
	*OutCopied = Take;
	return STATUS_SUCCESS;
}

void
NxcFileCaptureStats(
	_Out_ NXCMD_FCAP_STATS* Out
	)
{
	Out->Armed        = (NXCMD_U32)gInitDone;
	Out->Slots        = (NXCMD_U32)gRecordSlots;
	Out->Queued       = (NXCMD_U64)gQueued;
	Out->QueueFull    = (NXCMD_U64)gQueueFull;
	Out->RefFailed    = (NXCMD_U64)gRefFailed;
	Out->Captured     = (NXCMD_U64)gCaptured;
	Out->Gone         = (NXCMD_U64)gGone;
	Out->Total        = (NXCMD_U64)gRecordNext;
	Out->BytesUsed    = (NXCMD_U64)gByteArenaUsed;
	Out->BytesBudget  = gByteArenaSize;
}
