# Changelog

All notable changes to this project are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.9-beta] - 2026-01-27

First public release.

### Added
- Memory inspection and debugging tooling, with a Windows Forms interface.
- A UEFI bootkit stage, and the kernel driver it loads.

### Notes
- Licensed AGPL-3.0. This release contained code derived from
  [EfiGuard](https://github.com/Mattiwatti/EfiGuard) (GPL-3.0) and did not credit
  it; its third-party licence file listed Zydis, Zycore, EDK2, Roslyn and the
  .NET runtime but omitted EfiGuard. The omission was an oversight, and the
  correction is published on the release page and in `Nexus/UEFI/NOTICE`. The
  binary attached to this release has been withdrawn from distribution.

## [0.28.0] - 2026-01-04

### Added
- **Pointer Scanner Tuning** - Matched CE's result count (~3,127 vs CE's ~3,137)
  - Tuned `MAX_VISITS_PER_ADDRESS` to 4 (matches CE behavior)
  - Made parameters configurable: `maxVisitsPerAddress`, `threadStackCount`, `stackSize`
  - Changed offset storage order to match CE (base-to-target instead of target-to-base)
- **SQLite Export/Import** - CE-compatible format
  - Added `Microsoft.Data.Sqlite` package
  - `ExportToSqlite()` with CE schema (pointerfiles, modules, results tables)
  - `ImportFromSqlite()` to load CE exports
  - `CompareSqliteFiles()` tool for side-by-side comparison

### Fixed
- Pointer scanner progress bar bug (was showing 139%+)

---

## [0.27.0] - 2025-12-31

### Added
- **LastDigits scan mode**: Filter scan results by address hex suffix pattern
  - `NEXUS_SCAN_FLAG_LAST_DIGITS` (basic scanner)
  - `NEXUS_SCANOPT_LAST_DIGITS` (advanced scanner)
  - UI: rbAligned/rbLastDigits radio buttons wired to engine
- UI 1.0 form review complete - all 61 remaining forms reviewed and polished

### Changed
- Standardized button heights to 32px across all forms
- Fixed Close button handlers (DialogResult + explicit Close())
- Improved control spacing and form widths
- Disabled dev auto-attach (DEV_AUTO_ATTACH = null)
- Removed Form Reviewer from Help menu (debug tool, code kept)

### Fixed
- TracerConfigForm layout issues
- TracerForm control overlapping
- ValueHistoryForm sizing and button handlers
- WatchListAddEntryForm radio button spacing
- MainForm orphaned controls (chkActiveMemory removed, rbAligned/rbLastDigits wired)

---

## [0.26.1] - 2025-12-30

### Removed
- FloatingPointPanelForm (x64dbg will handle register views)
- NetworkConfigForm, NetworkDataCompressionForm, PointerRescanConnectForm, PointerScanConnectDialogForm, SetupPSNNodeForm (DMA/network out of scope)
- ExeTrainerGeneratorForm, TrainerGeneratorForm (trainers obsolete in 2025)
- LuaConsoleForm, LuaEngineForm, LuaScriptEditorForm, LuaScriptQuestionForm (replaced by future Roslyn scripting)
- Nexus/Native/TCC/ folder (LGPL incompatible with closed source)
- Nexus/Native/Lua/ folder (replaced by future Roslyn scripting)
- CommentForm (unused - use inline editing or InputBoxForm)
- ChangeDescriptionForm (replaced by InputBoxForm.Show)

**Tier 1 Orphan Cleanup (19 forms):**
- APIHookTemplateSettingsForm (API hooking not implemented)
- BranchMapperForm (complex visualization not implemented)
- CapturedTimersForm (speedhack sub-form, SpeedhackForm handles this)
- CR3SwitcherForm (kernel CR3 manipulation)
- D3DHookConfigForm (DirectX overlay - cheat devs do this)
- D3DHookSnapshotConfigForm (DirectX overlay)
- D3DTrainerOptionsForm (DirectX overlay)
- DBVMLoadManualForm (DBVM not implemented)
- DbvmWatchConfigForm (DBVM not implemented)
- FormDesignerForm (CE internal tool)
- GameInfoForm (CE game info, not implemented)
- GDTIDTViewerForm (kernel internals - study from original CE)
- IPTLogDisplayForm (Intel PT not implemented)
- PagingViewerForm (kernel internals)
- SDTViewerForm (kernel internals)
- SetCrosshairForm (game overlay - cheat devs do this)
- SnapshotHandlerForm (D3D snapshot feature)
- Ultimap2Form (Intel PT not implemented)
- UltimapForm (Intel PT not implemented)

**Tier 2 Cleanup (7 forms):**
- AccessedMemoryForm (working set monitor, complex/incomplete)
- CalculatorForm (use Windows Calculator)
- DriverListForm (future kernel work)
- DriverLoadedForm (future kernel work)
- EditHistoryForm (undo system not implemented)
- ProcessPluginsForm (plugin system not implemented)
- SyntaxHighlighterEditorForm (settings overkill)

**Tier 3 Orphan Cleanup (35 forms):**
- GroupScanAlgorithmForm (complex scan algorithm UI, not implemented)
- ListViewItemEditorForm (generic editor, unused)
- MemoryAllocHandlerForm (allocation tracking, not implemented)
- MemoryPatchForm (patch management, unused)
- MemoryProtectionForm (protection change UI, unused)
- MemoryRecordDropdownForm (dropdown config, unused)
- MemorySearchOptionsForm (search options, integrated elsewhere)
- MemViewPreferencesForm (memory view settings, unused)
- MemViewPreferencesFullForm (memory view settings, unused)
- MemoryViewExForm (extended memory view, unused)
- OpenFileAsProcessForm (file-as-process, not implemented)
- PasteTableEntryForm (table paste UI, unused)
- PEInfoForm (PE viewer, use external tools)
- PointerMapForm (pointer map visualization, not implemented)
- ProcessWatcherExtraForm (process watcher settings, unused)
- ReferencedFunctionsForm (function refs, not implemented)
- ReferencedStringsForm (string refs, not implemented)
- RegistersForm (register view, x64dbg handles this)
- ResumePointerScanForm (pointer scan resume, unused)
- SaveDisassemblyForm (disasm export, unused)
- SaveMemoryRegionForm (memory export, unused)
- SaveSnapshotsForm (snapshot save UI, unused)
- ScriptVariablesForm (script vars, Lua removed)
- SourceDisplayForm (source view, not implemented)
- StackTraceForm (stack trace, x64dbg handles this)
- StackViewerForm (stack view, x64dbg handles this)
- StructuresConfigForm (structure settings, unused)
- StructuresElementInfoForm (element info, unused)
- StructuresNewStructureForm (new structure, unused)
- SymbolConfigForm (symbol settings, unused)
- SymbolHandlerConfigForm (symbol handler settings, unused)
- TableExtraInfoForm (table extra info, unused)
- TypePopupForm (type selection popup, unused)
- ValueChangeForm (duplicate of ChangeValueForm)
- ValueTypeSelectorForm (type selector, unused)

**Form count: 166 → 95 (71 forms removed total)**

**Tier 4 Orphan Cleanup (34 forms):**
- AAEditPrefsForm (auto-assembler prefs, unused)
- AddressRangeForm (address range input, unused)
- AdvancedOptionsForm (code list/pause, not wired to menu)
- AssemblerErrorsForm (assembler errors, unused)
- AssemblyScanForm (assembly scan, not wired)
- AutoInjectScriptForm (auto-inject script, unused)
- BreakAndTraceForm (break and trace, not wired)
- ChangeOffsetForm (offset change, unused)
- CodeCaveFinderForm (code cave finder, not wired)
- CodeInjectionTemplatesForm (injection templates, unused)
- ConditionEditorForm (condition editor, unused)
- DebugEventsForm (debug events, not wired)
- DebuggerOptionsForm (debugger options, not wired)
- DebugStringsForm (debug strings, not wired)
- DebugSymbolStructureListForm (symbol structures, unused)
- DisassemblerOptionsForm (disassembler options, not wired)
- DisassemblyScanForm (disassembly scan, not wired)
- DisassemblySearchForm (disassembly search, unused)
- DissectCodeForm (code dissection, not wired)
- DissectWindowForm (window dissection, unused)
- DotNetObjectListForm (.NET objects, unused)
- DropdownSettingsForm (dropdown settings, unused)
- ExceptionRegionListForm (exception regions, unused)
- FilePatcherForm (file patcher, not wired)
- FoundCodeDialogForm (found code dialog, unused)
- InjectDllForm (DLL injection, not wired to menu)
- MemoryBrowserForm (memory browser, unused)
- MemRecComboboxForm (memory record combo, unused)
- ModifyRegistersForm (register modification, not wired)
- ProcessWatcherForm (process watcher, not wired)
- StringPointerScanForm (string pointer scan, not wired)
- StructureLinkerForm (structure linker, not wired)
- ThreadListDetailForm (thread details, not wired)
- WatchlistForm (watchlist, not wired)

**Form count: 95 → 61 (105 forms removed total, 63% reduction)**

### Changed
- Reorganized migration plan with Quick Start section at top
- Added Last Session section for conversation continuity
- Added Section Index for AI navigation

### Added
- Release Protection Strategies section (VMProtect, .NET obfuscation)
- Third-Party Dependency Audit section
- Scripting Strategy (Post-Lua) section
- Deleted Components Log

---

## [0.26.0] - 2025-12-25

### Added
- Kernel driver abstraction layer
- Transport layer with user-mode/kernel/hypervisor support
- Capability detection and graceful degradation
- Physical memory read/write API (requires driver)
- Virtual to physical translation API
- Object hiding API framework
- Anti-debug API framework
- 27 engine tests passing

---

## [0.25.0] - 2025-12-25

### Added
- Advanced memory scanner (multi-threaded)
- All value types: byte, word, dword, qword, float, double, string, AOB
- All comparison types: exact, range, increased, decreased, changed, unchanged
- Undo scan support
- Progress callbacks for UI integration
- 26 engine tests passing

---

## [0.24.0] - 2025-12-25

### Added
- Symbol handler (DbgHelp integration)
- PDB and export symbol resolution
- Microsoft symbol server support
- C++ name undecorating
- Line number support
- 25 engine tests passing

---

## [0.23.0] - 2025-12-25

### Added
- Disassembler (Zydis integration)
- x86/x64 support including AVX-512
- Intel and AT&T syntax modes
- Branch target detection
- RIP-relative address resolution
- 24 engine tests passing

---

## [0.22.0] - 2025-12-25

### Added
- AA script parsing
- Section extraction and validation
- CT import/export support
- Phase 4 backend feature parity COMPLETE

---

## [0.21.0] - 2025-12-25

### Added
- Structure dissection (.nxs format)
- Element type management
- CE structure import/export

---

## [0.20.0] - 2025-12-25

### Added
- Trainer generation (.nxt project format)
- C source code output
- Hotkey support

### Removed (2025-12-30)
- Feature removed as trainers are obsolete

---

## [0.19.0] - 2025-12-25

### Added
- Address file format (.nsa)
- Module-relative addressing
- CEA import/export

---

## [0.18.0] - 2025-12-25

### Added
- Lua engine integration
- Dynamic lua54.dll loading
- CE-compatible Lua functions

### Removed (2025-12-30)
- Feature removed, replaced by future Roslyn C# scripting

---

## [0.17.0] - 2025-12-25

### Added
- Trace logger
- Instruction tracing with ring buffer
- Export to TXT/CSV/JSON

---

## [0.16.0] - 2025-12-25

### Added
- Stack walker (DbgHelp-based)
- Symbol resolution for stack frames

---

## [0.15.0] - 2025-12-25

### Added
- Signature scanner
- Pattern matching with wildcards
- Module-scoped scans

---

## [0.14.0] - 2025-12-25

### Added
- Auto-assembler
- x64/x86 instruction encoding
- Label and symbol resolution

---

## [0.13.0] - 2025-12-25

### Added
- Speedhack
- Timing function hooks
- Shared memory + QPC shellcode injection

---

## [0.12.0] - 2025-12-25

### Added
- Cheat table format (.nst)
- Memory records, scripts, groups
- .ns file format naming convention

---

## [0.11.0] - 2025-12-25

### Added
- Code injection (shellcode)
- DLL injection (LoadLibrary, manual map)
- Remote function call

---

## [0.10.0] - 2025-12-25

### Added
- Pointer scanner
- Reverse pointer map algorithm
- Async scanning
- Save/load pointer scan results (.nxps)

---

## [0.9.0] - 2025-12-25

### Added
- Debugger
- Software and hardware breakpoints
- Single-step execution
- Debug event handling

---

## [0.8.0] - 2025-12-25

### Added
- Handle enumeration (NtQuerySystemInformation)
- PE parsing (exports, imports, sections)

---

## [0.7.0] - 2025-12-25

### Added
- Thread enumeration and control
- Memory allocation API
- Memory protection API
- Register read/write via thread context

---

## [0.6.0] - 2025-12-25

### Added
- Project format (.nxp JSON files)
- Address list management
- Pointer chain support
- Value refresh

---

## [0.5.0] - 2025-12-25

### Added
- Scanner core (all numeric types)
- String scan (ANSI/Unicode with case sensitivity)
- AOB scan with wildcard support

---

## [0.4.0] - 2025-12-25

### Added
- Memory allocation
- Memory protection changes

---

## [0.3.0] - 2025-12-25

### Added
- Memory snapshots (CaptureMemoryMap)
- Region filtering

---

## [0.2.0] - 2025-12-25

### Added
- Pointer resolution
- ResolvePointer, ResolvePointerAndRead
- ResolvePointerBatch

---

## [0.1.0] - 2025-12-25

### Added
- Core primitives
- Process enumeration and attach
- Memory read/write
- Module enumeration

---

## UI Milestones

### Phase 5 Complete - 2025-12-27
- 181 form files ported from CE Pascal to C# WinForms
- All essential CE forms implemented
- Zero warnings, zero errors build

### Phase 5 Started - 2025-12-25
- Created Nexus.UI WinForms project (.NET 8)
- P/Invoke bindings to engine.dll
- MainForm with scan controls and address list

---

## Plan Document Versions

The migration plan document (Nexus_Sentinel_Migration_Plan.md) tracks its own version separately:
- Current: v3.82 (2025-12-30)
- See `## Revision History` section in the plan for detailed plan changes

