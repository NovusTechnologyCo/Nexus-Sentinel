# Nexus Sentinel User Guide

Nexus Sentinel is a unified system introspection framework for Windows that combines memory scanning, debugging, structure analysis, and process monitoring into a single modern interface.

## Table of Contents

- [Quick Start](#quick-start)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Interface Overview](#interface-overview)
- [Memory Scanner](#memory-scanner)
- [Debugger](#debugger)
- [Structure Dissector](#structure-dissector)
- [Process Monitor](#process-monitor)
- [Plugins](#plugins)
- [Settings](#settings)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

1. **Launch** Nexus Sentinel (`Nexus.exe`)
2. **Attach** to a process: `File > Open Process` or press `Ctrl+O`
3. **Select a module** from the tab bar (Scanner, Debugger, Structures, ProcMon)
4. **Start analyzing** using the tools in each module

---

## System Requirements

| Requirement | Minimum |
|-------------|---------|
| OS | Windows 10/11 x64 |
| Runtime | .NET 10 |
| RAM | 4 GB |
| Disk | 100 MB |
| Privileges | Standard user (Admin for some features) |

**Note**: Some features require Administrator privileges:
- Attaching to protected processes
- Hardware breakpoints on system processes
- Kernel-mode monitoring (requires NexusKernel.sys driver)

---

## Installation

### Portable Installation

1. Extract `NexusSentinel.zip` to any folder
2. Run `Nexus.exe`

### Building from Source

```bash
# Clone the repository
git clone https://github.com/anthropics/nexus-sentinel.git
cd nexus-sentinel

# Build UI
dotnet build Nexus/UI/Nexus.UI.csproj -c Release

# Build Engine (requires CMake)
cd Nexus/Engine
cmake -B build -A x64
cmake --build build --config Release
```

---

## Interface Overview

Nexus Sentinel uses a tab-based interface with four main modules:

```
┌─────────────────────────────────────────────────────────────┐
│ File  View  Debug  Tools  Plugins  Settings  Help          │
├─────────────────────────────────────────────────────────────┤
│ [Scanner] [Debugger] [Structures] [ProcMon]    <- Tab Bar  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│                    Module Content Area                      │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ Ready | notepad.exe (PID: 1234) | User Mode | Administrator │
└─────────────────────────────────────────────────────────────┘
```

### Status Bar

- **Status**: Current operation status
- **Process**: Attached process name and PID
- **Provider**: Current privilege level (User Mode, Kernel, Hypervisor)
- **Elevation**: Administrator or User mode

### Common Operations

| Action | Menu | Shortcut |
|--------|------|----------|
| Open Process | File > Open Process | `Ctrl+O` |
| Detach | File > Detach | `Ctrl+D` |
| Memory Viewer | View > Memory Viewer | `Ctrl+M` |
| Process Inspector | View > Process Inspector | `Ctrl+I` |

---

## Memory Scanner

The Memory Scanner allows you to search for values in process memory and track changes.

### Scan Types

| Type | Description |
|------|-------------|
| Exact Value | Find addresses containing a specific value |
| Bigger Than | Find values greater than specified |
| Smaller Than | Find values less than specified |
| Between | Find values within a range |
| Unknown Initial | First scan when value is unknown |
| Increased | Values that increased since last scan |
| Decreased | Values that decreased since last scan |
| Changed | Values that changed |
| Unchanged | Values that stayed the same |

### Value Types

- **Integers**: Byte, 2 Bytes, 4 Bytes, 8 Bytes (signed/unsigned)
- **Floating Point**: Float, Double
- **Text**: String (ANSI), String (Unicode)
- **Binary**: Array of Bytes (AOB) with wildcard support

### Performing a Scan

1. **Enter Value**: Type the value to search for
2. **Select Type**: Choose value type (4 Bytes, Float, etc.)
3. **Select Scan Type**: Exact Value for first scan
4. **Click First Scan**: Results appear in the list
5. **Refine**: Change value in target, click Next Scan

### Array of Bytes (AOB) Scanning

AOB scans support wildcards using `?` or `??`:

```
48 8B 05 ?? ?? ?? ?? 48 85 C0
```

This matches any bytes at the wildcard positions.

### Pointer Scanning

To find stable pointers to a value:

1. Find the address using normal scanning
2. Right-click the address > **Pointer Scan**
3. Configure scan parameters:
   - Max offset: 0x1000 (typical)
   - Max depth: 5-7 levels
   - Only positive offsets: Usually enabled
4. Click **Start** and wait for completion
5. Results show pointer chains like: `game.exe+0x1234 -> +0x10 -> +0x8`

### Saved Addresses

- **Add**: Double-click a scan result or drag to saved list
- **Edit**: Double-click description or value
- **Freeze**: Check the box to lock value
- **Delete**: Right-click > Delete

---

## Debugger

The Debugger module provides x64dbg-style debugging with disassembly, registers, stack, and breakpoint management.

### Layout

```
┌─────────────────────────┬─────────────────────┐
│     Disassembly         │     Registers       │
│                         ├─────────────────────┤
│                         │     Arguments       │
├─────────────────────────┼─────────────────────┤
│     Hex Dump            │     Stack           │
├─────────────────────────┼─────────────────────┤
│     Breakpoints         │     Trace Log       │
└─────────────────────────┴─────────────────────┘
```

### Breakpoints

| Type | Description | Limit |
|------|-------------|-------|
| Software (INT3) | Standard breakpoint | Unlimited |
| Hardware (DR0-DR3) | Execute/Read/Write | 4 total |

**Setting Breakpoints:**
- Double-click address in disassembly
- Right-click > Toggle Breakpoint
- Press `F2` on selected address

**Hardware Breakpoints:**
- Right-click > Hardware Breakpoint > Execute/Read/Write
- Configure size: 1, 2, 4, or 8 bytes

### Stepping

| Action | Shortcut | Description |
|--------|----------|-------------|
| Step Into | `F7` | Execute one instruction, enter calls |
| Step Over | `F8` | Execute one instruction, skip calls |
| Step Out | `Ctrl+F9` | Run until return |
| Run | `F9` | Continue execution |
| Pause | `F12` | Break execution |

### Disassembly Features

- **Go to Address**: `Ctrl+G` or double-click address column
- **Follow in Dump**: Right-click > Follow in Dump
- **Copy**: `Ctrl+C` copies selected instructions
- **Assemble**: Right-click > Assemble to modify instructions
- **NOP**: Right-click > NOP to fill with NOPs

### Register Modification

- Double-click any register value to modify
- Right-click register > Copy/Zero/Increment/Decrement

### Trace Logging

1. Set start address or use current position
2. Configure max instructions (default: 10000)
3. Click **Start Trace**
4. Execution is logged until breakpoint or limit

---

## Structure Dissector

The Structure Dissector provides ReClass-style memory structure analysis and reverse engineering.

### Creating a Structure

1. Click **Add Class** or press `Ctrl+N`
2. Enter structure name (e.g., "Player")
3. Set base address (memory address to analyze)

### Field Types

| Category | Types |
|----------|-------|
| Integers | Int8, UInt8, Int16, UInt16, Int32, UInt32, Int64, UInt64 |
| Floating | Float, Double |
| Text | String, WString (Unicode) |
| Special | Bool, Pointer, GUID, Timestamp |
| Complex | Struct (nested), Array, Union, Bitfield, Enum |
| Layout | Padding, Bytes |

### Adding Fields

1. Select offset position in structure view
2. Right-click > Add Field > Select type
3. Or use toolbar buttons for common types

### Pointer Following

For pointer fields:
1. Add a Pointer field
2. Right-click > Set Nested Structure (for typed pointers)
3. Or right-click > Follow Pointer to navigate

**Multi-level Pointers:**
1. Right-click pointer > Set Pointer Chain
2. Enter offsets: `0x10, 0x20, 0x8`
3. Structure follows the chain automatically

### Auto-Dissect

The auto-dissect feature analyzes memory patterns:

1. Set base address
2. Click **Auto Dissect**
3. Engine detects likely field types based on patterns

### Arrays

1. Right-click field > Change to Array
2. Enter element count
3. Select base type for array elements

### Bitfields

For bit-packed structures:
1. Right-click field > Change to Bitfield
2. Enter bit offset (0-63)
3. Enter bit size (1-64)

### Enums

1. Right-click field > Change to Enum
2. Define enum name and values:
   ```
   0 = None
   1 = Walking
   2 = Running
   3 = Jumping
   ```

### Structure Library

Save and load structure definitions:

- **Save**: File > Save to Library
- **Load**: File > Load from Library
- **Manage**: File > Manage Library

Structures are saved to `%APPDATA%\NexusSentinel\structure_library.json`

### Advanced Analysis

| Feature | Description |
|---------|-------------|
| Compare Structures | Diff two structure definitions |
| Byte Map View | Visual color-coded byte layout |
| VTable Detection | Find and enumerate virtual functions |
| RTTI Parsing | Extract C++ type information |
| Scan for Strings | Find string references in structure |
| Scan for Pointers | Find pointer-like values |

---

## Process Monitor

The Process Monitor captures real-time events using two sources:
1. **ETW (Event Tracing for Windows)** - User-mode event tracing
2. **NexusKernel.sys** - Kernel-mode monitoring (more comprehensive, harder to evade)

### Event Categories

| Category | Events | Source |
|----------|--------|--------|
| Process | Create, Exit, Start | ETW |
| Thread | Create, Exit | ETW |
| Image | Load (DLL loading) | ETW |
| File | Create, Read, Write, Delete | ETW + Kernel Minifilter |
| Registry | Open, Query, Set, Delete | ETW + Kernel Callbacks |
| Network | Connect, Send, Receive | ETW |
| Handle | Process/Thread handle opens | Kernel Callbacks |
| Memory | Read/Write operations | Kernel Logging |

### Kernel vs ETW Monitoring

| Feature | ETW | Kernel Driver |
|---------|-----|---------------|
| Requires Admin | No | Yes |
| Detectable | Yes | Harder to detect |
| Bypassable | Can be bypassed | More resilient |
| File Operations | User-mode only | Kernel-level intercept |
| Registry | User-mode | Kernel callbacks |
| Handle Opens | Limited | Full access mask tracking |

### Loading the Kernel Driver

NexusKernel.sys supports two loading methods:

#### Method 1: Service Control (Standard)

1. **Install the driver** (requires Administrator):
   ```cmd
   sc create NexusKernel type=kernel binPath="C:\path\to\NexusKernel.sys"
   ```

2. **Set minifilter registry entries** (required for file monitoring):
   ```cmd
   reg add "HKLM\SYSTEM\CurrentControlSet\Services\NexusKernel\Instances" /v DefaultInstance /t REG_SZ /d "NexusKernel Instance"
   reg add "HKLM\SYSTEM\CurrentControlSet\Services\NexusKernel\Instances\NexusKernel Instance" /v Altitude /t REG_SZ /d 385100
   reg add "HKLM\SYSTEM\CurrentControlSet\Services\NexusKernel\Instances\NexusKernel Instance" /v Flags /t REG_DWORD /d 0
   ```

3. **Start the driver**:
   ```cmd
   sc start NexusKernel
   ```

4. **Verify minifilter is active**:
   ```cmd
   fltmc filters
   ```
   Look for `NexusKernel` at altitude `385100`.

#### Method 2: Manual Mapping (Stealth)

For scenarios requiring stealth operation (the driver won't appear in loaded module lists):

1. **Boot with NexusBoot** - The UEFI bootkit provides manual driver mapping
2. **Open Bootkit Control** - `Tools > Bootkit Control`
3. **Map the Driver** - Click "Map NexusKernel.sys"
4. **Establish Communication** - Click "Map Comm Channel" to enable shared memory

When manually mapped:
- Driver is invisible to `PsLoadedModuleList`
- No device object created (no `\\.\NexusKernel`)
- Communication uses shared memory ring buffers instead of IOCTL
- Provider automatically detects and uses the appropriate mode

**Auto-Detection**: The driver detects its load method at initialization:
- `DriverObject != NULL` → Standard IOCTL communication
- `DriverObject == NULL` → Shared memory communication

### Filtering

1. **Text Filter**: Type in search box to filter by any column
2. **Category Filter**: Check/uncheck event types in toolbar
3. **Process Filter**: Right-click > Filter by This Process

### Capture Controls

- **Start**: Begin capturing events
- **Stop**: Pause capture
- **Clear**: Remove all events
- **Auto-scroll**: Keep newest events visible

### Event Details

Click any event to see details:
- Timestamp
- Process/Thread ID
- Event-specific data (path, key, address, etc.)

---

## Plugins

Nexus Sentinel supports plugins for extending functionality.

### Managing Plugins

1. Go to `Plugins > Manage Plugins`
2. View installed plugins, their status, and trust level

### Plugin Installation

1. Place plugin DLL in `plugins/` folder
2. Restart Nexus Sentinel
3. Approve unsigned plugins when prompted

### Trust Levels

| Level | Description |
|-------|-------------|
| Trusted | Signed by Nexus Sentinel |
| User Approved | Manually approved unsigned plugin |
| Requires Approval | New unsigned plugin |
| Blocked | Explicitly blocked by user |

### Plugin Approval

For unsigned plugins:
1. Review the plugin details (file name, hash)
2. Click **Approve** to allow loading
3. Or **Block** to prevent loading
4. Choice is remembered for future sessions

See [Plugin Development Guide](PLUGIN_DEVELOPMENT.md) for creating plugins.

---

## Settings

Access settings via `Settings > Preferences`.

### General

- **Theme**: Dark (default) or Light mode
- **Auto-attach**: Automatically attach to specified processes
- **Save layout**: Remember window positions

### Scan Settings

- **Memory regions**: Include/exclude specific protection types
- **Fast scan**: Align to 4-byte boundaries
- **Max results**: Limit result count

### Debugger Settings

- **Break on entry**: Pause at entry point
- **Skip system breakpoints**: Ignore loader breakpoints
- **Symbol servers**: Configure PDB download sources

### Hotkeys

Customize keyboard shortcuts for all actions.

---

## Keyboard Shortcuts

### Global

| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Open Process |
| `Ctrl+D` | Detach |
| `Ctrl+M` | Memory Viewer |
| `Ctrl+I` | Process Inspector |
| `Ctrl+S` | Save |
| `F1` | Help |

### Scanner

| Shortcut | Action |
|----------|--------|
| `Enter` | First Scan / Next Scan |
| `Ctrl+N` | New Scan |
| `Delete` | Remove selected result |

### Debugger

| Shortcut | Action |
|----------|--------|
| `F2` | Toggle Breakpoint |
| `F7` | Step Into |
| `F8` | Step Over |
| `F9` | Run |
| `F12` | Pause |
| `Ctrl+F9` | Step Out |
| `Ctrl+G` | Go to Address |

### Structure Dissector

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | New Structure |
| `Delete` | Delete Field |
| `Ctrl+C` | Copy Field |
| `Ctrl+V` | Paste Field |

---

## Troubleshooting

### Cannot Attach to Process

**Symptoms**: "Access Denied" or attachment fails

**Solutions**:
1. Run Nexus Sentinel as Administrator
2. Check if process is protected (anti-cheat, system process)
3. Disable other debugging tools that may have attached

### Scan Returns No Results

**Symptoms**: First scan finds nothing

**Solutions**:
1. Verify value type matches (4 Bytes vs Float)
2. Check if value is in excluded memory regions
3. Try "Unknown Initial Value" scan first
4. Disable "Fast scan" for unaligned values

### Debugger Won't Break

**Symptoms**: Breakpoints don't trigger

**Solutions**:
1. Verify breakpoint is set (red dot visible)
2. Check if code actually executes
3. Try hardware breakpoint instead
4. Some code may be in excluded regions

### Plugin Won't Load

**Symptoms**: Plugin appears but shows error

**Solutions**:
1. Check plugin targets correct .NET version
2. Verify all dependencies are present
3. Check for load error in Plugin Manager
4. Review plugin trust settings

### High Memory Usage

**Symptoms**: Nexus uses excessive RAM

**Solutions**:
1. Limit scan result count in settings
2. Clear old scan results
3. Reduce pointer scan depth
4. Close unused panels

---

## Getting Help

- **Documentation**: You're reading it!
- **Issues**: [GitHub Issues](https://github.com/anthropics/nexus-sentinel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/anthropics/nexus-sentinel/discussions)
- **Website**: https://nexus-sentinel.org
