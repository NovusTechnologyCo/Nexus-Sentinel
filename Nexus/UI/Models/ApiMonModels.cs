// <file>
// <summary>
// Data model classes for the API Monitor subsystem. Includes API function definitions
// (parsed from XML), parameter definitions, module groupings for the tree view,
// captured API call events with parameters and return values, and selection profiles
// for saving/loading API monitoring configurations.
// </summary>
// </file>

namespace Nexus.UI.Models;

/// <summary>
/// Defines an API function from the XML definition files.
/// </summary>
public class ApiDefinition
{
    public string Module { get; set; } = "";
    public string Category { get; set; } = "";
    public string Name { get; set; } = "";
    public string ReturnType { get; set; } = "void";
    public string CallingConvention { get; set; } = "STDCALL";
    public List<ApiParamDef> Parameters { get; set; } = [];
    public string? SuccessCondition { get; set; }
    public string? SuccessValue { get; set; }
    public int Ordinal { get; set; }

    /// <summary>
    /// Unique key for this API: "Module!FunctionName"
    /// </summary>
    public string Key => $"{Module}!{Name}";

    public override string ToString() => $"{Module}!{Name}";
}

/// <summary>
/// Defines a parameter of an API function.
/// </summary>
public class ApiParamDef
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public bool IsOutput { get; set; }
    public bool IsOptional { get; set; }
    public string? Length { get; set; }
    public string? PostLength { get; set; }
    public string? InterfaceId { get; set; }
    public int? DerefCount { get; set; }

    public string DirectionString => IsOutput ? "OUT" : "IN";

    public override string ToString() => $"{Type} {Name}";
}

/// <summary>
/// Represents a captured API call event.
/// </summary>
public class ApiCallEvent
{
    private static int _sequenceCounter;

    public int SequenceNumber { get; } = Interlocked.Increment(ref _sequenceCounter);
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public int ProcessId { get; set; }
    public int ThreadId { get; set; }
    public string ProcessDisplayName { get; set; } = "";
    public string Module { get; set; } = "";
    public string Function { get; set; } = "";
    public string Category { get; set; } = "";
    public List<ApiParameter> Parameters { get; set; } = [];
    public string ReturnValue { get; set; } = "";
    public bool Success { get; set; }
    public TimeSpan Duration { get; set; }
    public List<CallStackFrame> CallStack { get; set; } = [];
    public byte[]? Buffer { get; set; }

    /// <summary>
    /// Summary string of parameters for the capture list view.
    /// </summary>
    public string ParameterSummary
    {
        get
        {
            if (Parameters.Count == 0) return "";
            return string.Join(", ", Parameters.Select(p =>
                $"{p.Name} = {p.Value}"));
        }
    }

    public static void ResetSequence() => Interlocked.Exchange(ref _sequenceCounter, 0);
}

/// <summary>
/// A decoded parameter value from a captured API call.
/// </summary>
public class ApiParameter
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string Value { get; set; } = "";
    public string RawValue { get; set; } = "";
    public byte[]? BufferData { get; set; }
    public bool IsOutput { get; set; }

    public string DirectionString => IsOutput ? "OUT" : "IN";
}

/// <summary>
/// A single frame in a call stack.
/// </summary>
public class CallStackFrame
{
    public int Index { get; set; }
    public ulong Address { get; set; }
    public string Module { get; set; } = "";
    public string Function { get; set; } = "";
    public int Offset { get; set; }

    public string AddressString => $"0x{Address:X}";
    public string FunctionDisplay => Offset > 0 ? $"{Function}+0x{Offset:X}" : Function;
}

/// <summary>
/// Groups API definitions by DLL module for the tree view.
/// </summary>
public class ApiModuleGroup
{
    public string ModuleName { get; set; } = "";
    public string CallingConvention { get; set; } = "STDCALL";
    public string? ErrorFunc { get; set; }
    public List<ApiCategoryGroup> Categories { get; set; } = [];
    public int TotalApiCount => Categories.Sum(c => c.TotalApiCount);

    public override string ToString() => $"{ModuleName} ({TotalApiCount} APIs)";
}

/// <summary>
/// Groups API definitions by category within a module.
/// Categories can be nested (e.g., "System Services/Processes and Threads/Process").
/// </summary>
public class ApiCategoryGroup
{
    public string Name { get; set; } = "";
    public string FullPath { get; set; } = "";
    public List<ApiCategoryGroup> SubCategories { get; set; } = [];
    public List<ApiDefinition> Apis { get; set; } = [];
    public int TotalApiCount => Apis.Count + SubCategories.Sum(c => c.TotalApiCount);

    public override string ToString() => $"{Name} ({TotalApiCount})";
}

/// <summary>
/// Profile of selected APIs for monitoring. Serialized to/from JSON.
/// </summary>
public class ApiMonitorProfile
{
    public string Name { get; set; } = "Default";
    public DateTime Created { get; set; } = DateTime.Now;
    public List<string> SelectedApis { get; set; } = [];
}
