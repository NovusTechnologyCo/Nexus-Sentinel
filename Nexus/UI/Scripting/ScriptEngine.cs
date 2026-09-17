// <file>
// <summary>
// C# script execution engine powered by Roslyn. Compiles user-written C# scripts at
// runtime, executes them in isolated AssemblyLoadContexts, and provides access to the
// Nexus Engine API for memory reading/writing, process operations, and debugging.
// Scripts run with a timeout and cancellation support. Compilation errors are reported
// with line/column information for the script editor.
// </summary>
// </file>

using System.Reflection;
using System.Runtime.Loader;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;
using Nexus.UI.Interop;

namespace Nexus.UI.Scripting;

/// <summary>
/// Script execution result code.
/// </summary>
public enum ScriptResult
{
    Success = 0,
    CompilationError = 1,
    RuntimeError = 2,
    Timeout = 3,
    Cancelled = 4
}

/// <summary>
/// Information about a compilation error.
/// </summary>
public class ScriptError
{
    public int Line { get; init; }
    public int Column { get; init; }
    public string Id { get; init; } = "";
    public string Message { get; init; } = "";
    public DiagnosticSeverity Severity { get; init; }

    public override string ToString() =>
        $"({Line},{Column}): {Severity} {Id}: {Message}";
}

/// <summary>
/// Script execution context providing access to memory operations.
/// </summary>
public class ScriptContext
{
    private readonly IntPtr _processHandle;
    private readonly int _processId;

    public IntPtr ProcessHandle => _processHandle;
    public int ProcessId => _processId;

    public ScriptContext(IntPtr processHandle, int processId)
    {
        _processHandle = processHandle;
        _processId = processId;
    }

    // Memory read operations
    public byte ReadByte(ulong address) => NexusEngine.ReadByte(_processHandle, address);
    public short ReadInt16(ulong address) => NexusEngine.ReadInt16(_processHandle, address);
    public int ReadInt32(ulong address) => NexusEngine.ReadInt32(_processHandle, address);
    public long ReadInt64(ulong address) => NexusEngine.ReadInt64(_processHandle, address);
    public float ReadFloat(ulong address) => NexusEngine.ReadFloat(_processHandle, address);
    public double ReadDouble(ulong address) => NexusEngine.ReadDouble(_processHandle, address);
    public string ReadString(ulong address, int maxLength = 256) => NexusEngine.ReadString(_processHandle, address, maxLength);
    public byte[] ReadBytes(ulong address, int count) => NexusEngine.ReadBytes(_processHandle, address, count);

    // Memory write operations
    public bool WriteByte(ulong address, byte value) => NexusEngine.WriteByte(_processHandle, address, value);
    public bool WriteInt16(ulong address, short value) => NexusEngine.WriteInt16(_processHandle, address, value);
    public bool WriteInt32(ulong address, int value) => NexusEngine.WriteInt32(_processHandle, address, value);
    public bool WriteInt64(ulong address, long value) => NexusEngine.WriteInt64(_processHandle, address, value);
    public bool WriteFloat(ulong address, float value) => NexusEngine.WriteFloat(_processHandle, address, value);
    public bool WriteDouble(ulong address, double value) => NexusEngine.WriteDouble(_processHandle, address, value);
    public bool WriteBytes(ulong address, byte[] data) => NexusEngine.WriteBytes(_processHandle, address, data);

    // Utility methods
    public void Print(string message) => Console.WriteLine(message);
    public void Sleep(int milliseconds) => Thread.Sleep(milliseconds);
}

/// <summary>
/// C# scripting engine using Roslyn for compilation.
/// </summary>
public class ScriptEngine : IDisposable
{
    private readonly List<ScriptError> _errors = new();
    private readonly List<MetadataReference> _references;
    private AssemblyLoadContext? _loadContext;
    private bool _disposed;

    public IReadOnlyList<ScriptError> Errors => _errors;
    public Action<string>? OutputCallback { get; set; }
    public Action<Exception>? ErrorCallback { get; set; }

    public ScriptEngine()
    {
        // Set up default references
        _references = new List<MetadataReference>
        {
            MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Console).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Enumerable).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(ScriptContext).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("System.Runtime").Location),
            MetadataReference.CreateFromFile(Assembly.Load("System.Collections").Location),
            MetadataReference.CreateFromFile(Assembly.Load("System.Linq").Location),
        };

        // Add reference to netstandard
        var netstandard = Assembly.Load("netstandard");
        _references.Add(MetadataReference.CreateFromFile(netstandard.Location));
    }

    /// <summary>
    /// Compile and execute a C# script.
    /// </summary>
    public ScriptResult Execute(string code, ScriptContext context, CancellationToken cancellationToken = default)
    {
        _errors.Clear();

        // Wrap user code in a class with Main method
        var wrappedCode = WrapScript(code);

        // Parse the code
        var syntaxTree = CSharpSyntaxTree.ParseText(wrappedCode);

        // Create compilation
        var compilation = CSharpCompilation.Create(
            $"Script_{Guid.NewGuid():N}",
            new[] { syntaxTree },
            _references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)
                .WithOptimizationLevel(OptimizationLevel.Release)
                .WithPlatform(Platform.X64));

        // Emit to memory stream
        using var ms = new MemoryStream();
        EmitResult result = compilation.Emit(ms);

        if (!result.Success)
        {
            foreach (var diagnostic in result.Diagnostics.Where(d =>
                d.Severity == DiagnosticSeverity.Error || d.Severity == DiagnosticSeverity.Warning))
            {
                var lineSpan = diagnostic.Location.GetLineSpan();
                _errors.Add(new ScriptError
                {
                    Line = lineSpan.StartLinePosition.Line - GetWrapperLineOffset() + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    Id = diagnostic.Id,
                    Message = diagnostic.GetMessage(),
                    Severity = diagnostic.Severity
                });
            }
            return ScriptResult.CompilationError;
        }

        // Load and execute the assembly
        ms.Seek(0, SeekOrigin.Begin);

        try
        {
            // Create isolated load context
            _loadContext = new AssemblyLoadContext($"ScriptContext_{Guid.NewGuid():N}", isCollectible: true);
            var assembly = _loadContext.LoadFromStream(ms);

            // Find and invoke the entry point
            var scriptType = assembly.GetType("NexusScript.Script");
            if (scriptType == null)
            {
                _errors.Add(new ScriptError { Message = "Could not find Script class", Severity = DiagnosticSeverity.Error });
                return ScriptResult.RuntimeError;
            }

            var runMethod = scriptType.GetMethod("Run", BindingFlags.Public | BindingFlags.Static);
            if (runMethod == null)
            {
                _errors.Add(new ScriptError { Message = "Could not find Run method", Severity = DiagnosticSeverity.Error });
                return ScriptResult.RuntimeError;
            }

            // Redirect console output - save and restore original to avoid
            // polluting global state for the entire AppDomain
            var originalOut = Console.Out;
            using var stringWriter = new StringWriter();

            try
            {
                Console.SetOut(stringWriter);

                // Execute with cancellation support
                var task = Task.Run(() => runMethod.Invoke(null, new object[] { context }), cancellationToken);

                if (task.Wait(TimeSpan.FromSeconds(30), cancellationToken))
                {
                    var output = stringWriter.ToString();
                    if (!string.IsNullOrEmpty(output))
                    {
                        OutputCallback?.Invoke(output);
                    }
                    return ScriptResult.Success;
                }
                else
                {
                    return ScriptResult.Timeout;
                }
            }
            finally
            {
                Console.SetOut(originalOut);
            }
        }
        catch (OperationCanceledException)
        {
            return ScriptResult.Cancelled;
        }
        catch (TargetInvocationException ex)
        {
            var innerEx = ex.InnerException ?? ex;
            _errors.Add(new ScriptError
            {
                Message = $"Runtime error: {innerEx.Message}",
                Severity = DiagnosticSeverity.Error
            });
            ErrorCallback?.Invoke(innerEx);
            return ScriptResult.RuntimeError;
        }
        catch (Exception ex)
        {
            _errors.Add(new ScriptError
            {
                Message = $"Execution error: {ex.Message}",
                Severity = DiagnosticSeverity.Error
            });
            ErrorCallback?.Invoke(ex);
            return ScriptResult.RuntimeError;
        }
    }

    /// <summary>
    /// Validate script without executing.
    /// </summary>
    public bool Validate(string code)
    {
        _errors.Clear();

        var wrappedCode = WrapScript(code);
        var syntaxTree = CSharpSyntaxTree.ParseText(wrappedCode);

        var compilation = CSharpCompilation.Create(
            "ValidationAssembly",
            new[] { syntaxTree },
            _references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var diagnostics = compilation.GetDiagnostics()
            .Where(d => d.Severity == DiagnosticSeverity.Error)
            .ToList();

        foreach (var diagnostic in diagnostics)
        {
            var lineSpan = diagnostic.Location.GetLineSpan();
            _errors.Add(new ScriptError
            {
                Line = lineSpan.StartLinePosition.Line - GetWrapperLineOffset() + 1,
                Column = lineSpan.StartLinePosition.Character + 1,
                Id = diagnostic.Id,
                Message = diagnostic.GetMessage(),
                Severity = diagnostic.Severity
            });
        }

        return diagnostics.Count == 0;
    }

    private static string WrapScript(string userCode)
    {
        return $@"
using System;
using System.Linq;
using System.Collections.Generic;
using Nexus.UI.Scripting;

namespace NexusScript
{{
    public static class Script
    {{
        public static void Run(ScriptContext ctx)
        {{
{IndentCode(userCode, 12)}
        }}
    }}
}}";
    }

    private static int GetWrapperLineOffset() => 11; // Number of lines before user code

    private static string IndentCode(string code, int spaces)
    {
        var indent = new string(' ', spaces);
        var lines = code.Split('\n');
        return string.Join('\n', lines.Select(line => indent + line.TrimEnd('\r')));
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _loadContext?.Unload();
            _loadContext = null;
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
