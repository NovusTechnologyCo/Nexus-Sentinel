using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Models;

namespace Nexus.UI.Services;

public partial class ApiMonitorService
{
    #region API Prioritization

    /// <summary>
    /// Priority order for DLL modules. Common system DLLs that are always loaded
    /// and frequently called are registered first. This ensures short-lived processes
    /// get the most useful hooks armed before they exit.
    /// </summary>
    private static readonly Dictionary<string, int> ModulePriority = new(StringComparer.OrdinalIgnoreCase)
    {
        ["kernel32.dll"] = 0,
        ["kernelbase.dll"] = 1,
        ["ntdll.dll"] = 2,
        ["user32.dll"] = 3,
        ["advapi32.dll"] = 4,
        ["ws2_32.dll"] = 5,
        ["sechost.dll"] = 6,
        ["crypt32.dll"] = 7,
        ["ole32.dll"] = 8,
        ["oleaut32.dll"] = 9,
        ["shell32.dll"] = 10,
        ["gdi32.dll"] = 11,
        ["wininet.dll"] = 12,
        ["winhttp.dll"] = 13,
        ["combase.dll"] = 14,
        ["bcrypt.dll"] = 15,
        ["ncrypt.dll"] = 16,
        ["msvcrt.dll"] = 17,
        ["ucrtbase.dll"] = 18,
        ["rpcrt4.dll"] = 19,
        ["setupapi.dll"] = 20,
        ["iphlpapi.dll"] = 21,
        ["dnsapi.dll"] = 22,
        ["psapi.dll"] = 23,
        ["dbghelp.dll"] = 24,
    };

    /// <summary>
    /// Sorts API definitions so commonly-used DLLs are registered first.
    /// The hook DLL processes APIs in order, so putting kernel32/ntdll first ensures
    /// the most important hooks are armed before a short-lived process exits.
    /// </summary>
    private static ApiDefinition[] PrioritizeApiDefinitions(List<ApiDefinition> apis)
    {
        const int defaultPriority = 100;
        return [.. apis.OrderBy(a =>
            ModulePriority.TryGetValue(a.Module, out var p) ? p : defaultPriority)];
    }

    #endregion
    #region MSG_CONFIGURE Serialization

    /// <summary>
    /// Serializes and sends the API list to the hook DLL.
    /// </summary>
    private void SendConfigure()
    {
        if (_configuredApis == null || _configuredApis.Length == 0) return;

        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.UTF8);

        bw.Write((ushort)_configuredApis.Length);

        foreach (var api in _configuredApis)
        {
            // Module name (UTF-8)
            var modBytes = Encoding.UTF8.GetBytes(api.Module);
            bw.Write((ushort)modBytes.Length);
            bw.Write(modBytes);

            // Function name (UTF-8)
            var funcBytes = Encoding.UTF8.GetBytes(api.Name);
            bw.Write((ushort)funcBytes.Length);
            bw.Write(funcBytes);

            // Parameter count
            byte paramCount = (byte)Math.Min(api.Parameters.Count, 16);
            bw.Write(paramCount);

            // Per-parameter metadata
            for (int i = 0; i < paramCount; i++)
            {
                var param = api.Parameters[i];
                byte flags = ComputeParamFlags(param);
                bw.Write(flags);

                var nameBytes = Encoding.UTF8.GetBytes(param.Name);
                bw.Write((ushort)nameBytes.Length);
                bw.Write(nameBytes);

                var typeBytes = Encoding.UTF8.GetBytes(param.Type);
                bw.Write((ushort)typeBytes.Length);
                bw.Write(typeBytes);
            }
        }

        // Propagation config — appended after API list
        // Format: [uint8 flags] [uint16 dllPathLenBytes] [wchar_t[] dllPath]
        var hookDllPath = FindHookDll(HookDllName64);
        if (hookDllPath != null)
        {
            bw.Write((byte)0x01); // propagation enabled
            var dllPathW = Encoding.Unicode.GetBytes(hookDllPath + '\0');
            bw.Write((ushort)dllPathW.Length);
            bw.Write(dllPathW);
        }
        else
        {
            bw.Write((byte)0x00); // propagation disabled
        }

        bw.Flush();
        SendMessage(MSG_CONFIGURE, ms.ToArray());
    }

    /// <summary>
    /// Maps an ApiParamDef to wire protocol flags.
    /// </summary>
    private static byte ComputeParamFlags(ApiParamDef param)
    {
        byte flags = 0;
        if (param.IsOutput) flags |= PARAM_FLAG_OUTPUT;
        if (param.IsOptional) flags |= PARAM_FLAG_OPTIONAL;

        var type = param.Type.ToUpperInvariant();

        // Detect POBJECT_ATTRIBUTES BEFORE generic string detection because
        // it's a more specific type. The hook engine handles dereferencing
        // POBJECT_ATTRIBUTES -> ObjectName.Buffer to expose the embedded
        // file/registry/section path. This is required for any NT* API call
        // (NtCreateFile, NtOpenKey, NtOpenSection, etc.) to surface actual
        // names instead of opaque pointers.
        if (type.Contains("OBJECT_ATTRIBUTES"))
        {
            flags |= PARAM_FLAG_OBJECT_ATTRIBUTES;
            flags |= PARAM_FLAG_POINTER;
            return flags;
        }

        // Detect string types
        if (type.Contains("LPWSTR") || type.Contains("LPCWSTR") || type.Contains("PWSTR") ||
            type.Contains("PCWSTR") || type.Contains("BSTR") || type.Contains("WCHAR*") ||
            type == "LPTSTR" || type == "LPCTSTR")
        {
            flags |= PARAM_FLAG_WIDE_STRING;
        }
        else if (type.Contains("LPSTR") || type.Contains("LPCSTR") || type.Contains("PSTR") ||
                 type.Contains("PCSTR") || type.Contains("CHAR*"))
        {
            flags |= PARAM_FLAG_ANSI_STRING;
        }

        // Detect pointer types
        if (type.Contains('*') || type.StartsWith("LP") || type.StartsWith("P") ||
            type == "HANDLE" || type == "HMODULE" || type == "HKEY" || type == "PVOID")
        {
            flags |= PARAM_FLAG_POINTER;
        }

        return flags;
    }

    #endregion
}
