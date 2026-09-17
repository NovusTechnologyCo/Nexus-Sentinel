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
    #region Message Handlers

    private void HandleReady(byte[] payload)
    {
        if (payload.Length < 6) return;

        ushort total = BitConverter.ToUInt16(payload, 0);
        ushort success = BitConverter.ToUInt16(payload, 2);
        ushort fail = BitConverter.ToUInt16(payload, 4);

        OnReady?.Invoke(total, success, fail);
    }

    private void HandleEvent(byte[] payload)
    {
        if (_configuredApis == null) return;

        try
        {
            var evt = DeserializeEvent(payload);
            if (evt != null)
                OnApiCalled?.Invoke(evt);
        }
        catch { /* malformed event - skip */ }
    }

    private void HandleError(byte[] payload)
    {
        if (payload.Length < 2) return;
        ushort msgLen = BitConverter.ToUInt16(payload, 0);
        if (payload.Length < 2 + msgLen) return;
        string message = Encoding.UTF8.GetString(payload, 2, msgLen);
        OnError?.Invoke(message);
    }

    private void HandleChildCreated(byte[] payload)
    {
        if (payload.Length < 4) return;
        uint childPid = BitConverter.ToUInt32(payload, 0);
        OnChildCreated?.Invoke((int)childPid);
    }

    #endregion
    #region MSG_EVENT Deserialization

    /// <summary>
    /// Deserializes a binary MSG_EVENT payload into an ApiCallEvent.
    /// </summary>
    private ApiCallEvent? DeserializeEvent(byte[] data)
    {
        if (data.Length < 31) return null; // minimum size

        int offset = 0;

        uint threadId = BitConverter.ToUInt32(data, offset); offset += 4;
        ulong timestampQpc = BitConverter.ToUInt64(data, offset); offset += 8;
        ushort hookIndex = BitConverter.ToUInt16(data, offset); offset += 2;
        ulong durationQpc = BitConverter.ToUInt64(data, offset); offset += 8;
        ulong returnValue = BitConverter.ToUInt64(data, offset); offset += 8;
        uint lastError = BitConverter.ToUInt32(data, offset); offset += 4;
        byte paramCount = data[offset]; offset += 1;

        // Resolve API definition from hook index
        if (hookIndex >= (_configuredApis?.Length ?? 0))
            return null;

        var apiDef = _configuredApis![hookIndex];

        var evt = new ApiCallEvent
        {
            ProcessId = _targetPid,
            ThreadId = (int)threadId,
            Module = apiDef.Module,
            Function = apiDef.Name,
            Category = apiDef.Category,
            Duration = QpcFrequency > 0
                ? TimeSpan.FromTicks((long)(durationQpc * TimeSpan.TicksPerSecond / (ulong)QpcFrequency))
                : TimeSpan.Zero,
            ReturnValue = $"0x{returnValue:X}",
            Success = EvaluateSuccess(apiDef, returnValue, lastError),
        };

        // Deserialize parameters
        for (int i = 0; i < paramCount && offset < data.Length; i++)
        {
            if (offset + 10 > data.Length) break;

            ulong rawValue = BitConverter.ToUInt64(data, offset); offset += 8;
            ushort strLen = BitConverter.ToUInt16(data, offset); offset += 2;

            string stringData = "";
            if (strLen > 0 && offset + strLen <= data.Length)
            {
                stringData = Encoding.UTF8.GetString(data, offset, strLen);
                offset += strLen;
            }

            // Use definition metadata if available
            var paramDef = i < apiDef.Parameters.Count ? apiDef.Parameters[i] : null;

            evt.Parameters.Add(new ApiParameter
            {
                Name = paramDef?.Name ?? $"arg{i}",
                Type = paramDef?.Type ?? "UINT_PTR",
                RawValue = $"0x{rawValue:X}",
                Value = !string.IsNullOrEmpty(stringData) ? stringData : FormatRawValue(rawValue, paramDef),
                IsOutput = paramDef?.IsOutput ?? false,
            });
        }

        // Deserialize stack trace
        if (offset < data.Length)
        {
            byte stackDepth = data[offset]; offset += 1;
            for (int i = 0; i < stackDepth && offset + 8 <= data.Length; i++)
            {
                ulong addr = BitConverter.ToUInt64(data, offset); offset += 8;
                evt.CallStack.Add(new CallStackFrame
                {
                    Index = i,
                    Address = addr,
                });
            }
        }

        return evt;
    }

    /// <summary>
    /// Evaluates whether an API call succeeded based on the definition's success condition.
    /// </summary>
    private static bool EvaluateSuccess(ApiDefinition apiDef, ulong returnValue, uint lastError)
    {
        if (string.IsNullOrEmpty(apiDef.SuccessCondition))
            return true; // no condition defined = assume success

        return apiDef.SuccessCondition switch
        {
            "NotEqual" when apiDef.SuccessValue == "0" => returnValue != 0,
            "NotEqual" when apiDef.SuccessValue == "-1" => returnValue != unchecked((ulong)-1),
            "NotEqual" when apiDef.SuccessValue == "INVALID_HANDLE_VALUE" => returnValue != unchecked((ulong)-1),
            "Equal" when apiDef.SuccessValue == "0" => returnValue == 0,
            "Equal" when apiDef.SuccessValue == "S_OK" => returnValue == 0,
            "NotEqual" when apiDef.SuccessValue == "FALSE" => returnValue != 0,
            "NotEqual" when apiDef.SuccessValue == "NULL" => returnValue != 0,
            _ => lastError == 0
        };
    }

    /// <summary>
    /// Formats a raw uint64 value for display when no string data is available.
    /// </summary>
    private static string FormatRawValue(ulong rawValue, ApiParamDef? paramDef)
    {
        if (paramDef == null) return $"0x{rawValue:X}";

        var type = paramDef.Type.ToUpperInvariant();

        // Boolean types
        if (type == "BOOL" || type == "BOOLEAN")
            return rawValue != 0 ? "TRUE" : "FALSE";

        // Small integer types
        if (type is "INT" or "LONG" or "DWORD" or "UINT" or "ULONG" or "NTSTATUS" or "HRESULT")
            return $"0x{(uint)rawValue:X} ({(int)rawValue})";

        // Default: hex
        return $"0x{rawValue:X}";
    }

    #endregion
}
