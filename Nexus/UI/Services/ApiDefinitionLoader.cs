// <file>
// <summary>
// Parser for rohitab API Monitor XML definition files. Reads the API/ directory tree
// containing per-DLL XML files with function signatures, parameter types, and categories.
// Builds a hierarchical model (DLL -> Category -> Function) used to populate the API
// Monitor panel's tree view for API selection. Results are cached after first load.
// </summary>
// </file>

using System.Xml.Linq;
using Nexus.UI.Models;

namespace Nexus.UI.Services;

/// <summary>
/// Loads and caches API function definitions from API Monitor XML files.
/// Parses the directory tree under the API/ folder to build a
/// DLL -> Category -> Function hierarchy for the API Monitor tree view.
/// </summary>
public class ApiDefinitionLoader
{
    private static List<ApiModuleGroup>? _cachedModules;
    private static readonly object _cacheLock = new();

    /// <summary>
    /// Resolves the base API directory path by searching known locations.
    /// </summary>
    public static string? FindApiDirectory()
    {
        // Try relative paths from the executable directory
        // Output is Nexus/bin/, repo root is ../../ from there
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        const string relPath = "reference material/api-monitor-apis/api-monitor-v2r13/API";
        string[] candidates =
        [
            Path.Combine(baseDir, relPath),
            Path.Combine(baseDir, "..", relPath),
            Path.Combine(baseDir, "..", "..", relPath),
            Path.Combine(baseDir, "..", "..", "..", relPath),
            Path.Combine(baseDir, "..", "..", "..", "..", relPath),
            Path.Combine(baseDir, "..", "..", "..", "..", "..", relPath),
            Path.Combine(baseDir, "..", "..", "..", "..", "..", "..", relPath),
        ];

        foreach (var candidate in candidates)
        {
            var fullPath = Path.GetFullPath(candidate);
            if (Directory.Exists(fullPath) && Directory.Exists(Path.Combine(fullPath, "Windows")))
                return fullPath;
        }

        return null;
    }

    /// <summary>
    /// Loads all API definitions from the XML files. Result is cached.
    /// </summary>
    public static List<ApiModuleGroup> LoadAll(string? apiDirectory = null)
    {
        lock (_cacheLock)
        {
            if (_cachedModules != null)
                return _cachedModules;
        }

        apiDirectory ??= FindApiDirectory();
        if (apiDirectory == null || !Directory.Exists(apiDirectory))
            return [];

        var modules = new List<ApiModuleGroup>();

        // Parse all directories containing module XML files
        string[] moduleDirs =
        [
            Path.Combine(apiDirectory, "Windows"),
            Path.Combine(apiDirectory, "Internal"),
            Path.Combine(apiDirectory, "Interfaces"),
            Path.Combine(apiDirectory, "MAPI"),
            Path.Combine(apiDirectory, "MMF"),
            Path.Combine(apiDirectory, "Mozilla"),
            Path.Combine(apiDirectory, "SMI"),
            Path.Combine(apiDirectory, "VSS"),
            Path.Combine(apiDirectory, "WindowsFirewall"),
            Path.Combine(apiDirectory, "WindowsStore"),
            Path.Combine(apiDirectory, "WMI"),
        ];

        foreach (var dir in moduleDirs)
        {
            if (!Directory.Exists(dir)) continue;

            foreach (var xmlFile in Directory.EnumerateFiles(dir, "*.xml"))
            {
                try
                {
                    var parsed = ParseModuleFile(xmlFile);
                    if (parsed != null)
                        modules.AddRange(parsed);
                }
                catch
                {
                    // Skip files that fail to parse
                }
            }
        }

        // Sort modules by name
        modules.Sort((a, b) => string.Compare(a.ModuleName, b.ModuleName, StringComparison.OrdinalIgnoreCase));

        lock (_cacheLock)
        {
            _cachedModules = modules;
        }

        return modules;
    }

    /// <summary>
    /// Clears the cached definitions, forcing a reload on next call.
    /// </summary>
    public static void ClearCache()
    {
        lock (_cacheLock)
        {
            _cachedModules = null;
        }
    }

    /// <summary>
    /// Parses a single XML file and extracts Module definitions with their APIs.
    /// </summary>
    private static List<ApiModuleGroup>? ParseModuleFile(string filePath)
    {
        var doc = XDocument.Load(filePath);
        var root = doc.Root;
        if (root == null || root.Name.LocalName != "ApiMonitor")
            return null;

        var results = new List<ApiModuleGroup>();

        foreach (var moduleElement in root.Elements("Module"))
        {
            var moduleName = moduleElement.Attribute("Name")?.Value;
            if (string.IsNullOrEmpty(moduleName) || moduleName == "*")
                continue;

            var group = new ApiModuleGroup
            {
                ModuleName = moduleName,
                CallingConvention = moduleElement.Attribute("CallingConvention")?.Value ?? "STDCALL",
                ErrorFunc = moduleElement.Attribute("ErrorFunc")?.Value,
            };

            ParseModuleApis(moduleElement, group);

            if (group.TotalApiCount > 0)
                results.Add(group);
        }

        return results.Count > 0 ? results : null;
    }

    /// <summary>
    /// Extracts APIs from a Module element, organizing by Category.
    /// </summary>
    private static void ParseModuleApis(XElement moduleElement, ApiModuleGroup group)
    {
        string currentCategory = "";

        foreach (var child in moduleElement.Elements())
        {
            switch (child.Name.LocalName)
            {
                case "Category":
                    currentCategory = child.Attribute("Name")?.Value ?? "";
                    break;

                case "Api":
                    var api = ParseApi(child, group.ModuleName, currentCategory, group.CallingConvention);
                    if (api != null)
                    {
                        var categoryNode = GetOrCreateCategory(group, currentCategory);

                        // BothCharset="True" means rohitab represents the ANSI/Wide
                        // pair as a single base entry (e.g. "LoadLibrary"). The runtime
                        // DLLs do NOT export the base name -- only "LoadLibraryA" and
                        // "LoadLibraryW". Expand into both variants here so the in-memory
                        // DB matches what GetProcAddress can actually resolve in the
                        // hook DLL. Param Type strings (LPCTSTR / TCHAR / etc.) are
                        // also rewritten so ComputeParamFlags picks the right capture
                        // mode for each variant.
                        var bothCharset = child.Attribute("BothCharset")?.Value == "True";
                        if (bothCharset)
                        {
                            categoryNode.Apis.Add(CloneApiForCharset(api, child, isWide: false));
                            categoryNode.Apis.Add(CloneApiForCharset(api, child, isWide: true));
                        }
                        else
                        {
                            categoryNode.Apis.Add(api);
                        }
                    }
                    break;
            }
        }
    }

    /// <summary>
    /// Clones a BothCharset API into either the ANSI ("...A") or Wide ("...W")
    /// variant. Substitutes T-style placeholder type names (LPCTSTR/TCHAR/etc.)
    /// in parameter types so ComputeParamFlags picks the right capture mode.
    /// Honors per-variant OrdinalA / OrdinalW attributes if present.
    /// </summary>
    private static ApiDefinition CloneApiForCharset(ApiDefinition source, XElement apiElement, bool isWide)
    {
        var suffix = isWide ? "W" : "A";
        var clone = new ApiDefinition
        {
            Module = source.Module,
            Category = source.Category,
            Name = source.Name + suffix,
            ReturnType = source.ReturnType,
            CallingConvention = source.CallingConvention,
            SuccessCondition = source.SuccessCondition,
            SuccessValue = source.SuccessValue,
            Ordinal = source.Ordinal,
        };

        // Per-variant ordinals (e.g. OrdinalA="377" OrdinalW="378")
        var perVariantOrdinal = apiElement.Attribute(isWide ? "OrdinalW" : "OrdinalA")?.Value;
        if (int.TryParse(perVariantOrdinal, out int ord))
            clone.Ordinal = ord;

        foreach (var p in source.Parameters)
        {
            clone.Parameters.Add(new ApiParamDef
            {
                Name = p.Name,
                Type = SubstituteTCharType(p.Type, isWide),
                IsOutput = p.IsOutput,
                IsOptional = p.IsOptional,
                Length = p.Length,
                PostLength = p.PostLength,
                InterfaceId = p.InterfaceId,
                DerefCount = p.DerefCount,
            });
        }
        return clone;
    }

    /// <summary>
    /// Replaces T-style placeholder type names with their A or W concrete form.
    /// Used when expanding BothCharset Api entries into per-variant copies.
    /// </summary>
    private static string SubstituteTCharType(string type, bool isWide)
    {
        if (string.IsNullOrEmpty(type)) return type;
        var c = isWide ? "W" : "A";
        // Order matters: longer prefixes first so LPCTSTR matches before TSTR.
        // Also handle the rohitab `$cT` placeholder some headers use.
        return type
            .Replace("LPCTSTR", "LPC" + c + "STR")
            .Replace("LPTSTR",  "LP" + c + "STR")
            .Replace("PCTSTR",  "PC" + c + "STR")
            .Replace("PTSTR",   "P" + c + "STR")
            .Replace("TCHAR",   isWide ? "WCHAR" : "CHAR")
            .Replace("$cT",     "$c" + c);
    }

    /// <summary>
    /// Parses a single Api element into an ApiDefinition.
    /// </summary>
    private static ApiDefinition? ParseApi(XElement apiElement, string module, string category, string callingConvention)
    {
        var name = apiElement.Attribute("Name")?.Value;
        if (string.IsNullOrEmpty(name))
            return null;

        var api = new ApiDefinition
        {
            Module = module,
            Category = category,
            Name = name,
            CallingConvention = apiElement.Attribute("CallingConvention")?.Value ?? callingConvention,
        };

        // Parse ordinal
        var ordinalStr = apiElement.Attribute("Ordinal")?.Value;
        if (int.TryParse(ordinalStr, out int ordinal))
            api.Ordinal = ordinal;

        // Parse parameters
        foreach (var paramElement in apiElement.Elements("Param"))
        {
            var param = ParseParam(paramElement);
            if (param != null)
                api.Parameters.Add(param);
        }

        // Parse return type
        var returnElement = apiElement.Element("Return");
        if (returnElement != null)
            api.ReturnType = returnElement.Attribute("Type")?.Value ?? "void";

        // Parse success condition
        var successElement = apiElement.Element("Success");
        if (successElement != null)
        {
            api.SuccessCondition = successElement.Attribute("Return")?.Value;
            api.SuccessValue = successElement.Attribute("Value")?.Value;
        }

        return api;
    }

    /// <summary>
    /// Parses a Param element into an ApiParamDef.
    /// </summary>
    private static ApiParamDef? ParseParam(XElement paramElement)
    {
        var type = paramElement.Attribute("Type")?.Value;
        var name = paramElement.Attribute("Name")?.Value;
        if (string.IsNullOrEmpty(type) || string.IsNullOrEmpty(name))
            return null;

        var param = new ApiParamDef
        {
            Type = type,
            Name = name,
            Length = paramElement.Attribute("Length")?.Value,
            PostLength = paramElement.Attribute("PostLength")?.Value,
            InterfaceId = paramElement.Attribute("InterfaceId")?.Value,
        };

        // Check output attribute
        var outputAttr = paramElement.Attribute("OutputOnly")?.Value;
        param.IsOutput = outputAttr == "True";

        // Check optional attribute
        var optAttr = paramElement.Attribute("Optional")?.Value;
        param.IsOptional = optAttr == "True";

        // Parse deref count
        var derefStr = paramElement.Attribute("DerefCount")?.Value;
        if (int.TryParse(derefStr, out int deref))
            param.DerefCount = deref;

        return param;
    }

    /// <summary>
    /// Gets or creates a category node in the hierarchy from a slash-separated path.
    /// E.g., "System Services/Processes and Threads/Process" creates 3 nested levels.
    /// </summary>
    private static ApiCategoryGroup GetOrCreateCategory(ApiModuleGroup group, string categoryPath)
    {
        if (string.IsNullOrEmpty(categoryPath))
        {
            // No category — use a default "Uncategorized" node
            var uncategorized = group.Categories.FirstOrDefault(c => c.Name == "Uncategorized");
            if (uncategorized == null)
            {
                uncategorized = new ApiCategoryGroup { Name = "Uncategorized", FullPath = "Uncategorized" };
                group.Categories.Add(uncategorized);
            }
            return uncategorized;
        }

        var parts = categoryPath.Split('/');
        List<ApiCategoryGroup> currentList = group.Categories;
        ApiCategoryGroup? current = null;
        var pathSoFar = "";

        foreach (var part in parts)
        {
            pathSoFar = pathSoFar.Length > 0 ? $"{pathSoFar}/{part}" : part;
            var existing = currentList.FirstOrDefault(c => c.Name == part);
            if (existing == null)
            {
                existing = new ApiCategoryGroup { Name = part, FullPath = pathSoFar };
                currentList.Add(existing);
            }
            current = existing;
            currentList = existing.SubCategories;
        }

        return current!;
    }
}
