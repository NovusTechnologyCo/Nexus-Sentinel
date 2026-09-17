// <file>
// <summary>
// Partial class for ApiMonPanel handling the API selection tree view: populating
// nodes from API definition XML files, tri-state checkbox cascading (parent/child),
// search filtering, and tracking which API functions are selected for monitoring.
// </summary>
// </file>

using Nexus.UI.Models;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class ApiMonPanel
{
    // Suppresses AfterCheck cascading during programmatic updates
    private bool _suppressCheckEvents;

    /// <summary>
    /// Populates the TreeView from loaded API definitions.
    /// </summary>
    private void PopulateTree()
    {
        _apiTree.BeginUpdate();
        _apiTree.Nodes.Clear();

        int totalApis = 0;

        foreach (var module in _moduleGroups)
        {
            var moduleNode = new TreeNode(module.ModuleName)
            {
                Tag = module,
            };

            foreach (var category in module.Categories)
            {
                AddCategoryNode(moduleNode, category);
            }

            totalApis += module.TotalApiCount;
            _apiTree.Nodes.Add(moduleNode);
        }

        _apiTree.EndUpdate();
        _statusLabel.Text = $"Loaded {totalApis:N0} APIs from {_moduleGroups.Count} modules - Select APIs and attach a process to begin";
    }

    /// <summary>
    /// Recursively adds category and API nodes to the tree.
    /// </summary>
    private static void AddCategoryNode(TreeNode parent, ApiCategoryGroup category)
    {
        var catNode = new TreeNode($"{category.Name} ({category.TotalApiCount})")
        {
            Tag = category,
        };

        // Add sub-categories
        foreach (var sub in category.SubCategories)
        {
            AddCategoryNode(catNode, sub);
        }

        // Add individual API functions
        foreach (var api in category.Apis)
        {
            var apiNode = new TreeNode(api.Name)
            {
                Tag = api,
            };
            catNode.Nodes.Add(apiNode);
        }

        parent.Nodes.Add(catNode);
    }

    /// <summary>
    /// Handles checkbox cascading: parent check → check all children, child change → update parents.
    /// </summary>
    private void ApiTree_AfterCheck(object? sender, TreeViewEventArgs e)
    {
        if (_suppressCheckEvents || e.Node == null) return;

        _suppressCheckEvents = true;
        try
        {
            // Cascade to children
            SetChildrenChecked(e.Node, e.Node.Checked);

            // Update parent state
            UpdateParentCheck(e.Node.Parent);

            // Update selected APIs set
            UpdateSelectedApis();
        }
        finally
        {
            _suppressCheckEvents = false;
        }
    }

    private static void SetChildrenChecked(TreeNode node, bool isChecked)
    {
        foreach (TreeNode child in node.Nodes)
        {
            child.Checked = isChecked;
            SetChildrenChecked(child, isChecked);
        }
    }

    private static void UpdateParentCheck(TreeNode? parent)
    {
        while (parent != null)
        {
            bool anyChecked = false;

            foreach (TreeNode child in parent.Nodes)
            {
                if (child.Checked)
                {
                    anyChecked = true;
                    break;
                }
            }

            parent.Checked = anyChecked;
            parent = parent.Parent;
        }
    }

    /// <summary>
    /// Rebuilds the _selectedApis set from checked tree leaf nodes.
    /// </summary>
    private void UpdateSelectedApis()
    {
        _selectedApis.Clear();
        CollectCheckedApis(_apiTree.Nodes);
        _eventCountLabel.Text = $"Events: {_events.Count} | Selected: {_selectedApis.Count}";
    }

    private void CollectCheckedApis(TreeNodeCollection nodes)
    {
        foreach (TreeNode node in nodes)
        {
            if (node.Tag is ApiDefinition api && node.Checked)
            {
                _selectedApis.Add(api.Key);
            }
            CollectCheckedApis(node.Nodes);
        }
    }

    /// <summary>
    /// Filters the tree to show only nodes matching the search text.
    /// </summary>
    private void TreeSearchBox_TextChanged(object? sender, EventArgs e)
    {
        _treeSearchText = _treeSearchBox.Text.Trim();

        if (string.IsNullOrEmpty(_treeSearchText))
        {
            // Show all nodes
            _apiTree.BeginUpdate();
            ShowAllNodes(_apiTree.Nodes);
            _apiTree.EndUpdate();
            return;
        }

        _apiTree.BeginUpdate();
        FilterTreeNodes(_apiTree.Nodes, _treeSearchText);
        _apiTree.EndUpdate();
    }

    /// <summary>
    /// Recursively filters tree nodes, hiding non-matching branches.
    /// Returns true if any child matches (to keep parent visible).
    /// </summary>
    private static bool FilterTreeNodes(TreeNodeCollection nodes, string search)
    {
        bool anyVisible = false;

        foreach (TreeNode node in nodes)
        {
            bool nodeMatches = node.Text.Contains(search, StringComparison.OrdinalIgnoreCase);
            bool childMatches = FilterTreeNodes(node.Nodes, search);

            bool shouldShow = nodeMatches || childMatches;

            // TreeView doesn't support hiding nodes directly, so we use
            // ForeColor to dim non-matching nodes and expand matching branches
            if (shouldShow)
            {
                node.ForeColor = NexusTheme.TextPrimary;
                if (childMatches && !nodeMatches)
                    node.Expand();
                anyVisible = true;
            }
            else
            {
                node.ForeColor = Color.FromArgb(80, 80, 80);
                node.Collapse();
            }

            // If the node itself matches, expand to show it
            if (nodeMatches && node.Tag is ApiDefinition)
            {
                node.EnsureVisible();
            }
        }

        return anyVisible;
    }

    private static void ShowAllNodes(TreeNodeCollection nodes)
    {
        foreach (TreeNode node in nodes)
        {
            node.ForeColor = NexusTheme.TextPrimary;
            ShowAllNodes(node.Nodes);
        }
    }

    private void BtnSelectAll_Click(object? sender, EventArgs e) => SelectAllApis();
    private void BtnSelectNone_Click(object? sender, EventArgs e) => DeselectAllApis();

    private void SelectAllApis()
    {
        _suppressCheckEvents = true;
        try
        {
            foreach (TreeNode node in _apiTree.Nodes)
            {
                node.Checked = true;
                SetChildrenChecked(node, true);
            }
        }
        finally
        {
            _suppressCheckEvents = false;
        }
        UpdateSelectedApis();
    }

    private void DeselectAllApis()
    {
        _suppressCheckEvents = true;
        try
        {
            foreach (TreeNode node in _apiTree.Nodes)
            {
                node.Checked = false;
                SetChildrenChecked(node, false);
            }
        }
        finally
        {
            _suppressCheckEvents = false;
        }
        UpdateSelectedApis();
    }
}
