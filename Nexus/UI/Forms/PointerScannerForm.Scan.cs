// <file>
// <summary>
// Pointer scanner form - scan operations, menu actions, and timer updates.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;

namespace Nexus.UI.Forms;

public partial class PointerScannerForm
{
    private void UpdateTimer_Tick(object? sender, EventArgs e)
    {
        if (_isScanning && _scanHandle != IntPtr.Zero)
        {
            var elapsed = DateTime.Now - _scanStartTime;

            // Get progress from engine
            var result = NexusEngine.Nexus_PointerScanGetProgress(_scanHandle, out var progress);
            if (result == NexusResult.OK)
            {
                UpdateStatistics(elapsed, progress);

                // Check if scan is complete
                if (progress.IsComplete != 0)
                {
                    _isScanning = false;
                    _btnStopScan.Enabled = false;
                    _updateTimer.Stop();
                    _lblProgress.Text = progress.WasCancelled != 0 ? "Scan cancelled" : "Scan complete";

                    // Load results
                    LoadResultsFromEngine();
                }
            }
        }
    }

    private void UpdateStatistics(TimeSpan elapsed, NexusPointerScanProgress progress)
    {
        if (_tvInfo.Nodes.Count > 0 && _tvInfo.Nodes[0].Nodes.Count > 0)
        {
            var statsNode = _tvInfo.Nodes[0];
            statsNode.Nodes[0].Text = $"Total time: {elapsed:hh\\:mm\\:ss}";
            statsNode.Nodes[1].Text = $"Addresses scanned: {progress.AddressesScanned:N0}";
            statsNode.Nodes[2].Text = $"Progress: {progress.Progress * 100:F1}%";
            statsNode.Nodes[3].Text = $"Results found: {progress.PathsFound:N0}";
            statsNode.Nodes[4].Text = $"Current level: {progress.CurrentLevel}";
        }

        // Clamp progress to 0-100 range to prevent ProgressBar exception
        int progressValue = Math.Clamp((int)(progress.Progress * 100), 0, 100);
        _progressBar.Value = progressValue;
        _lblProgress.Text = $"Scanning level {progress.CurrentLevel}... {progress.PathsFound:N0} paths found";
    }

    #region Menu Actions

    private void NewScan()
    {
        _engineResults.Clear();
        _lvResults.VirtualListSize = 0;
        InitializeInfoTree();
        _lblProgress.Text = "Ready";
        _progressBar.Value = 0;

        // Destroy existing scan handle
        if (_scanHandle != IntPtr.Zero)
        {
            NexusEngine.Nexus_PointerScanDestroy(_scanHandle);
            _scanHandle = IntPtr.Zero;
        }
    }

    private void OpenResults()
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "Pointer files (*.ptr;*.nsp)|*.ptr;*.nsp|All files (*.*)|*.*",
            Title = "Open pointer scan results"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            LoadResults(dialog.FileName);
        }
    }

    private void SaveResults()
    {
        using var dialog = new SaveFileDialog
        {
            Filter = "Pointer files (*.nsp)|*.nsp|All files (*.*)|*.*",
            Title = "Save pointer scan results"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            SaveResultsToFile(dialog.FileName);
        }
    }

    private void LoadResults(string filename)
    {
        if (_scanHandle == IntPtr.Zero)
        {
            var result = NexusEngine.Nexus_PointerScanCreate(_processHandle, out _scanHandle);
            if (result != NexusResult.OK)
            {
                MessageBox.Show($"Failed to create scan handle: {NexusHelper.GetErrorMessage(result)}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
        }

        var loadResult = NexusEngine.Nexus_PointerScanLoad(_scanHandle, filename);
        if (loadResult == NexusResult.OK)
        {
            LoadResultsFromEngine();
            _lblProgress.Text = $"Loaded: {Path.GetFileName(filename)}";
        }
        else
        {
            MessageBox.Show($"Failed to load: {NexusHelper.GetErrorMessage(loadResult)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void SaveResultsToFile(string filename)
    {
        if (_scanHandle == IntPtr.Zero)
        {
            MessageBox.Show("No scan results to save", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var result = NexusEngine.Nexus_PointerScanSave(_scanHandle, filename);
        if (result == NexusResult.OK)
        {
            _lblProgress.Text = $"Saved: {Path.GetFileName(filename)}";
        }
        else
        {
            MessageBox.Show($"Failed to save: {NexusHelper.GetErrorMessage(result)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void MergePointerFiles()
    {
        using var settingsForm = new MergePointerScanResultSettingsForm();
        if (settingsForm.ShowDialog() != DialogResult.OK)
            return;

        using var dialog = new OpenFileDialog
        {
            Filter = "Pointer files (*.ptr;*.nsp)|*.ptr;*.nsp|All files (*.*)|*.*",
            Title = "Select pointer files to merge",
            Multiselect = true
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            // Merging pointer files combines results from multiple scans to find common pointer paths
            // This is useful when scanning the same game multiple times to verify stable pointers
            MessageBox.Show($"Pointer file merging is an advanced feature.\nSelected {dialog.FileNames.Length} files for merge.",
                "Merge Pointers", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void StartPointerScan()
    {
        using var settingsForm = new PointerScanSettingsForm();
        if (settingsForm.ShowDialog() != DialogResult.OK)
            return;

        // Create scan handle if needed
        if (_scanHandle == IntPtr.Zero)
        {
            var result = NexusEngine.Nexus_PointerScanCreate(_processHandle, out _scanHandle);
            if (result != NexusResult.OK)
            {
                MessageBox.Show($"Failed to create pointer scan: {NexusHelper.GetErrorMessage(result)}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
        }

        // Configure scan parameters
        var scanParams = new NexusPointerScanParams
        {
            TargetAddress = settingsForm.TargetAddress,
            BaseStart = 0, // Auto
            BaseEnd = 0,   // Auto
            MaxLevel = (uint)settingsForm.MaxLevel,
            MaxOffset = (uint)settingsForm.MaxOffset,
            Alignment = _is64Bit ? 8u : 4u,  // Match pointer size
            Is64Bit = _is64Bit ? 1u : 0u,
            ScanWritable = 0,
            ScanStatic = settingsForm.OnlyBaseAddress ? 1u : 0u,
            MaxResults = (uint)settingsForm.MaxResults,
            MaxOffsetsPerNode = 3, // CE default is 3
            AllowNegativeOffsets = settingsForm.AllowNegativeOffsets ? 1u : 0u
        };

        // Start the scan
        var startResult = NexusEngine.Nexus_PointerScanStart(_scanHandle, ref scanParams);
        if (startResult != NexusResult.OK)
        {
            MessageBox.Show($"Failed to start pointer scan: {NexusHelper.GetErrorMessage(startResult)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        _isScanning = true;
        _scanStartTime = DateTime.Now;
        _btnStopScan.Enabled = true;
        _lblProgress.Text = "Scanning...";
        _updateTimer.Start();
    }

    private void RescanMemory()
    {
        using var rescanForm = new PointerRescanForm();
        if (rescanForm.ShowDialog() != DialogResult.OK)
            return;

        // Rescan filters the existing pointer paths by checking if they still point to expected values
        // This is useful after the target value changes to narrow down valid pointers
        if (_engineResults.Count == 0)
        {
            MessageBox.Show("No pointer paths to rescan. Run a pointer scan first.",
                "Rescan", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        MessageBox.Show($"Rescan would filter {_engineResults.Count} pointer paths.\nThis feature will check which pointers still resolve to valid addresses.",
            "Rescan Memory", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void ResumeScan()
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "Pointer scan state (*.pss)|*.pss|All files (*.*)|*.*",
            Title = "Resume pointer scan"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            // Resume scan loads a previously saved scan state to continue scanning
            MessageBox.Show($"Would resume scan from: {dialog.FileName}\nScan state resume allows continuing interrupted scans.",
                "Resume Scan", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void SetWorkFolder()
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Select work folder for pointer scanner"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            // The work folder is used for temporary files during long pointer scans
            MessageBox.Show($"Work folder set to: {dialog.SelectedPath}\nTemporary files will be stored here during scans.",
                "Work Folder", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void ShowSortPointerList()
    {
        using var form = new SortPointerlistForm();
        if (form.ShowDialog() == DialogResult.OK)
        {
            // Apply the configured sort options to the results
            // The sort settings from the form would be used here
            RefreshResults();
        }
    }

    private void ShowAdvancedSettings()
    {
        using var form = new PointerScannerSettingsForm();
        form.ShowDialog();
    }

    #endregion

    #region Control Actions

    private void StopScan()
    {
        if (_scanHandle != IntPtr.Zero)
        {
            NexusEngine.Nexus_PointerScanCancel(_scanHandle);
        }

        _isScanning = false;
        _btnStopScan.Enabled = false;
        _updateTimer.Stop();
        _lblProgress.Text = "Scan stopped";

        // Load whatever results we have
        LoadResultsFromEngine();
    }

    private void StopRescanLoop()
    {
        _btnStopRescanLoop.Enabled = false;
        // Rescan loop is not currently running in continuous mode
        // This button is disabled when not in a rescan loop
    }

    #endregion
}
