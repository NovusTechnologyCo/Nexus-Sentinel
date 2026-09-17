// <file>
// <summary>
// Designer-generated code for FoundCodeForm. Do not edit manually.
// </summary>
// </file>
namespace Nexus.UI.Forms;

partial class FoundCodeForm
{
    private System.ComponentModel.IContainer components = null!;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _monitoring = false;

            if (components != null)
            {
                components.Dispose();
            }
        }
        base.Dispose(disposing);
    }

    #region Windows Form Designer generated code

    private void InitializeComponent()
    {
        this.components = new System.ComponentModel.Container();

        this.pnlRight = new Panel();
        this.lblDescription = new Label();
        this.pnlButtons = new Panel();
        this.btnReplace = new Button();
        this.btnShowDisasm = new Button();
        this.btnAddToCodeList = new Button();
        this.btnMoreInfo = new Button();
        this.pnlOK = new Panel();
        this.btnOK = new Button();
        this.pnlLeft = new Panel();
        this.lvFoundCode = new ListView();
        this.colCount = new ColumnHeader();
        this.colInstruction = new ColumnHeader();
        this.splitter = new Splitter();
        this.memoInfo = new TextBox();
        this.ctxFoundCode = new ContextMenuStrip(this.components);
        this.ctxReplace = new ToolStripMenuItem();
        this.ctxShowDisasm = new ToolStripMenuItem();
        this.ctxAddToCodeList = new ToolStripMenuItem();
        this.ctxMoreInfo = new ToolStripMenuItem();
        this.toolStripSeparator1 = new ToolStripSeparator();
        this.ctxSelectAll = new ToolStripMenuItem();
        this.toolStripSeparator2 = new ToolStripSeparator();
        this.ctxSaveToFile = new ToolStripMenuItem();
        this.ctxCopyToClipboard = new ToolStripMenuItem();

        this.pnlRight.SuspendLayout();
        this.pnlButtons.SuspendLayout();
        this.pnlOK.SuspendLayout();
        this.pnlLeft.SuspendLayout();
        this.ctxFoundCode.SuspendLayout();
        this.SuspendLayout();

        // pnlRight
        this.pnlRight.Controls.Add(this.lblDescription);
        this.pnlRight.Controls.Add(this.pnlButtons);
        this.pnlRight.Controls.Add(this.pnlOK);
        this.pnlRight.Dock = DockStyle.Right;
        this.pnlRight.Location = new Point(294, 0);
        this.pnlRight.Name = "pnlRight";
        this.pnlRight.Size = new Size(136, 399);

        // lblDescription
        this.lblDescription.Dock = DockStyle.Fill;
        this.lblDescription.Location = new Point(0, 150);
        this.lblDescription.Name = "lblDescription";
        this.lblDescription.Padding = new Padding(5);
        this.lblDescription.Size = new Size(136, 209);
        this.lblDescription.TextAlign = ContentAlignment.TopCenter;

        // pnlButtons
        this.pnlButtons.Controls.Add(this.btnReplace);
        this.pnlButtons.Controls.Add(this.btnShowDisasm);
        this.pnlButtons.Controls.Add(this.btnAddToCodeList);
        this.pnlButtons.Controls.Add(this.btnMoreInfo);
        this.pnlButtons.Dock = DockStyle.Top;
        this.pnlButtons.Location = new Point(0, 0);
        this.pnlButtons.Name = "pnlButtons";
        this.pnlButtons.Size = new Size(136, 150);

        // btnReplace
        this.btnReplace.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        this.btnReplace.Enabled = false;
        this.btnReplace.Location = new Point(5, 5);
        this.btnReplace.Name = "btnReplace";
        this.btnReplace.Size = new Size(126, 30);
        this.btnReplace.Text = "Replace";
        this.btnReplace.UseVisualStyleBackColor = true;
        this.btnReplace.Click += new EventHandler(this.BtnReplace_Click);

        // btnShowDisasm
        this.btnShowDisasm.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        this.btnShowDisasm.Enabled = false;
        this.btnShowDisasm.Location = new Point(5, 40);
        this.btnShowDisasm.Name = "btnShowDisasm";
        this.btnShowDisasm.Size = new Size(126, 30);
        this.btnShowDisasm.Text = "Show disassembler";
        this.btnShowDisasm.UseVisualStyleBackColor = true;
        this.btnShowDisasm.Click += new EventHandler(this.BtnShowDisasm_Click);

        // btnAddToCodeList
        this.btnAddToCodeList.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        this.btnAddToCodeList.Enabled = false;
        this.btnAddToCodeList.Location = new Point(5, 75);
        this.btnAddToCodeList.Name = "btnAddToCodeList";
        this.btnAddToCodeList.Size = new Size(126, 30);
        this.btnAddToCodeList.Text = "Add to codelist";
        this.btnAddToCodeList.UseVisualStyleBackColor = true;
        this.btnAddToCodeList.Click += new EventHandler(this.BtnAddToCodeList_Click);

        // btnMoreInfo
        this.btnMoreInfo.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        this.btnMoreInfo.Enabled = false;
        this.btnMoreInfo.Location = new Point(5, 110);
        this.btnMoreInfo.Name = "btnMoreInfo";
        this.btnMoreInfo.Size = new Size(126, 30);
        this.btnMoreInfo.Text = "More information";
        this.btnMoreInfo.UseVisualStyleBackColor = true;
        this.btnMoreInfo.Click += new EventHandler(this.BtnMoreInfo_Click);

        // pnlOK
        this.pnlOK.Controls.Add(this.btnOK);
        this.pnlOK.Dock = DockStyle.Bottom;
        this.pnlOK.Location = new Point(0, 359);
        this.pnlOK.Name = "pnlOK";
        this.pnlOK.Size = new Size(136, 40);

        // btnOK
        this.btnOK.Anchor = AnchorStyles.Top;
        this.btnOK.DialogResult = DialogResult.Cancel;
        this.btnOK.Location = new Point(31, 5);
        this.btnOK.Name = "btnOK";
        this.btnOK.Size = new Size(80, 32);
        this.btnOK.Text = "OK";
        this.btnOK.UseVisualStyleBackColor = true;
        this.btnOK.Click += new EventHandler(this.BtnOK_Click);

        // pnlLeft
        this.pnlLeft.Controls.Add(this.lvFoundCode);
        this.pnlLeft.Controls.Add(this.splitter);
        this.pnlLeft.Controls.Add(this.memoInfo);
        this.pnlLeft.Dock = DockStyle.Fill;
        this.pnlLeft.Location = new Point(0, 0);
        this.pnlLeft.Name = "pnlLeft";
        this.pnlLeft.Size = new Size(294, 399);

        // lvFoundCode
        this.lvFoundCode.Columns.AddRange(new ColumnHeader[] { this.colCount, this.colInstruction });
        this.lvFoundCode.ContextMenuStrip = this.ctxFoundCode;
        this.lvFoundCode.Dock = DockStyle.Fill;
        this.lvFoundCode.Font = new Font("Consolas", 9F);
        this.lvFoundCode.FullRowSelect = true;
        this.lvFoundCode.HideSelection = false;
        this.lvFoundCode.Location = new Point(0, 0);
        this.lvFoundCode.MultiSelect = true;
        this.lvFoundCode.Name = "lvFoundCode";
        this.lvFoundCode.Size = new Size(294, 236);
        this.lvFoundCode.View = View.Details;
        this.lvFoundCode.SelectedIndexChanged += new EventHandler(this.LvFoundCode_SelectedIndexChanged);
        this.lvFoundCode.DoubleClick += new EventHandler(this.LvFoundCode_DoubleClick);

        // colCount
        this.colCount.Text = "Count";
        this.colCount.Width = 70;

        // colInstruction
        this.colInstruction.Text = "Instruction";
        this.colInstruction.Width = -2; // Auto-size to fill remaining space

        // splitter
        this.splitter.Dock = DockStyle.Bottom;
        this.splitter.Location = new Point(0, 236);
        this.splitter.Name = "splitter";
        this.splitter.Size = new Size(294, 5);

        // memoInfo
        this.memoInfo.Dock = DockStyle.Bottom;
        this.memoInfo.Font = new Font("Segoe UI", 9F);
        this.memoInfo.Location = new Point(0, 241);
        this.memoInfo.Multiline = true;
        this.memoInfo.Name = "memoInfo";
        this.memoInfo.ReadOnly = true;
        this.memoInfo.ScrollBars = ScrollBars.Vertical;
        this.memoInfo.Size = new Size(294, 158);
        this.memoInfo.WordWrap = true;

        // ctxFoundCode
        this.ctxFoundCode.Items.AddRange(new ToolStripItem[] {
            this.ctxReplace,
            this.ctxShowDisasm,
            this.ctxAddToCodeList,
            this.ctxMoreInfo,
            this.toolStripSeparator1,
            this.ctxSelectAll,
            this.toolStripSeparator2,
            this.ctxSaveToFile,
            this.ctxCopyToClipboard
        });
        this.ctxFoundCode.Name = "ctxFoundCode";
        this.ctxFoundCode.Size = new Size(300, 186);

        // ctxReplace
        this.ctxReplace.Text = "Replace with code that does nothing (NOP)";
        this.ctxReplace.Click += new EventHandler(this.BtnReplace_Click);

        // ctxShowDisasm
        this.ctxShowDisasm.Text = "Show this address in the disassembler";
        this.ctxShowDisasm.ShortcutKeys = Keys.Control | Keys.D;
        this.ctxShowDisasm.Click += new EventHandler(this.BtnShowDisasm_Click);

        // ctxAddToCodeList
        this.ctxAddToCodeList.Text = "Add to the codelist";
        this.ctxAddToCodeList.Click += new EventHandler(this.BtnAddToCodeList_Click);

        // ctxMoreInfo
        this.ctxMoreInfo.Text = "More Info";
        this.ctxMoreInfo.Font = new Font(this.ctxMoreInfo.Font, FontStyle.Bold);
        this.ctxMoreInfo.Click += new EventHandler(this.BtnMoreInfo_Click);

        // ctxSelectAll
        this.ctxSelectAll.Text = "Select all";
        this.ctxSelectAll.ShortcutKeys = Keys.Control | Keys.A;
        this.ctxSelectAll.Click += new EventHandler(this.CtxSelectAll_Click);

        // ctxSaveToFile
        this.ctxSaveToFile.Text = "Save selection to file";
        this.ctxSaveToFile.Click += new EventHandler(this.CtxSaveToFile_Click);

        // ctxCopyToClipboard
        this.ctxCopyToClipboard.Text = "Copy selection to clipboard";
        this.ctxCopyToClipboard.ShortcutKeys = Keys.Control | Keys.C;
        this.ctxCopyToClipboard.Click += new EventHandler(this.CtxCopyToClipboard_Click);

        // FoundCodeForm
        this.AutoScaleDimensions = new SizeF(7F, 15F);
        this.AutoScaleMode = AutoScaleMode.Font;
        this.CancelButton = this.btnOK;
        this.ClientSize = new Size(600, 420);
        this.Controls.Add(this.pnlLeft);
        this.Controls.Add(this.pnlRight);
        this.MinimumSize = new Size(450, 300);
        this.Name = "FoundCodeForm";
        this.StartPosition = FormStartPosition.CenterParent;
        this.Text = "The following opcodes changed the selected address";

        this.pnlRight.ResumeLayout(false);
        this.pnlButtons.ResumeLayout(false);
        this.pnlOK.ResumeLayout(false);
        this.pnlLeft.ResumeLayout(false);
        this.pnlLeft.PerformLayout();
        this.ctxFoundCode.ResumeLayout(false);
        this.ResumeLayout(false);
    }

    #endregion

    private Panel pnlRight;
    private Label lblDescription;
    private Panel pnlButtons;
    private Button btnReplace;
    private Button btnShowDisasm;
    private Button btnAddToCodeList;
    private Button btnMoreInfo;
    private Panel pnlOK;
    private Button btnOK;
    private Panel pnlLeft;
    private ListView lvFoundCode;
    private ColumnHeader colCount;
    private ColumnHeader colInstruction;
    private Splitter splitter;
    private TextBox memoInfo;
    private ContextMenuStrip ctxFoundCode;
    private ToolStripMenuItem ctxReplace;
    private ToolStripMenuItem ctxShowDisasm;
    private ToolStripMenuItem ctxAddToCodeList;
    private ToolStripMenuItem ctxMoreInfo;
    private ToolStripSeparator toolStripSeparator1;
    private ToolStripMenuItem ctxSelectAll;
    private ToolStripSeparator toolStripSeparator2;
    private ToolStripMenuItem ctxSaveToFile;
    private ToolStripMenuItem ctxCopyToClipboard;
}
