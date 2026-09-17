// <file>
// <summary>
// Designer-generated code for SaveMemoryForm. Do not edit manually.
// </summary>
// </file>
namespace Nexus.UI.Forms;

partial class SaveMemoryForm
{
    private System.ComponentModel.IContainer components = null!;

    protected override void Dispose(bool disposing)
    {
        if (disposing && (components != null))
        {
            components.Dispose();
        }
        base.Dispose(disposing);
    }

    #region Windows Form Designer generated code

    private void InitializeComponent()
    {
        this.components = new System.ComponentModel.Container();

        this.lblInstructions = new Label();
        this.lbRegions = new ListBox();
        this.pnlRight = new Panel();
        this.lblFrom = new Label();
        this.txtFrom = new TextBox();
        this.lblTo = new Label();
        this.txtTo = new TextBox();
        this.btnAdd = new Button();
        this.pnlBottom = new Panel();
        this.chkNoHeader = new CheckBox();
        this.btnSave = new Button();
        this.btnCancel = new Button();
        this.ctxRegions = new ContextMenuStrip(this.components);
        this.ctxClearList = new ToolStripMenuItem();

        this.pnlRight.SuspendLayout();
        this.pnlBottom.SuspendLayout();
        this.ctxRegions.SuspendLayout();
        this.SuspendLayout();

        // lblInstructions
        this.lblInstructions.Dock = DockStyle.Top;
        this.lblInstructions.Location = new Point(0, 0);
        this.lblInstructions.Name = "lblInstructions";
        this.lblInstructions.Padding = new Padding(5, 5, 5, 5);
        this.lblInstructions.Size = new Size(284, 30);
        this.lblInstructions.Text = "Add the region(s) of memory you want to save:";

        // lbRegions
        this.lbRegions.Dock = DockStyle.Fill;
        this.lbRegions.Font = new Font("Consolas", 9F);
        this.lbRegions.FormattingEnabled = true;
        this.lbRegions.ItemHeight = 14;
        this.lbRegions.Location = new Point(0, 30);
        this.lbRegions.Name = "lbRegions";
        this.lbRegions.Size = new Size(174, 185);
        this.lbRegions.ContextMenuStrip = this.ctxRegions;
        this.lbRegions.DoubleClick += new EventHandler(this.LbRegions_DoubleClick);

        // pnlRight
        this.pnlRight.Controls.Add(this.lblFrom);
        this.pnlRight.Controls.Add(this.txtFrom);
        this.pnlRight.Controls.Add(this.lblTo);
        this.pnlRight.Controls.Add(this.txtTo);
        this.pnlRight.Controls.Add(this.btnAdd);
        this.pnlRight.Dock = DockStyle.Right;
        this.pnlRight.Location = new Point(174, 30);
        this.pnlRight.Name = "pnlRight";
        this.pnlRight.Size = new Size(110, 185);

        // lblFrom
        this.lblFrom.AutoSize = true;
        this.lblFrom.Location = new Point(10, 5);
        this.lblFrom.Name = "lblFrom";
        this.lblFrom.Size = new Size(35, 15);
        this.lblFrom.Text = "From:";

        // txtFrom
        this.txtFrom.Location = new Point(10, 23);
        this.txtFrom.MaxLength = 16;
        this.txtFrom.Name = "txtFrom";
        this.txtFrom.Size = new Size(90, 23);
        this.txtFrom.TabIndex = 0;
        this.txtFrom.CharacterCasing = CharacterCasing.Upper;

        // lblTo
        this.lblTo.AutoSize = true;
        this.lblTo.Location = new Point(10, 51);
        this.lblTo.Name = "lblTo";
        this.lblTo.Size = new Size(22, 15);
        this.lblTo.Text = "To:";

        // txtTo
        this.txtTo.Location = new Point(10, 69);
        this.txtTo.MaxLength = 16;
        this.txtTo.Name = "txtTo";
        this.txtTo.Size = new Size(90, 23);
        this.txtTo.TabIndex = 1;
        this.txtTo.CharacterCasing = CharacterCasing.Upper;

        // btnAdd
        this.btnAdd.Location = new Point(17, 100);
        this.btnAdd.Name = "btnAdd";
        this.btnAdd.Size = new Size(80, 32);
        this.btnAdd.TabIndex = 2;
        this.btnAdd.Text = "Add";
        this.btnAdd.UseVisualStyleBackColor = true;
        this.btnAdd.Click += new EventHandler(this.BtnAdd_Click);

        // pnlBottom
        this.pnlBottom.Controls.Add(this.chkNoHeader);
        this.pnlBottom.Controls.Add(this.btnSave);
        this.pnlBottom.Controls.Add(this.btnCancel);
        this.pnlBottom.Dock = DockStyle.Bottom;
        this.pnlBottom.Location = new Point(0, 215);
        this.pnlBottom.Name = "pnlBottom";
        this.pnlBottom.Size = new Size(284, 65);

        // chkNoHeader
        this.chkNoHeader.AutoSize = true;
        this.chkNoHeader.Location = new Point(10, 40);
        this.chkNoHeader.Name = "chkNoHeader";
        this.chkNoHeader.Size = new Size(210, 19);
        this.chkNoHeader.Text = "Don't include header in file (raw data)";

        // btnSave
        this.btnSave.Location = new Point(60, 8);
        this.btnSave.Name = "btnSave";
        this.btnSave.Size = new Size(80, 32);
        this.btnSave.TabIndex = 3;
        this.btnSave.Text = "Save";
        this.btnSave.UseVisualStyleBackColor = true;
        this.btnSave.Click += new EventHandler(this.BtnSave_Click);

        // btnCancel
        this.btnCancel.DialogResult = DialogResult.Cancel;
        this.btnCancel.Location = new Point(145, 8);
        this.btnCancel.Name = "btnCancel";
        this.btnCancel.Size = new Size(80, 32);
        this.btnCancel.TabIndex = 4;
        this.btnCancel.Text = "Cancel";
        this.btnCancel.UseVisualStyleBackColor = true;
        this.btnCancel.Click += new EventHandler(this.BtnCancel_Click);

        // ctxRegions
        this.ctxRegions.Items.AddRange(new ToolStripItem[] { this.ctxClearList });
        this.ctxRegions.Name = "ctxRegions";
        this.ctxRegions.Size = new Size(120, 26);

        // ctxClearList
        this.ctxClearList.Text = "Clear list";
        this.ctxClearList.Click += new EventHandler(this.CtxClearList_Click);

        // SaveMemoryForm
        this.AcceptButton = this.btnSave;
        this.AutoScaleDimensions = new SizeF(7F, 15F);
        this.AutoScaleMode = AutoScaleMode.Font;
        this.CancelButton = this.btnCancel;
        this.ClientSize = new Size(284, 280);
        this.Controls.Add(this.lbRegions);
        this.Controls.Add(this.pnlRight);
        this.Controls.Add(this.lblInstructions);
        this.Controls.Add(this.pnlBottom);
        this.FormBorderStyle = FormBorderStyle.FixedDialog;
        this.MaximizeBox = false;
        this.MinimizeBox = false;
        this.Name = "SaveMemoryForm";
        this.StartPosition = FormStartPosition.CenterParent;
        this.Text = "Save memory region";

        this.pnlRight.ResumeLayout(false);
        this.pnlRight.PerformLayout();
        this.pnlBottom.ResumeLayout(false);
        this.pnlBottom.PerformLayout();
        this.ctxRegions.ResumeLayout(false);
        this.ResumeLayout(false);
    }

    #endregion

    private Label lblInstructions;
    private ListBox lbRegions;
    private Panel pnlRight;
    private Label lblFrom;
    private TextBox txtFrom;
    private Label lblTo;
    private TextBox txtTo;
    private Button btnAdd;
    private Panel pnlBottom;
    private CheckBox chkNoHeader;
    private Button btnSave;
    private Button btnCancel;
    private ContextMenuStrip ctxRegions;
    private ToolStripMenuItem ctxClearList;
}
