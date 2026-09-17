// <file>
// <summary>
// Designer-generated code for LoadMemoryForm. Do not edit manually.
// </summary>
// </file>
namespace Nexus.UI.Forms;

partial class LoadMemoryForm
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
        this.lbRegions = new ListBox();
        this.lblAddress = new Label();
        this.txtAddress = new TextBox();
        this.btnEdit = new Button();
        this.btnOK = new Button();
        this.btnCancel = new Button();

        this.SuspendLayout();

        // lbRegions
        this.lbRegions.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        this.lbRegions.Font = new Font("Consolas", 9F);
        this.lbRegions.FormattingEnabled = true;
        this.lbRegions.ItemHeight = 14;
        this.lbRegions.Location = new Point(0, 0);
        this.lbRegions.Name = "lbRegions";
        this.lbRegions.Size = new Size(235, 74);
        this.lbRegions.TabIndex = 0;
        this.lbRegions.SelectedIndexChanged += new EventHandler(this.LbRegions_SelectedIndexChanged);

        // lblAddress
        this.lblAddress.AutoSize = true;
        this.lblAddress.Location = new Point(5, 82);
        this.lblAddress.Name = "lblAddress";
        this.lblAddress.Size = new Size(95, 15);
        this.lblAddress.Text = "Target Address:";

        // txtAddress
        this.txtAddress.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        this.txtAddress.Location = new Point(5, 100);
        this.txtAddress.MaxLength = 16;
        this.txtAddress.Name = "txtAddress";
        this.txtAddress.Size = new Size(175, 23);
        this.txtAddress.TabIndex = 1;
        this.txtAddress.CharacterCasing = CharacterCasing.Upper;

        // btnEdit
        this.btnEdit.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        this.btnEdit.Location = new Point(185, 99);
        this.btnEdit.Name = "btnEdit";
        this.btnEdit.Size = new Size(45, 25);
        this.btnEdit.TabIndex = 2;
        this.btnEdit.Text = "Edit";
        this.btnEdit.UseVisualStyleBackColor = true;
        this.btnEdit.Click += new EventHandler(this.BtnEdit_Click);

        // btnOK
        this.btnOK.Location = new Point(40, 135);
        this.btnOK.Name = "btnOK";
        this.btnOK.Size = new Size(80, 32);
        this.btnOK.TabIndex = 3;
        this.btnOK.Text = "OK";
        this.btnOK.UseVisualStyleBackColor = true;
        this.btnOK.Click += new EventHandler(this.BtnOK_Click);

        // btnCancel
        this.btnCancel.DialogResult = DialogResult.Cancel;
        this.btnCancel.Location = new Point(120, 135);
        this.btnCancel.Name = "btnCancel";
        this.btnCancel.Size = new Size(80, 32);
        this.btnCancel.TabIndex = 4;
        this.btnCancel.Text = "Cancel";
        this.btnCancel.UseVisualStyleBackColor = true;
        this.btnCancel.Click += new EventHandler(this.BtnCancel_Click);

        // LoadMemoryForm
        this.AcceptButton = this.btnOK;
        this.AutoScaleDimensions = new SizeF(7F, 15F);
        this.AutoScaleMode = AutoScaleMode.Font;
        this.CancelButton = this.btnCancel;
        this.ClientSize = new Size(235, 170);
        this.Controls.Add(this.lbRegions);
        this.Controls.Add(this.lblAddress);
        this.Controls.Add(this.txtAddress);
        this.Controls.Add(this.btnEdit);
        this.Controls.Add(this.btnOK);
        this.Controls.Add(this.btnCancel);
        this.FormBorderStyle = FormBorderStyle.FixedDialog;
        this.MaximizeBox = false;
        this.MinimizeBox = false;
        this.Name = "LoadMemoryForm";
        this.StartPosition = FormStartPosition.CenterParent;
        this.Text = "Load Memory Region";

        this.ResumeLayout(false);
        this.PerformLayout();
    }

    #endregion

    private ListBox lbRegions;
    private Label lblAddress;
    private TextBox txtAddress;
    private Button btnEdit;
    private Button btnOK;
    private Button btnCancel;
}
