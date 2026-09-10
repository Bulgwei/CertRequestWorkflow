<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Linq" %>
<%@ Import Namespace="System.Security" %>
<%@ Import Namespace="Microsoft.Win32" %>
<%@ Import Namespace="System.Text" %>

<script runat="server">
    private const string RegistryPath = @"SYSTEM\CurrentControlSet\Services\CertSvc\EnrollAgents";
    private const string UploadSessionKey = "CertificateRequestUpload";
    private const string UploadFileNameSessionKey = "CertificateRequestUploadFileName";
    private const string ConfigSessionKey = "CertificateRequestConfig";
    private const string SelectedCaSessionKey = "CertificateRequestSelectedCa";
    private const string SelectedTemplateSessionKey = "CertificateRequestSelectedTemplate";
    private const string SanSessionKey = "CertificateRequestSan";

    [Serializable]
    private sealed class RequestConfig
    {
        public string Inbox;
        public string DefaultTemplate;
        public string[] Templates;
        public string[] Cas;
    }

    private RequestConfig Config
    {
        get
        {
            var value = Session[ConfigSessionKey] as RequestConfig;
            if (value == null)
            {
                value = ReadConfig();
                Session[ConfigSessionKey] = value;
            }
            return value;
        }
    }

    protected void Page_Load(object sender, EventArgs e)
    {
        try
        {
            if (Request.QueryString["view"] == "details")
            {
                RenderDetails(false);
                return;
            }

            if (!IsPostBack)
            {
                BindConfiguration();
                RestoreSubmissionSettings();
                var hasStoredUpload = HasStoredUpload();
                detailsTab.Enabled = hasStoredUpload;
                submitButton.Enabled = hasStoredUpload;
                selectedFileName.InnerText = hasStoredUpload
                    ? "Chosen request: " + Convert.ToString(Session[UploadFileNameSessionKey])
                    : "";
                status.Text = hasStoredUpload
                    ? "Request retained on the server. Submit will use the chosen request unless a new file is selected."
                    : "Select a .csr or .req file to begin.";
            }
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private RequestConfig ReadConfig()
    {
        using (var key = Registry.LocalMachine.OpenSubKey(RegistryPath, false))
        {
            if (key == null)
                throw new InvalidOperationException("The EnrollAgents registry configuration was not found.");

            var inbox = Convert.ToString(key.GetValue("WorkingDirectory", ""));
            var defaultTemplate = Convert.ToString(key.GetValue("DefaultTemplate", ""));
            var templates = (key.GetValue("Templates") as string[]) ?? new string[0];
            var caText = Convert.ToString(key.GetValue("CaName", ""));
            var cas = caText.Split(new[] { ';', '|', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                            .Select(x => x.Trim())
                            .Where(x => x.Length > 0)
                            .Distinct(StringComparer.OrdinalIgnoreCase)
                            .ToArray();

            if (String.IsNullOrWhiteSpace(inbox))
                throw new InvalidOperationException("WorkingDirectory is empty in the EnrollAgents registry configuration.");
            if (cas.Length == 0)
                throw new InvalidOperationException("CaName is empty in the EnrollAgents registry configuration.");

            return new RequestConfig
            {
                Inbox = Path.Combine(inbox, "inbox"),
                DefaultTemplate = defaultTemplate,
                Templates = templates.Where(x => !String.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                Cas = cas
            };
        }
    }

    private void BindConfiguration()
    {
        caList.Items.Clear();
        foreach (var ca in Config.Cas)
            caList.Items.Add(new System.Web.UI.WebControls.ListItem(ca, ca));

        templateList.Items.Clear();
        templateList.Items.Add(new System.Web.UI.WebControls.ListItem("Use configured default (" + Config.DefaultTemplate + ")", ""));
        foreach (var template in Config.Templates)
            templateList.Items.Add(new System.Web.UI.WebControls.ListItem(template, template));
    }

    private void SaveSubmissionSettings()
    {
        Session[SelectedCaSessionKey] = caList.SelectedValue;
        Session[SelectedTemplateSessionKey] = templateList.SelectedValue;
        Session[SanSessionKey] = sanInput.Value ?? "";
    }

    private void RestoreSubmissionSettings()
    {
        var selectedCa = Convert.ToString(Session[SelectedCaSessionKey]);
        if (!String.IsNullOrWhiteSpace(selectedCa) && caList.Items.FindByValue(selectedCa) != null)
            caList.SelectedValue = selectedCa;

        var selectedTemplate = Convert.ToString(Session[SelectedTemplateSessionKey]);
        if (templateList.Items.FindByValue(selectedTemplate) != null)
            templateList.SelectedValue = selectedTemplate;

        sanInput.Value = Convert.ToString(Session[SanSessionKey]);
        selectedFileName.InnerText = HasStoredUpload()
            ? "Chosen request: " + Convert.ToString(Session[UploadFileNameSessionKey])
            : "";
    }

    protected void RequestFileChanged(object sender, EventArgs e)
    {
        submitButton.Enabled = requestUpload.HasFile;
        status.Text = requestUpload.HasFile ? "File selected. Parse it before submitting." : "Select a .csr or .req file to begin.";
    }

    protected void ParseRequest(object sender, EventArgs e)
    {
        try
        {
            ValidateUpload();
            SaveSubmissionSettings();
            if (requestUpload.HasFile)
                SaveUploadToSession();
            selectedFileName.InnerText = "Chosen request: " + Convert.ToString(Session[UploadFileNameSessionKey]);
            detailsTab.Enabled = true;
            submitButton.Enabled = true;
            RenderDetails(true);
            ClientScript.RegisterStartupScript(GetType(), "showRequestDetails", "showRequestDetails();", true);
        }
        catch (Exception ex)
        {
            detailsPage.Visible = true;
            detailsOutput.InnerText = "Request parsing failed: " + ex.Message;
            ShowError(ex);
            ClientScript.RegisterStartupScript(GetType(), "showRequestDetailsError", "showRequestDetails();", true);
        }
    }

    protected void SubmitRequest(object sender, EventArgs e)
    {
        var submissionSucceeded = false;
        try
        {
            ValidateUpload();
            var selectedCa = caList.SelectedValue;
            if (String.IsNullOrWhiteSpace(selectedCa) || !Config.Cas.Contains(selectedCa, StringComparer.OrdinalIgnoreCase))
                throw new InvalidOperationException("Select a configured CA.");

            var source = requestUpload.HasFile ? SaveUploadToSession() : GetStoredUploadPath();
            var name = Path.GetFileNameWithoutExtension(source);
            var safeName = MakeSafeName(name);
            var destinationBase = Path.Combine(Config.Inbox, safeName + "-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Config.Inbox);

            var requestPath = destinationBase + ".csr";
            var sanPath = destinationBase + ".san";
            var templatePath = destinationBase + ".tmpl";
            var caPath = destinationBase + ".ca";
            var temporaryRequestPath = requestPath + ".uploading";
            var temporarySanPath = sanPath + ".uploading";
            var temporaryTemplatePath = templatePath + ".uploading";
            var temporaryCaPath = caPath + ".uploading";

            try
            {
                File.Copy(source, temporaryRequestPath, false);
                File.WriteAllText(temporarySanPath, NormalizeLines(sanInput.Value), new UTF8Encoding(false));
                File.WriteAllText(temporaryTemplatePath, String.IsNullOrWhiteSpace(templateList.SelectedValue) ? Config.DefaultTemplate : templateList.SelectedValue, new UTF8Encoding(false));
                File.WriteAllText(temporaryCaPath, selectedCa, new UTF8Encoding(false));
                File.Move(temporarySanPath, sanPath);
                File.Move(temporaryTemplatePath, templatePath);
                File.Move(temporaryCaPath, caPath);
                File.Move(temporaryRequestPath, requestPath);
            }
            catch
            {
                foreach (var path in new[] { requestPath, sanPath, templatePath, caPath, temporaryRequestPath, temporarySanPath, temporaryTemplatePath, temporaryCaPath })
                {
                    if (File.Exists(path))
                        File.Delete(path);
                }
                throw;
            }

            DeleteSessionUpload();
            ClearSubmissionSettings();
            status.CssClass = "status success";
            status.Text = "Success: Certificate request submitted to the inbox. The form will reset in 5 seconds.";
            submitButton.Enabled = false;
            submissionSucceeded = true;
            if (submissionSucceeded)
                ClientScript.RegisterStartupScript(GetType(), "resetForm", "window.sessionStorage.removeItem('certificateRequestSubmissionState'); window.setTimeout(function(){ document.getElementById('" + form1.ClientID + "').reset(); window.location.href='" + ResolveUrl(Request.Path) + "'; }, 5000);", true);
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private string SaveUploadToSession()
    {
        var existing = Session[UploadSessionKey] as string;
        if (!String.IsNullOrWhiteSpace(existing) && File.Exists(existing))
            File.Delete(existing);

        var extension = Path.GetExtension(requestUpload.FileName).ToLowerInvariant();
        var path = Path.Combine(Path.GetTempPath(), "CertRequest-" + Guid.NewGuid().ToString("N") + extension);
        requestUpload.SaveAs(path);
        Session[UploadSessionKey] = path;
        Session[UploadFileNameSessionKey] = Path.GetFileName(requestUpload.FileName);
        return path;
    }

    private bool HasStoredUpload()
    {
        var path = Session[UploadSessionKey] as string;
        return !String.IsNullOrWhiteSpace(path) && File.Exists(path);
    }

    private string GetStoredUploadPath()
    {
        if (!HasStoredUpload())
            throw new InvalidOperationException("Select a certificate request file.");
        return (string)Session[UploadSessionKey];
    }

    private void ValidateUpload()
    {
        if (!requestUpload.HasFile && !HasStoredUpload())
            throw new InvalidOperationException("Select a certificate request file.");
        if (!requestUpload.HasFile)
            return;
        var extension = Path.GetExtension(requestUpload.FileName).ToLowerInvariant();
        if (extension != ".csr" && extension != ".req")
            throw new InvalidOperationException("Only .csr and .req files are accepted.");
        if (requestUpload.PostedFile.ContentLength == 0)
            throw new InvalidOperationException("The selected request file is empty.");
    }

    private void RenderDetails(bool keepSubmissionPageVisible)
    {
        var path = Session[UploadSessionKey] as string;
        if (String.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            detailsOutput.InnerText = "The uploaded request is no longer available. Return to the submission page and select it again.";
            return;
        }

        detailsTitle.InnerText = "Certificate Request Details";
        detailsPage.Visible = true;
        submissionPage.Visible = keepSubmissionPageVisible;
        var dump = RunCertUtil(path);
        detailsSummary.InnerHtml = BuildRequestSummary(dump);
        detailsOutput.InnerText = dump;
    }

    private string BuildRequestSummary(string dump)
    {
        var fields = new[]
        {
            new { Name = "Subject", Patterns = new[] { "Subject" } },
            new { Name = "Key Algorithm", Patterns = new[] { "Public Key Algorithm", "Key Algorithm" } },
            new { Name = "Key Length", Patterns = new[] { "Public Key Length", "Key Length" } },
            new { Name = "Key Usage", Patterns = new[] { "Key Usage" } },
            new { Name = "Enhanced Key Usage", Patterns = new[] { "Enhanced Key Usage" } },
            new { Name = "Subject Alternative Names", Patterns = new[] { "Subject Alternative Name", "Subject Alternative Names" } }
        };

        var html = new StringBuilder("<table class=\"request-summary\"><tbody>");
        foreach (var field in fields)
        {
            html.Append("<tr><th>").Append(Server.HtmlEncode(field.Name)).Append("</th><td>")
                .Append(BuildSummaryValue(FindDumpValue(dump, field.Patterns), field.Name == "Subject Alternative Names"))
                .Append("</td></tr>");
        }
        return html.Append("</tbody></table>").ToString();
    }

    private string BuildSummaryValue(string value, bool oneValuePerLine)
    {
        if (!oneValuePerLine)
            return Server.HtmlEncode(value);

        return String.Join("<br />", (value ?? "").Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries)
            .Select(Server.HtmlEncode));
    }

    private static string FindDumpValue(string dump, string[] labels)
    {
        var lines = (dump ?? "").Replace("\r", "").Split('\n');
        for (var lineIndex = 0; lineIndex < lines.Length; lineIndex++)
        {
            var line = lines[lineIndex];
            var trimmed = line.Trim();
            var label = labels.FirstOrDefault(x => IsDumpLabel(trimmed, x));
            if (label == null)
                continue;

            var isSubject = labels.Contains("Subject");
            var isKeyAlgorithm = labels.Contains("Public Key Algorithm") || labels.Contains("Key Algorithm");

            var labelEnd = label.Length;
            var inlineValue = trimmed.Length > labelEnd && (trimmed[labelEnd] == ':' || trimmed[labelEnd] == '=')
                ? trimmed.Substring(labelEnd + 1).Trim()
                : "";
            var values = new List<string>();
            if (!String.IsNullOrWhiteSpace(inlineValue) && !IsExcludedMetadata(inlineValue, isSubject, isKeyAlgorithm))
                values.Add(inlineValue);

            var labelIndent = line.Length - line.TrimStart().Length;
            for (var valueIndex = lineIndex + 1; valueIndex < lines.Length; valueIndex++)
            {
                var valueLine = lines[valueIndex];
                if (String.IsNullOrWhiteSpace(valueLine))
                    continue;

                var valueIndent = valueLine.Length - valueLine.TrimStart().Length;
                if (valueIndent <= labelIndent)
                    break;

                var value = valueLine.Trim();
                if (!IsExcludedMetadata(value, isSubject, isKeyAlgorithm))
                    values.Add(value);
            }

            if (values.Count > 0)
                return isSubject || isKeyAlgorithm
                    ? values[0]
                    : String.Join("; ", values.Distinct(StringComparer.OrdinalIgnoreCase));
        }
        return "Not found";
    }

    private static bool IsExcludedMetadata(string value, bool isSubject, bool isKeyAlgorithm)
    {
        if (isSubject)
            return value.StartsWith("Name:", StringComparison.OrdinalIgnoreCase)
                || value.StartsWith("Name Hash", StringComparison.OrdinalIgnoreCase)
                || value.StartsWith("Hash:", StringComparison.OrdinalIgnoreCase);

        return isKeyAlgorithm && value.StartsWith("Algorithm Parameters", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDumpLabel(string line, string label)
    {
        return line.Equals(label, StringComparison.OrdinalIgnoreCase)
            || line.StartsWith(label + ":", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith(label + "=", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith(label + " =", StringComparison.OrdinalIgnoreCase);
    }

    private string RunCertUtil(string path)
    {
        var start = new ProcessStartInfo
        {
            FileName = "certutil.exe",
            Arguments = "-dump " + QuoteArgument(path),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        using (var process = Process.Start(start))
        {
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit(30000);
            if (process.ExitCode != 0)
                throw new InvalidOperationException("certutil could not parse the request: " + error.Trim());
            return output + (String.IsNullOrWhiteSpace(error) ? "" : Environment.NewLine + error);
        }
    }

    private static string QuoteArgument(string value)
    {
        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    private static string NormalizeLines(string value)
    {
        return String.Join(Environment.NewLine, (value ?? "").Replace("\r", "").Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0)) + Environment.NewLine;
    }

    private static string MakeSafeName(string value)
    {
        var invalid = new string(Path.GetInvalidFileNameChars()) + " .";
        var safe = new string((value ?? "request").Where(c => invalid.IndexOf(c) < 0).ToArray()).Trim();
        return String.IsNullOrWhiteSpace(safe) ? "request" : safe;
    }

    private void DeleteSessionUpload()
    {
        var path = Session[UploadSessionKey] as string;
        if (!String.IsNullOrWhiteSpace(path) && File.Exists(path))
            File.Delete(path);
        Session.Remove(UploadSessionKey);
        Session.Remove(UploadFileNameSessionKey);
    }

    private void ClearSubmissionSettings()
    {
        Session.Remove(SelectedCaSessionKey);
        Session.Remove(SelectedTemplateSessionKey);
        Session.Remove(SanSessionKey);
    }

    private void ShowError(Exception ex)
    {
        status.CssClass = "status error";
        status.Text = "Failure: " + Server.HtmlEncode(ex.Message);
    }
</script>

<!DOCTYPE html>
<html lang="en">
<head runat="server">
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title><%= Request.QueryString["view"] == "details" ? "Certificate Request Details" : "Certificate Request Submission" %></title>
    <script>
        var submissionStateKey = 'certificateRequestSubmissionState';

        function persistSubmissionForm() {
            var upload = document.getElementById('<%= requestUpload.ClientID %>');
            var state = {
                ca: document.getElementById('<%= caList.ClientID %>').value,
                template: document.getElementById('<%= templateList.ClientID %>').value,
                san: document.getElementById('<%= sanInput.ClientID %>').value,
                fileName: upload && upload.files.length ? upload.files[0].name : ''
            };
            window.sessionStorage.setItem(submissionStateKey, JSON.stringify(state));
        }

        function restoreSubmissionForm() {
            var saved = window.sessionStorage.getItem(submissionStateKey);
            if (!saved) return;

            try {
                var state = JSON.parse(saved);
                var ca = document.getElementById('<%= caList.ClientID %>');
                var template = document.getElementById('<%= templateList.ClientID %>');
                var san = document.getElementById('<%= sanInput.ClientID %>');
                var fileName = document.getElementById('<%= selectedFileName.ClientID %>');
                if (ca && state.ca !== undefined) ca.value = state.ca;
                if (template && state.template !== undefined) template.value = state.template;
                if (san && state.san !== undefined) san.value = state.san;
                if (fileName && state.fileName) fileName.textContent = 'Chosen request: ' + state.fileName;
            } catch (error) {
                window.sessionStorage.removeItem(submissionStateKey);
            }
        }

        function toggleRequestActions(input) {
            var enabled = !!(input && input.value);
            var fileName = document.getElementById('<%= selectedFileName.ClientID %>');
            if (fileName) fileName.textContent = enabled && input.files.length ? 'Chosen request: ' + input.files[0].name : '';
            var actionIds = ['<%= detailsTab.ClientID %>', '<%= submitButton.ClientID %>'];
            for (var index = 0; index < actionIds.length; index++) {
                var action = document.getElementById(actionIds[index]);
                if (!action) continue;
                action.disabled = !enabled;
                if (enabled) {
                    action.removeAttribute('disabled');
                } else {
                    action.setAttribute('disabled', 'disabled');
                }
            }
        }

        function showRequestDetails() {
            var details = document.getElementById('<%= detailsPage.ClientID %>');
            document.getElementById('submissionTabPanel').style.display = 'none';
            details.style.display = 'block';
            details.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        function returnToSubmission() {
            document.getElementById('<%= detailsPage.ClientID %>').style.display = 'none';
            document.getElementById('submissionTabPanel').style.display = 'block';
            window.scrollTo(0, 0);
        }

        function showSubmissionTab() {
            returnToSubmission();
        }

        window.addEventListener('DOMContentLoaded', function () {
            if (window.location.search.indexOf('view=details') === -1) {
                restoreSubmissionForm();
            }
        });

        function showRequestTab(tabName) {
            var summary = document.getElementById('requestSummaryTab');
            var raw = document.getElementById('requestRawTab');
            var summaryButton = document.getElementById('requestSummaryButton');
            var rawButton = document.getElementById('requestRawButton');
            var showSummary = tabName === 'summary';
            summary.hidden = !showSummary;
            raw.hidden = showSummary;
            summaryButton.setAttribute('aria-selected', showSummary ? 'true' : 'false');
            rawButton.setAttribute('aria-selected', showSummary ? 'false' : 'true');
        }
    </script>
    <style>
        :root { color-scheme: light; --ink: #17212b; --muted: #596774; --line: #c8d0d6; --accent: #006d77; --accent-dark: #00515a; --paper: #f7f4ee; --panel: #fffdf9; --danger: #a33a2b; --success: #236b4a; }
        * { box-sizing: border-box; }
        body { margin: 0; background: radial-gradient(circle at 85% 10%, #dceeea 0, transparent 28rem), var(--paper); color: var(--ink); font: 16px/1.5 Consolas, 'Courier New', monospace; }
        main { width: min(1120px, calc(100% - 48px)); margin: 32px auto; }
        .page-header { margin-bottom: 24px; }
        .page-header h1 { margin-bottom: 8px; }
        h1 { margin: 0 0 8px; font-size: clamp(1.2rem, 5.5vw, 3.5rem); line-height: 1.05; letter-spacing: 0; white-space: nowrap; }
        .lede { color: var(--muted); margin: 0 0 28px; }
        .panel { background: rgba(255,253,249,.94); border: 1px solid var(--line); border-top: 5px solid var(--accent); padding: clamp(20px, 4vw, 42px); box-shadow: 0 18px 45px rgba(23,33,43,.09); }
        .grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 20px 24px; }
        .grid > * { min-width: 0; }
        .full { grid-column: 1 / -1; }
        label { display: block; font-weight: bold; margin-bottom: 7px; }
        input[type=file], select, textarea { width: 100%; border: 1px solid var(--line); border-radius: 2px; background: #fff; color: var(--ink); padding: 10px 12px; font: inherit; }
        textarea { min-height: 130px; resize: vertical; }
        .file-row { display: flex; align-items: center; gap: 16px; margin-top: 5px; }
        .file-row input[type=file] { width: auto; flex: 0 1 auto; }
        .retained-file { display: block; min-width: 0; flex: 1 1 auto; border: 1px solid var(--line); border-radius: 2px; background: #eef2f1; color: var(--muted); padding: 10px 12px; font: normal 16px/1.5 Consolas, 'Courier New', monospace; overflow-wrap: anywhere; }
        .help { color: var(--muted); font-size: .9rem; margin-top: 5px; }
        .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 28px; }
        .actions .parse-action { margin-left: auto; }
        button, input[type=submit], .link-button { border: 0; border-radius: 2px; background: var(--accent); color: #fff; cursor: pointer; padding: 14px 24px; font: bold 1.1rem Consolas, 'Courier New', monospace; text-decoration: none; }
        button:hover, input[type=submit]:hover, .link-button:hover { background: var(--accent-dark); }
        button:disabled, input[type=submit]:disabled { background: #aab4b8; cursor: not-allowed; }
        .secondary { background: #64727a; }
        .status { display: block; min-height: 28px; margin-top: 28px; padding: 12px 14px; border-left: 4px solid var(--accent); color: var(--muted); }
        .status.error { border-color: var(--danger); color: var(--danger); }
        .status.success { border-color: var(--success); color: var(--success); }
        .tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--line); margin-bottom: 16px; }
        .form-tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--line); margin-bottom: 28px; }
        .form-tabs .tab { border-bottom: 1px solid var(--line); }
        .form-tabs .tab[aria-selected="true"] { background: var(--panel); color: var(--accent-dark); font-weight: bold; }
        .tab { border: 1px solid var(--line); border-bottom: 0; background: #e7eceb; color: var(--ink); padding: 9px 14px; cursor: pointer; font: inherit; }
        .tab[aria-selected="true"] { background: var(--panel); color: var(--accent-dark); font-weight: bold; }
        .request-summary { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        .request-summary th, .request-summary td { border-bottom: 1px solid var(--line); padding: 10px 12px; text-align: left; vertical-align: top; }
        .request-summary th { width: 32%; }
        .details-panel { min-height: calc(100vh - 96px); margin-top: 120px !important; }
        .result-spacer { height: 96px; }
        .result-area { min-height: 520px; }
        .details-panel .tabs { margin-top: 0; }
        pre { max-height: 68vh; min-height: 320px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; background: #17212b; color: #e7f0ed; padding: 20px; font: 13px/1.45 Consolas, 'Courier New', monospace; }
        @media (max-width: 680px) { .grid { grid-template-columns: 1fr; } .full { grid-column: auto; } .file-row { align-items: stretch; flex-direction: column; gap: 8px; } .file-row input[type=file], .retained-file { width: 100%; } main { margin: 24px auto; } }
    </style>
</head>
<body>
    <main>
        <header class="page-header">
            <h1>Certificate Request Workflow</h1>
            <p class="lede">Submit and inspect certificate requests for the configured AD CS inbox.</p>
        </header>
        <section id="submissionPage" runat="server" class="panel">
            <form id="form1" runat="server" enctype="multipart/form-data">
                <div class="form-tabs" role="tablist">
                    <button type="button" class="tab" role="tab" aria-selected="true" onclick="showSubmissionTab();">Certificate Request Submission</button>
                    <asp:Button ID="detailsTab" runat="server" Text="Request Details" OnClick="ParseRequest" OnClientClick="persistSubmissionForm();" CssClass="tab tab-action" Enabled="false" />
                </div>
                <div id="submissionTabPanel" class="form-tab-panel">
                    <div class="grid">
                    <div>
                        <label for="caList">Certificate authority</label>
                        <asp:DropDownList ID="caList" runat="server" />
                    </div>
                    <div>
                        <label for="templateList">Certificate template</label>
                        <asp:DropDownList ID="templateList" runat="server" />
                    </div>
                    <div class="full">
                        <label for="requestUpload">Certificate request file</label>
                        <div class="help">Choose a .csr or .req file. Network locations available to this browser can be selected through the normal file picker.</div>
                        <div class="file-row">
                            <asp:FileUpload ID="requestUpload" runat="server" accept=".csr,.req" onchange="toggleRequestActions(this);" />
                            <label id="selectedFileName" runat="server" class="retained-file" aria-label="Chosen request"></label>
                        </div>
                    </div>
                    <div class="full">
                        <label for="sanInput">Subject Alternative Names</label>
                        <textarea id="sanInput" runat="server" placeholder="One DNS name or email address per line"></textarea>
                        <div class="help">Each non-empty line is written to the request's .san companion file.</div>
                    </div>
                    </div>
                    <div class="actions">
                    <asp:Button ID="submitButton" runat="server" Text="Submit" OnClick="SubmitRequest" OnClientClick="persistSubmissionForm();" Enabled="false" />
                    </div>
                    <div class="status-area">
                        <asp:Label ID="status" runat="server" CssClass="status" />
                    </div>
                </div>
                <section id="detailsPage" runat="server" class="details-panel" visible="false">
                    <h1 id="detailsTitle" runat="server">Certificate Request Details</h1>
                    <p class="lede">Full output from the Windows certificate request parser.</p>
                    <div class="result-area">
                        <div class="tabs" role="tablist">
                            <button id="requestSummaryButton" type="button" class="tab" role="tab" aria-selected="true" onclick="showRequestTab('summary');">Extracted fields</button>
                            <button id="requestRawButton" type="button" class="tab" role="tab" aria-selected="false" onclick="showRequestTab('raw');">Raw request dump</button>
                        </div>
                        <div id="requestSummaryTab" role="tabpanel">
                            <div id="detailsSummary" runat="server"></div>
                        </div>
                        <div id="requestRawTab" role="tabpanel" hidden="hidden">
                            <pre id="detailsOutput" runat="server"></pre>
                        </div>
                    </div>
                </section>
            </form>
        </section>
    </main>
</body>
</html>
