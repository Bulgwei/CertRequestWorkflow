# CertRequestWorkflow
Secure Replacement for ADCS CAWE

## IIS Web Forms prerequisites

`CertificateRequestSubmission.aspx` uses `System.DirectoryServices` and `System.DirectoryServices.AccountManagement`. These are .NET Framework assemblies and are not supplied by the standalone `dotnet` runtime.

Run the following on the IIS server from an elevated 64-bit PowerShell session:

```powershell
.\Test-WebPrerequisites.ps1 -RepairAspNet
```

The IIS application pool must use `.NET CLR Version v4.0`, have `Enable 32-Bit Applications` set to `False`, and be recycled after installation. If the server does not have .NET Framework 4.8, install the full .NET Framework 4.8 runtime first, then run the check again.

Do not remove the two `Assembly` directives from `CertificateRequestSubmission.aspx`; the page uses types from both assemblies and will fail during compilation without them.

CertRequestWorkflow provides a secure way of submitting certificate requests and separately additional Subject Alternative Names (SANs) to the specified online CA. The workflow consists of two scripts that will run periodically as scheduled tasks, referred to as Agents later in the documentation. 

•	Submit Agent (SubmitAgnt.ps1)

The submit agent is looking into a filesystem (CIFs)-based inbox and submits the content including additional SANs to the CA. At the CA the requests stay pending and waiting for approval of a Certificate Manager. During the pending state, possible additional SANs will be securely added to the request (without having EDITF_ATTRIBUTESUBJECTALTNAME2 on the policy module enabled).

Additionally, own, custom rules can be added to verify the initial request (e.g. only allow specific domain names or verify, if the subject is a valid object in the environment).

•	Enroll Agent (EnrollAgnt.ps)

The enroll agent verifies if a request has been issued/approved and exports the appropriate certificate onto a filesystem (CIFs)-based outbox.
The installation of the agents and their configuration is based on a XML-configuration file.
