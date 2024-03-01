# ==============================================================================================
# THIS SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service. 
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample or documentation, even if Microsoft has been advised 
# of the possibility of such damages.
# ==============================================================================================
#
# version 1.1
# dev'd by andreas.luy@microsoft.com
#
#

$RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\EnrollAgents"

Function Get-XmlConfig {
    param (
        [Parameter(Mandatory=$True) ] [String]$ConfigFile
    )

    If (Test-Path $ConfigFile) {
        [XML]$XmlConfig = Get-Content $ConfigFile
        Return $XmlConfig
    } Else {
        #Write-Error "Error: Could not find configuration file $ConfigFile - Aborting."
        Write-Host "Error: Could not find configuration file $ConfigFile - Aborting."
        # fatal error so just quit.
        exit
    }

}

Function Use-Eventlog
{
    $Global:EventLog = (Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "EventlogName").EventlogName
    $Global:EventSource = (Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "EventSource").EventSource
    if (($UseEvtlog = (Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "UseEventlog").UseEventlog -eq 1 )) {
        if ((Get-EventLog -list).Log | where { $_ -eq $EventLog }) {
            $Global:WriteSuccessEvents = ((Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "WriteSuccessEvents").WriteSuccessEvents -eq 1)
            [int32]$Global:SubmitEventID = (Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "SubmitEventID").SubmitEventID
            [int32]$Global:FailEventID = (Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "FailEventID").FailEventID
            [int32]$Global:IssueEventID = (Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "IssueEventID").IssueEventID
            [int32]$Global:EnrollEventID = (Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "EnrollEventID").EnrollEventID
            $Global:SubmitEventMsg = (Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "SubmitEventMsg").SubmitEventMsg
            $Global:EnrollEventMsg = (Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "EnrollEventMsg").EnrollEventMsg
            $Global:FailedEventMsg = (Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "FailedEventMsg").FailedEventMsg
            $Global:DeniedEventMsg = (Get-ItemProperty -Path $RegistryRoot\Eventlog -Name "DeniedEventMsg").DeniedEventMsg
        } else {
            #no event log available to use - continuing without...
            $UseEvtlog = $false
        }
    }
    return $UseEvtlog
}

Function Use-Mail
{
    if ([boolean]$Global:UseAdminEmail = (Get-ItemProperty -Path $RegistryRoot\Email -Name "UseAdminEmail").UseAdminEmail) {
        $Global:AdminMailTo = (Get-ItemProperty -Path $RegistryRoot\Email -Name "AdminMailTo").AdminMailTo
        $Global:MailServer = (Get-ItemProperty -Path $RegistryRoot\Email -Name "SmtpServer").SmtpServer
        $Global:MailFrom = (Get-ItemProperty -Path $RegistryRoot\Email -Name "MailFrom").MailFrom
        $Global:MailUseSSL = if ((Get-ItemProperty -Path $RegistryRoot\Email -Name "UseSSL").UseSSL -ne 1) {
            $false
            [int32]$Global:MailPort = (Get-ItemProperty -Path $RegistryRoot\Email -Name "Port").Port
        } else {
            $true
            [int32]$Global:MailPort = (Get-ItemProperty -Path $RegistryRoot\Email -Name "SSlPort").SSlPort
        }
    }
    if (($UseMailInfo = (Get-ItemProperty -Path $RegistryRoot\Email -Name "UseMailInfo").UseMailInfo -eq 1 )) {
        $Global:MailServer = (Get-ItemProperty -Path $RegistryRoot\Email -Name "SmtpServer").SmtpServer
        $Global:MailFrom = (Get-ItemProperty -Path $RegistryRoot\Email -Name "MailFrom").MailFrom
        $Global:MailCC = (Get-ItemProperty -Path $RegistryRoot\Email -Name "MailCC").MailCC
        $Global:MailSubject = (Get-ItemProperty -Path $RegistryRoot\Email -Name "Subject").Subject
        $Global:MailUseSSL = if ((Get-ItemProperty -Path $RegistryRoot\Email -Name "UseSSL").UseSSL -ne 1) {
            $false
            [int32]$Global:MailPort = (Get-ItemProperty -Path $RegistryRoot\Email -Name "Port").Port
        } else {
            $true
            [int32]$Global:MailPort = (Get-ItemProperty -Path $RegistryRoot\Email -Name "SSlPort").SSlPort
        }
        $Global:MailSubmitMessage = (Get-ItemProperty -Path $RegistryRoot\Email -Name "SubmitMsg").SubmitMsg
        $Global:MailMessage = (Get-ItemProperty -Path $RegistryRoot\Email -Name "EnrollMsg").EnrollMsg
        $Global:MailFailedMessage = (Get-ItemProperty -Path $RegistryRoot\Email -Name "FailMsg").FailMsg
        $Global:MailDeniedMessage = (Get-ItemProperty -Path $RegistryRoot\Email -Name "DenyMsg").DenyMsg
    }
    return $UseMailInfo
}

Function Shoot-AdminMail
{
    param (
        [Parameter(Mandatory=$True)] [string]$Subject,
        [Parameter(Mandatory=$True)] [string]$EvtMsg
    )

    try{
        if($Global:MailUseSSL){
            Send-MailMessage -SmtpServer $Global:MailServer -From $Global:MailFrom -To $Global:AdminMailTo -Subject $Subject -Port $Global:MailPort -UseSsl -Body $EvtMsg -BodyAsHtml -ErrorAction Stop
        }else{
            Send-MailMessage -SmtpServer $Global:MailServer -From $Global:MailFrom -To $Global:AdminMailTo -Subject $Subject -Port $Global:MailPort -Body $EvtMsg -BodyAsHtml -ErrorAction Stop
        }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        $EvtMsg = "Send-MailMessage failed for administrative alerting. The error message was:`r`n`r`n"+$ErrorMessage
        Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1111 -EntryType Error -Message $EvtMsg
    }
}

Function Shoot-MailInfo
{
    param (
        [Parameter(Mandatory=$True)] [string]$Subject,
        [Parameter(Mandatory=$True)] [string]$EvtMsg,
        [Parameter(Mandatory=$True)] [string]$Recipient
        )

    try{
        if($Global:MailUseSSL){
            Send-MailMessage -SmtpServer $Global:MailServer -From $Global:MailFrom -To $Recipient -Cc $Global:AdminMailTo -Subject $Subject -Port $Global:MailPort -UseSsl -Body $EvtMsg -BodyAsHtml -ErrorAction Stop
        }else{
            Send-MailMessage -SmtpServer $Global:MailServer -From $Global:MailFrom -To $Recipient -Cc $Global:AdminMailTo -Subject $Subject -Port $Global:MailPort -Body $EvtMsg -BodyAsHtml -ErrorAction Stop
        }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        $EvtMsg = "Send-MailMessage failed for informative mailing. The error message was:`r`n`r`n"+$ErrorMessage
        Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1111 -EntryType Error -Message $EvtMsg
    }
}

Function Read-BinFile
{
    param (
        [Parameter(Mandatory=$True) ] [string]$Filename
    )

    [Byte[]]$file = get-content -Encoding Byte $Filename -Raw
    return $file
}

Function Test-RegistryValue
{
    param (
        [Parameter(Mandatory=$True)] [string]$RegKeyPath,
        [Parameter(Mandatory=$True)] [string]$Value
    )
    
    $ValueExist = ((Get-ItemProperty $RegKeyPath).$Value -ne $null)
    Return $ValueExist
}

Function Compare-FileHash
{
    param (
        [Parameter(Mandatory=$True)] [string]$CntlFileHash
    )

    If (!(Test-RegistryValue $RegistryRoot\ControlFile "CntlFileHash")) {
    # hash not set
        return $True
    } Else {
        $RegFileHash = (Get-ItemProperty -Path $RegistryRoot\ControlFile -Name CntlFileHash).CntlFileHash
        # Compare the hashes & note this in the log
        If ($CntlFileHash -ne $RegFileHash)
        {
            $EvtMsg = "Control file has been manually modified!`n`rHash has comparision failed!`n`r Verify audit logs to detect who modified this file!"
            Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1110 -EntryType Warning -Message $EvtMsg
            return $false
        } else {
            return $True
        }
    }
}

Function Update-FileHash
{
    param (
        [Parameter(Mandatory=$True)] [string]$CntlFileHash
    )
    If (!(Test-RegistryValue $RegistryRoot\ControlFile "CntlFileHash")) {
        New-ItemProperty -Path $RegistryRoot\ControlFile -Name CntlFileHash -Value $CntlFileHash -PropertyType String -Force
    } else {
        Set-ItemProperty -Path $RegistryRoot\ControlFile -Name CntlFileHash -Value $CntlFileHash -Force
    }
}

Function Create-ConfigRegistry
{
    param (
        [Parameter(Mandatory=$True)] $ConfigFile
    )
    If (Test-Path -Path $RegistryRoot) {
        # Reg hive exist --> remove before continuing
        Remove-ConfigRegistry
    }
#region general reg keys
    New-Item -Path $RegistryRoot -Force
    New-ItemProperty -Path $RegistryRoot -Name CaName -Value $Config.Config.CaName -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot -Name Templates -Value $Config.Config.Templates.Template -PropertyType MultiString -Force
    New-ItemProperty -Path $RegistryRoot -Name DefaultTemplate -Value $Config.Config.Templates.DefaultTemplate -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot -Name AutoApproveTemplates -Value $Config.Config.AutoApprove.EnabledTemplate -PropertyType MultiString -Force
    New-ItemProperty -Path $RegistryRoot -Name AllowEmailInSAN -Value (($Config.Config.IncludeEmailInSAN).ToLower() -eq "true" ) -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot -Name WorkingDirectory -Value $Config.Config.BaseDir -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot -Name CleanUpDuration -Value $Config.Config.CleanUpDuration -PropertyType Dword -Force
#endregion

#region eventlog reg keys
    New-Item -Path $RegistryRoot\EventLog -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name UseEventLog -Value (($Config.Config.Eventlog.UseEventlog).ToLower() -eq "true" ) -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name EventLogName -Value $Config.Config.Eventlog.Eventlog -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name EventSource -Value $Config.Config.Eventlog.EventSource -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name WriteSuccessEvents -Value (($Config.Config.Eventlog.WriteSuccessEvents).ToLower() -eq "true" ) -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name FailEventID -Value $Config.Config.Eventlog.FailEventID -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name SubmitEventID -Value $Config.Config.Eventlog.SubmitEventID -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name IssueEventID -Value $Config.Config.Eventlog.IssueEventID -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name EnrollEventID -Value $Config.Config.Eventlog.EnrollEventID -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name SubmitEventMsg -Value $Config.Config.Eventlog.SubmitEventMsg -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name EnrollEventMsg -Value $Config.Config.Eventlog.EnrollEventMsg -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name FailedEventMsg -Value $Config.Config.Eventlog.FailedEventMsg -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\EventLog -Name DeniedEventMsg -Value $Config.Config.Eventlog.DeniedEventMsg -PropertyType String -Force
#endregion

#region email reg keys
    New-Item -Path $RegistryRoot\Email -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name UseMailInfo -Value (($Config.Config.Mail.UseMailInformation).ToLower() -eq "true" ) -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name UseAdminEmail -Value (($Config.Config.Mail.UseAdminEmail).ToLower() -eq "true" ) -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name SmtpServer -Value $Config.Config.Mail.Server -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name Port -Value $Config.Config.Mail.Port -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name SSLPort -Value $Config.Config.Mail.SSLPort -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name UseSSL -Value (($Config.Config.Mail.UseSSL).ToLower() -eq "true" ) -PropertyType Dword -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name MailFrom -Value $Config.Config.Mail.MailFrom -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name MailCC -Value $Config.Config.Mail.MailCC -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name AdminMailTo -Value $Config.Config.Mail.AdminMailTo -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name Subject -Value $Config.Config.Mail.Subject -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name SubmitMsg -Value $Config.Config.Mail.SubmitMsg -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name EnrollMsg -Value $Config.Config.Mail.EnrollMsg -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name FailMsg -Value $Config.Config.Mail.FailMsg -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name DenyMsg -Value $Config.Config.Mail.DenyMsg -PropertyType String -Force
    New-ItemProperty -Path $RegistryRoot\Email -Name Subject -Value $Config.Config.Mail.Subject -PropertyType String -Force
#endregion

#region FileHash reg key
    New-Item -Path $RegistryRoot\ControlFile -Force
#endregion

}

Function Update-Config2Registry
{
    param (
        [Parameter(Mandatory=$True)] $ConfigFile
    )
    If (Test-Path -Path $RegistryRoot) {
#region general reg keys
        Set-ItemProperty -Path $RegistryRoot -Name CaName -Value $Config.Config.CaName -Force
        Set-ItemProperty -Path $RegistryRoot -Name Templates -Value $Config.Config.Templates.Template  -Force
        Set-ItemProperty -Path $RegistryRoot -Name DefaultTemplate -Value $Config.Config.Templates.DefaultTemplate -Force
        Set-ItemProperty -Path $RegistryRoot -Name AutoApproveTemplates -Value $Config.Config.AutoApprove.EnabledTemplate -Force
        Set-ItemProperty -Path $RegistryRoot -Name AllowEmailInSAN -Value (($Config.Config.IncludeEmailInSAN).ToLower() -eq "true" ) -Force
        Set-ItemProperty -Path $RegistryRoot -Name WorkingDirectory -Value $Config.Config.BaseDir -Force
        Set-ItemProperty -Path $RegistryRoot -Name CleanUpDuration -Value $Config.Config.CleanUpDuration -Force
#endregion

#region creating and configuring event log if changed
        if (!((Get-EventLog -list).Log | where { $_ -eq $Config.Config.Eventlog.Eventlog })) {
            New-EventLog -LogName $Config.Config.Eventlog.Eventlog -Source $Config.Config.Eventlog.EventSource
            Limit-EventLog -OverflowAction OverWriteAsNeeded -MaximumSize 2048KB -LogName $Config.Config.Eventlog.Eventlog
            Write-Host ("EventLog "+$Config.Config.Eventlog.Eventlog+" and Event Source "+$Config.Config.Eventlog.EventSource+" successfully created!")
        }
#endregion

#region eventlog reg keys
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name UseEventLog -Value (($Config.Config.Eventlog.UseEventlog).ToLower() -eq "true" ) -Force
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name EventLogName -Value $Config.Config.Eventlog.Eventlog -Force
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name EventSource -Value $Config.Config.Eventlog.EventSource -Force
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name WriteSuccessEvents -Value (($Config.Config.Eventlog.WriteSuccessEvents).ToLower() -eq "true" ) -Force
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name FailEventID -Value $Config.Config.Eventlog.FailEventID -Force
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name SubmitEventID -Value $Config.Config.Eventlog.SubmitEventID -Force
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name IssueEventID -Value $Config.Config.Eventlog.IssueEventID -Force
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name EnrollEventID -Value $Config.Config.Eventlog.EnrollEventID -Force
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name SubmitEventMsg -Value $Config.Config.Eventlog.SubmitEventMsg -Force
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name EnrollEventMsg -Value $Config.Config.Eventlog.EnrollEventMsg -Force
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name FailedEventMsg -Value $Config.Config.Eventlog.FailedEventMsg -Force
        Set-ItemProperty -Path $RegistryRoot\EventLog -Name DeniedEventMsg -Value $Config.Config.Eventlog.DeniedEventMsg -Force
#endregion

#region email reg keys
        Set-ItemProperty -Path $RegistryRoot\Email -Name UseMailInfo -Value (($Config.Config.Mail.UseMailInformation).ToLower() -eq "true" ) -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name UseAdminEmail -Value (($Config.Config.Mail.UseAdminEmail).ToLower() -eq "true" ) -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name SmtpServer -Value $Config.Config.Mail.Server -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name Port -Value $Config.Config.Mail.Port -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name SSLPort -Value $Config.Config.Mail.SSLPort -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name UseSSL -Value (($Config.Config.Mail.UseSSL).ToLower() -eq "true" ) -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name MailFrom -Value $Config.Config.Mail.MailFrom -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name MailCC -Value $Config.Config.Mail.MailCC -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name AdminMailTo -Value $Config.Config.Mail.AdminMailTo -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name Subject -Value $Config.Config.Mail.Subject -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name SubmitMsg -Value $Config.Config.Mail.SubmitMsg -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name EnrollMsg -Value $Config.Config.Mail.EnrollMsg -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name FailMsg -Value $Config.Config.Mail.FailMsg -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name DenyMsg -Value $Config.Config.Mail.DenyMsg -Force
        Set-ItemProperty -Path $RegistryRoot\Email -Name Subject -Value $Config.Config.Mail.Subject -Force
#endregion
    } else {
        # Reg hive does not exist --> Agents not installed
        Write-Host "No EnrollmentAgent configuration found ..." -ForegroundColor Yellow
        Write-Host "Exiting ..." -ForegroundColor Yellow
    }
}

Function Remove-ConfigRegistry
{
    If (Test-Path -Path $RegistryRoot) {
        Remove-Item $RegistryRoot -Recurse -Force -Confirm:$false
    }
}

Function Set-RegKeyPermissions
{
    param (
        [Parameter(Mandatory=$True)] [string]$SubRegKeyPath,
        [Parameter(Mandatory=$True)] [string]$ADIdentity,
        [Parameter(Mandatory=$True)]
        [ValidateSet("FullControl","GenericRead","GenericWrite")] 
        [string]$Perms
    )

    # setting Full Control permissions for agent account
    $acl = Get-Acl $RegistryRoot\$SubRegKeyPath
    $Identity = [System.Security.Principal.NTAccount]$ADIdentity          
    $access = [System.Security.AccessControl.RegistryRights]$Perms
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($Identity,$access,$inheritance,$propagation,$type)
    $acl.AddAccessRule($rule)
    $acl |Set-Acl

}

function Check-AutoApprove
{
    param (
        [Parameter(Mandatory=$True) ] $RequestTemplate
    )

    $AutoApproveTmpl = $false
    (Get-ItemProperty -Path $RegistryRoot -Name "AutoApproveTemplates").AutoApproveTemplates|foreach-object {
        if ( $RequestTemplate -eq $_ ) { $AutoApproveTmpl= $true }
    }
    return $AutoApproveTmpl
}

function Is-CertSrvRunning
{
    [boolean]$IsRunning = if((Get-Service -Name CertSvc).Status -eq "Running") {$true}else{$false}
    return $IsRunning
}

function Is-IcertReqOnline
{
    $CACnfg = (Get-ItemProperty -Path $RegistryRoot -Name "CaName").CaName
    $result = certutil -config $CACnfg -ping
    $IsAlive = if($result -like "*ICertRequest2 interface is alive*") {$true}else{$false}
    return $IsAlive
}

