#
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

<#
    .SYNOPSIS
    Submit incoming requests to CA and add additional SANs to that appropriate pending request. 
    All necessary parameters are taken from the config.xml file

    .PARAMETER Help
    display help.

   .Notes
    AUTHOR: Andreas Luy, MSFT; andreas.luy@microsoft.com
    last change 26.07.2021

#>

Param (
    [Parameter(Mandatory=$false)]
    [Switch]$Help
)

If ($Help) {
    Get-Help $MyInvocation.MyCommand.Definition -Detailed
    exit
}


function Get-RequestTmpl {
    param (
        [Parameter(Mandatory=$True) ] $RequestFileName
    )
    $TmplFileName = ($RequestFileName.DirectoryName+"\"+(($RequestFileName.name).split(".")[0])+".tmpl")
    if (Test-Path $TmplFileName) {
        $Tmpl = Get-Content ($TmplFileName)
        if ($tmpl.GetType().Name -ne "String") {
            $Tmpl = $global:DefaultTmpl
        } else {
            $AllowedTmpl = $false
            (Get-ItemProperty -Path $RegistryRoot -Name "Templates").Templates|foreach-object {
                if ( $Tmpl -eq $_ ) { $AllowedTmpl= $true }
            }
            if ( !$AllowedTmpl ) {
                $Tmpl = $global:DefaultTmpl
            }
        }
    }else{
        #no template file found --> assign default template
        $Tmpl = $global:DefaultTmpl
    }
    return $Tmpl
}

function ConvertTo-DERstring {
    param (
        [Parameter(Mandatory=$True) ] [byte[]]$bytes
)
    if ($bytes.Length % 2 -eq 1) {$bytes += 0}
    $SB = New-Object System.Text.StringBuilder
    for ($n = 0; $n -lt $bytes.count; $n += 2) {
        [void]$SB.Append([char]([int]$bytes[$n+1] -shl 8 -bor $bytes[$n]))
    }
    $SB.ToString()
}

function Get-SANs {
    param (
        [Parameter(Mandatory=$True) ] $RequestFileName
    )
    $SanList = @()
    $SanFileName = ($RequestFileName.DirectoryName+"\"+(($RequestFileName.name).split(".")[0])+".san")
    if (Test-Path $SanFileName) {
        #$SanList = Get-Content ($SanFileName)
        $sSAN = Get-Content ($SanFileName)
        foreach($line in $sSAN) {
            if ($line -notmatch "---"){
                $SanList += $line
            }
        }
    }
    return $SanList
}

function Add-SanToPendRequest {
    param (
        [Parameter(Mandatory=$True) ] [array]$SanList,
        [Parameter(Mandatory=$True) ] [string]$RequestID,
        [Parameter(Mandatory=$True) ] [string]$ReqCA,
        [Parameter(Mandatory=$False) ] [boolean]$AllowEmail=$false
    )

    $IAN = @()
    $SanExt = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $IANCol = New-Object -ComObject X509Enrollment.CAlternativeNames
    $SanList| ForEach-Object{
        $IAN1 = New-Object -ComObject X509Enrollment.CAlternativeName
        if (($_ -match "@") -and $AllowEmail) {
            $IAN1.InitializeFromString(0x2,$_)
        } else {
            $IAN1.InitializeFromString(0x3,$_)
        }
        $IAN += $IAN1
        $IAN1 = $null
    }
    $IAN | ForEach-Object {$IANCol.Add($_)}
    $SanExt.InitializeEncode($IANCol)
    $bytes = [convert]::FromBase64String($SanExt.RawData(1))
    $pvarvalue = ConvertTo-DERstring $bytes
    $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
    $CertAdmin.SetCertificateExtension($ReqCA,$RequestID,"2.5.29.17",0x3,0,$pvarvalue)
}

function Get-RequestOwner {
    param (
        [Parameter(Mandatory=$True) ] [array]$SanList
    )
    $Owner = ""
    $SanList| ForEach-Object{
        if ($_ -match "@" ) {
            $Owner=$_
        }
    }
    return $Owner
}


$ScriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

#debug only
#$ScriptDir = "C:\LabFiles\AutoReqCntl"
. ($ScriptDir+"\lib.helper.ps1")
. ($ScriptDir+"\lib.csr.dump.ps1")
. ($ScriptDir+"\lib.csr.verify.ps1")

$RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\EnrollAgents"
$BaseDir = (Get-ItemProperty -Path $RegistryRoot -Name "WorkingDirectory").WorkingDirectory

#region verify if eventlog should be used
$UseEventlog = Use-Eventlog
#endregion

#region verify if mail information should be used
$UseMail = Use-Mail
#endregion

#region control file location file
$CntlFile = $ScriptDir+"\RequestCntl.csv"
#endregion

if(!(Test-Path $BaseDir)) {
    $EvtMsg = "Configuration Error!`n`r`n`rWorking directory is not accessible:`n`r"+$BaseDir+".`n`rVerify that the directory exists and the EnrollmentAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1001 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Working directory is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}
if(!(Test-Path $BaseDir\inbox)) {
    $EvtMsg = "Configuration Error!`n`r`n`rInbox folder is not accessible:`n`r"+$BaseDir+"\Inbox.`n`rVerify that the folder exists and the EnrollmentAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1002 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Inbox folder is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}
if(!(Test-Path $BaseDir\outbox)) {
    $EvtMsg = "Configuration Error!`n`r`n`rOutbox folder is not accessible:`n`r"+$BaseDir+"\Outbox.`n`rVerify that the folder exists and the EnrollmentAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1003 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Outbox folder is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}
if(!(Test-Path $BaseDir\archive)) {
    $EvtMsg = "Configuration Error!`n`r`n`rArchive folder is not accessible:`n`r"+$BaseDir+"\Archive.`n`rVerify that the folder exists and the EnrollmentAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1004 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Archive folder is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}
if(!(Test-Path $BaseDir\rejected)) {
    $EvtMsg = "Configuration Error!`n`r`n`rRejected folder is not accessible:`n`r"+$BaseDir+"\rejected.`n`rVerify that the folder exists and the EnrollmentAgent account has appropriate access permissions."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1005 -EntryType Error -Message $EvtMsg
    if ($Global:UseAdminEmail){
        $Subject = "Rejected folder is not accessible"
        Shoot-AdminMail $Subject $EvtMsg
    }
    break
}
if(!(Is-IcertReqOnline)) {
    $EvtMsg = "General Error!`n`r`n`rActive Directory Certificate Services cannot be reached:`n`rEnsure the service is started and can be reached before continuing..."
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1000 -EntryType Error -Message $EvtMsg
        if ($Global:UseAdminEmail){
        $Subject = "Active Directory Certificate Services cannot be reached"
        Shoot-AdminMail $Subject $EvtMsg
    }
break
}

$TargetCA = (Get-ItemProperty -Path $RegistryRoot -Name "CaName").CaName
$AllowedTemplateList = (Get-ItemProperty -Path $RegistryRoot -Name "Templates").Templates
$global:DefaultTmpl = (Get-ItemProperty -Path $RegistryRoot -Name "DefaultTemplate").DefaultTemplate
[boolean]$UseEmailInSAN = (Get-ItemProperty -Path $RegistryRoot -Name "AllowEmailInSAN").AllowEmailInSAN
$InputFiles = (dir ($BaseDir+"\inbox\*.csr"))
#define empty array which will be filled with request objects
$ReqList = @()


#verify if control file file already exist and read/import if so
if( $inputfiles.Length -gt 0 ) {
    if (Test-Path $CntlFile) {
        Compare-FileHash ((Get-FileHash -Path $CntlFile -Algorithm SHA256).hash)
        $ReqList = @(import-csv $CntlFile)
    } else {
        If (Test-RegistryValue $RegistryRoot\ControlFile "CntlFileHash") {
            # no file but existing hash --> ControlFile was deleted
            $EvtMsg = "Control file has been deleted!`n`rVerify audit logs to detect who deleted this file!"
            Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1110 -EntryType Warning -Message $EvtMsg
            if ($Global:UseAdminEmail){
                $Subject = "Audit Error - ControlFile"
                Shoot-AdminMail $Subject $EvtMsg
            }
        }        
    }

    
    #submit single requests ...
    foreach ( $ReqFile in $inputfiles ) {

    #region verify csr file

        $csr = Dump-Request $ReqFile

        if( Pass-CsrVerification $csr $ReqFile) {
    #endregion

            $RequestObj = "" | select ReqFileName,RequestID,Disposition,Date,OwnerEmail,AutoApprove
            $Template = Get-RequestTmpl $ReqFile
            [int32]$AutoApprove = Check-AutoApprove $Template
            $Sans = Get-SANs $ReqFile
            $Result = Certreq.exe -submit -q -config "$TargetCA" -attrib "CertificateTemplate:$Template" $ReqFile.fullname
            if (($result -like "*error*") -or ($result -like "*fail*") -or ($result -like "*denied*")) {
                if ($UseEventlog) {
                    $ErrorMessage = $result
                    $EvtMsg = "Certificate submission failed for "+$ReqFile.Name+". The error message was:`r`n`r`n"+$ErrorMessage
                    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID $Global:FailEventID -EntryType Error -Message $EvtMsg
                }
                try{
                    dir ($BaseDir+"\inbox\"+$ReqFile.BaseName+".*" ) | ForEach {
                        Move-Item $_.FullName ("$($BaseDir+"\failed\")\$($_.BaseName)-ReqId$($ReqID)-$(get-date -f yyyyMMdd-HHmm)$($_.extension)") -ErrorAction Stop
                    }
                }
                catch{
                    $ErrorMessage = $_.Exception.Message
                    $EvtMsg = "Move-Item failed for failed request "+$ReqFile.name+", RequestID: "+$ReqID+". The error message was:`r`n`r`n"+$ErrorMessage
                    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1010 -EntryType Error -Message $EvtMsg
                }
            } else {    
                $ReqID = ($Result[0].split(":")[1]).trim()
                $RequestObj.RequestID = $ReqID
                $RequestObj.ReqFileName = $ReqFile.Name
                $RequestObj.Disposition = 9
                $RequestObj.Date = Get-Date
                $RequestObj.AutoApprove = $AutoApprove

                if ($Sans) {
                    Add-SanToPendRequest $Sans $ReqID $TargetCA $UseEmailInSAN
                    if (($RequestObj.OwnerEmail).length -eq 0){
                        $RequestObj.OwnerEmail = Get-RequestOwner $Sans
                    }
                }
                $ReqList += $RequestObj
                try{
                    dir ($BaseDir+"\inbox\"+$ReqFile.BaseName+".*" ) | ForEach {
                        Move-Item $_.FullName ("$($BaseDir+"\archive\")\$($_.BaseName)-ReqId$($ReqID)-$(get-date -f yyyyMMdd-HHmm)$($_.extension)") -ErrorAction Stop
                    }
                }
                catch{
                    $ErrorMessage = $_.Exception.Message
                    $EvtMsg = "Move-Item failed for archiving "+$ReqFile.name+", RequestID: "+$ReqID+". The error message was:`r`n`r`n"+$ErrorMessage
                    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1010 -EntryType Error -Message $EvtMsg
                }
                if ($RequestObj.OwnerEmail -and $UseMail) {
                    $msg = $Global:MailSubmitMessage -replace "!REQName!",$ReqFile.name
                    $Subject = $Global:MailSubject + " - " + $ReqFile.name
                    Shoot-AdminMail $Subject $msg
                }
                if ($UseEventlog -and $Global:WriteSuccessEvents) {
                    $EvtMsg = $SubmitEventMsg -replace "!REQName!",$ReqFile.name
                    $EvtMsg = $EvtMsg -replace "!REQID!",$ReqID
                    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID $Global:SubmitEventID -EntryType Information -Message $EvtMsg
                }
            }
        } else {
            try{
                dir ($BaseDir+"\inbox\"+$ReqFile.BaseName+".*" ) | ForEach {
                    Move-Item $_.FullName ("$($BaseDir+"\rejected\")\$($_.BaseName)-$(get-date -f yyyyMMdd-HHmm)$($_.extension)") -ErrorAction Stop
                }
            }
            catch{
                $ErrorMessage = $_.Exception.Message
                $EvtMsg = "Move-Item failed for rejected "+$ReqFile.name+", RequestID: "+$ReqID+". The error message was:`r`n`r`n"+$ErrorMessage
                Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1010 -EntryType Error -Message $EvtMsg
                if ($Global:UseAdminEmail){
                    $Subject = "Audit Error - ControlFile"
                    Shoot-AdminMail $Subject $EvtMsg
                }
            }
        }
    }

    # update control file and file hash
    $ReqList | export-csv $CntlFile -NoTypeInformation -Force
    Update-FileHash ((Get-FileHash -Path $CntlFile -Algorithm SHA256).hash)
}
