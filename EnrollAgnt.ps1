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
#
# COMMENT: Export issued certificates from CA in cer and p7b format
#
#
# USAGE:
#	.\EnrollAgnt.ps1 
#
# ==============================================================================================
# version 1.1
# dev'd by andreas.luy@microsoft.com
#

<#
    .SYNOPSIS
    Verifies if a pending request has been issued/approved and exports the appropriate certificate
    onto a file-based outbox. All necessary parameters are taken from the config.xml file

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


Function Clean-Up {
    param (
        [Parameter(Mandatory=$True) ] [string]$CleanUpDir,
        [Parameter(Mandatory=$True) ] [String]$DeleteAfter
    )
    #Clean out  files older then $HoldForDays days
    Write-host "Delete old request files"
    try{
        Get-ChildItem ($CleanUpDir) -ErrorAction Stop | ? {($_.lastwritetime -lt (Get-Date).AddDays(-$DeleteAfter))} | Remove-Item -Verbose -force -ErrorAction Stop
        }
    catch{
        $ErrorMessage = $_.Exception.Message
        $EvtMsg = "Clean Up failed. The error message was:`r`n`r`n"+$ErrorMessage
        Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1100 -EntryType Error -Message $EvtMsg
        if ($Global:UseAdminEmail){
            $Subject = "Clean Up Error"
            Shoot-AdminMail $Subject $EvtMsg
        }
    }
}


$ScriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# debug only
#$ScriptDir = "C:\LabFiles\scripts\AutoReqCntl"
. ($ScriptDir+"\lib.helper.ps1")

$RegistryRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\EnrollAgents"
$BaseDir = (Get-ItemProperty -Path $RegistryRoot -Name "WorkingDirectory").WorkingDirectory
$OutputDir = $BaseDir+"\outbox"

#region verify if eventlog should be used
$UseEventlog = Use-Eventlog
#endregion

#region control file location file
$CntlFile = $ScriptDir+"\RequestCntl.csv"
#endregion

#region verify if mail information should be used
$UseMail = Use-Mail
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
$ReqList=@()

# clean up the file system
[int32]$CleanUpDuration = (Get-ItemProperty -Path $RegistryRoot -Name "CleanUpDuration").CleanUpDuration

#.csv Datei importieren
if (Test-Path $CntlFile) {
    Compare-FileHash ((Get-FileHash -Path $CntlFile -Algorithm SHA256).hash)
    $ReqList=@(import-csv $CntlFile)
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

    
$ReqID = "0"

for ($ListIndex=0;$ListIndex -lt $ReqList.Length; $ListIndex++) {
    # selecting only "open" requests in file queue --> disposition = 9
    if ($ReqList[$ListIndex].Disposition -eq "9") {
        # resetting values
        $Result = $null
        $Result2 = $null
        $requestor = $null

        $ReqID = $ReqList[$ListIndex].RequestID
        [boolean]$AutoApproval = [int32]$ReqList[$ListIndex].AutoApprove
        
        # checking if request still exist in CA db
        $Result = Certutil -config $TargetCA -view -restrict "RequestID=$ReqID" -out "RequestID,Disposition,ResolvedWhen" csv
        if (($result.Length -eq 2) -and ($Result -match "Disposition")) {
            # request exists
            # extracting disposition value from result
            $Disposition = (($Result[1].Split(",")[1]).split("""")[1]).split("-")[0].trim()
            if ($ReqList[$ListIndex].OwnerEmail) {
                $requestor = ($ReqList[$ListIndex].OwnerEmail)
            }

            # checking for auto approval for this request and request is still pending in CA db --> disposition = 9
            if ($AutoApproval -and ($Disposition -eq "9")) {
                # sending approval for this request
                $ResultSmt = Certutil -config $TargetCA -resubmit $ReqID
                if ($ResultSmt -match "FAILED") {
                    # resubmitting failed for some reason
                    $EvtMsg = "Auto approval error for request "+$ReqID+"!`n`rError Message:`n`r"+$ResultSmt
                    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1050 -EntryType Warning -Message $EvtMsg
                    if ($Global:UseAdminEmail){
                        $Subject = "Auto Approval Error - RequestID:"+$ReqID
                        Shoot-AdminMail $Subject $EvtMsg
                    }
                
                } else {
                    # resubmitting succeeded, adjusting disposition and setting submission time
                    $EvtMsg = "Auto approval succeeded for request "+$ReqID+"!`n`rSuccess Message:`n`r"+$ResultSmt
                    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1050 -EntryType Warning -Message $EvtMsg
                    if ($Global:UseAdminEmail){
                        $Subject = "Auto Approval succeeded - RequestID:"+$ReqID
                        Shoot-AdminMail $Subject $EvtMsg
                    }
                    $Disposition = "20"
                    $ResolvedWhen = (Get-Date -Format g)
                }
            } else {
                # no auto approval or request has alread manually approved
                # extracting request procession date value from result
                $ResolvedWhen = (($Result[1].Split(",")[2]).split("""")[1]).trim()
            }

            switch ($Disposition) {
                # issued
                "20" {
                    # get the cert files and P7B from CA db
                    $CerFileName = $BaseDir+"\outbox\"+((($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1]).split(".")[0])+".cer"
                    $P7bFileName = $BaseDir+"\outbox\"+((($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1]).split(".")[0])+".p7b"
                    $Result2 = Certreq -q -f -retrieve -config $TargetCA $ReqID $CerFileName $P7bFileName
                    if ($Result2 -like "*Certificate retrieved(Issued)*") {
                        # set disposition to 20 --> issued/enrolled
                        $ReqList[$ListIndex].Disposition=20
                        $ReqList[$ListIndex].Date=$ResolvedWhen
                        if ($requestor -and $UseMail) {
                            # send mail to requestor
                            $msg = $Global:MailMessage -replace "!REQName!", (($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1])
                            $msg = $msg -replace "!CERName!", $CerFileName
                            $msg = $msg -replace "!P7BName!", $P7bFileName
                            $Subject = $Global:MailSubject+" - "+(($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1])
                            Shoot-MailInfo $Subject $msg $requestor
                        }
                        if ($UseEventlog -and $Global:WriteSuccessEvents) {
                            # write successful enrollment into eventlog
                            $EvtMsg = $EnrollEventMsg -replace "!REQName!",(($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1])
                            $EvtMsg = $EvtMsg -replace "!REQID!",$ReqID
                            Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID $Global:EnrollEventID -EntryType Information -Message $EvtMsg
                        }
                    }else {
                        if ($UseEventlog) {
                            $ErrorMessage = if($_.Exception.Message){$_.Exception.Message}else{$Result2}
                            $EvtMsg = "Certificate enrollment failed for enrolling "+(($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1])+", RequestID: "+$ReqID+". The error message was:`r`n`r`n"+$ErrorMessage
                            Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID $Global:FailEventID -EntryType Error -Message $EvtMsg
                        }
                    }
                }
                # failed
                "30" {
                    $ReqList[$ListIndex].Disposition=30
                    if ($requestor -and $UseMail) {
                        # send mail to requestor
                        $msg = $MailFailedMessage -replace "!REQName!", (($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1])
                        $Subject=$Global:MailSubject+" - "+(($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1])
                        Shoot-MailInfo $Subject $msg $requestor
                    }
                    if ($UseEventlog) {
                        # write enrollment failure into eventlog
                        $EvtMsg = $FailedEventMsg -replace "!REQName!",(($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1])
                        $EvtMsg = $EvtMsg -replace "!REQID!",$ReqID
                        Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID $Global:EnrollEventID -EntryType Warning -Message $EvtMsg
                    }
                }
                # denied
                "31" {
                    $ReqList[$ListIndex].Disposition=31
                    if ($requestor -and $UseMail) {
                        # send mail to requestor
                        $msg = $MailDeniedMessage -replace "!REQName!", (($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1])
                        $Subject=$Global:MailSubject+" - "+(($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1])
                        Shoot-MailInfo $Subject $msg $requestor
                    }
                    if ($UseEventlog) {
                        # write enrollment failure into eventlog
                        $EvtMsg = $DeniedEventMsg -replace "!REQName!",(($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1])
                        $EvtMsg = $EvtMsg -replace "!REQID!",$ReqID
                        Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID $Global:EnrollEventID -EntryType Warning -Message $EvtMsg
                    }
                }
            }
        } else {
            # request does not exists
            $Subject = "Request not found in CA db - RequestID: "+$ReqID
            $ErrorMessage = $Result
            $EvtMsg = "Certificate record identification in database failed for "+(($ReqList[$ListIndex].ReqFilename).split("\")[(($ReqList[$ListIndex].ReqFilename).split("\")).Length-1])+","+$ReqID+". The error message was:`r`n`r`n"+$ErrorMessage
            Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 1020 -EntryType Error -Message $EvtMsg
            Shoot-AdminMail $Subject $EvtMsg
        }
    }
}
# update .csv and file hash
$ReqList | export-csv $CntlFile -NoTypeInformation -Force
Update-FileHash ((Get-FileHash -Path $CntlFile -Algorithm SHA256).hash)

# do folder clean up
Clean-Up ($BaseDir+"\archive") $CleanUpDuration
Clean-Up ($BaseDir+"\outbox") $CleanUpDuration

