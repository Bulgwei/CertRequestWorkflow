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
#

<#
    .SYNOPSIS
    Install/uninstall Submit and Enroll agents and updates agent's configurations

    .PARAMETER InstallAgents
    define if the agents will be installed as scheduled task; creates necessary event log and sources
    configuration items are taken from the config.xml file
    default value: false

    .PARAMETER UninstallAgents
    remove the agent's scheduled task and registry configuration
    default value: false

    .PARAMETER UpdateConfig
    define whether the Configuration should be updated in registry
    default value: false

    .PARAMETER Help
    display help.

   .Notes
    AUTHOR: Andreas Luy, MSFT; andreas.luy@microsoft.com
    last change 26.07.2021

#>

[CmdletBinding(DefaultParameterSetName="Install")]
Param (
    [Parameter(Mandatory=$false,
        ParameterSetName="Install")]
    [Switch]$InstallAgents,

    [Parameter(Mandatory=$false,
        ParameterSetName="Uninstall")]
    [Switch]$UninstallAgents,

    [Parameter(Mandatory=$false,
        ParameterSetName="Update")]
    [Switch]$UpdateConfig,

    [Parameter(Mandatory=$false,
        ParameterSetName="Install")]
    [Parameter(Mandatory=$false,
        ParameterSetName="Uninstall")]
    [Parameter(Mandatory=$false,
        ParameterSetName="Update")]
    [Switch]$Help
)

If ($Help) {
    Get-Help $MyInvocation.MyCommand.Definition -Detailed
    exit
}

Function Check-Installed
{

}

Function Check-AdminPrivileges {

	$HasSeBackupPriv = $false
    $WindowsIdentity = [system.security.principal.windowsidentity]::GetCurrent()
    $HasSeSecurityPriv = (whoami /priv |findstr SeSecurityPrivilege)

	if (!($HasSeSecurityPriv)) {
		Return $False
	}
    return $True
}

Function Install-Scripts {
    param (
        [Parameter(Mandatory=$True) ] [String]$ScriptBaseDir,
        [Parameter(Mandatory=$True) ] [String]$WorkDir
    )

    $TranscriptFile = "$(Split-Path -Path $MyInvocation.MyCommand.Definition -Parent)EnrollAgentInstallation_$(Get-Date -format yyyyMMdd_HHmmss).txt"
    Trap {Continue} Start-Transcript -path $TranscriptFile
    

    $EventLog = $Config.Config.Eventlog.EventLog
    $EventSource = $Config.Config.Eventlog.EventSource
    If (!$EventLog -or !$EventSource) {break}

    $SubmitAgent = $ScriptBaseDir+"\SubmitAgnt.ps1"
    $EnrollAgent = $ScriptBaseDir+"\EnrollAgnt.ps1"
    $SubmitTaskName = "Microsoft\ADCS\"+$Config.Config.Install.SubmitTaskName
    $EnrollTaskName = "Microsoft\ADCS\"+$Config.Config.Install.EnrollTaskName
    $AgentAccountName = $Config.Config.Install.AgentAccountName
    [int32]$TaskInterval = $Config.Config.Install.TaskRepetitionInterval

    if (Check-AdminPrivileges) {
#region creating and configuring event log
        if (!((Get-EventLog -list).Log | where { $_ -eq $EventLog })) {
            New-EventLog -LogName $EventLog -Source $EventSource
            Limit-EventLog -OverflowAction OverWriteAsNeeded -MaximumSize 2048KB -LogName $EventLog
            Write-Host ("EventLog "+$EventLog+" and Event Source "+$EventSource+" successfully created!")
        } else {
            Write-Host "Event log already exist - skipping ..."
        }
#endregion

#region install scheduled tasks
        # check if task account is gMSA
        $IsgMSA = if ($AgentAccountName.Contains("$")) {$true} else {$false}
        if (!$IsgMSA) {
            # no gMSA --> get account password
            Write-Host 
            Write-Host "Enter Service Account Password:" -ForegroundColor Yellow
            $sPW = Read-Host "---> " -AsSecureString 
            $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $AgentAccountName, $sPW
            $PW = $Credentials.GetNetworkCredential().Password         }
        # check if task already exist
        if ((Get-ScheduledTask -TaskName $Config.Config.Install.SubmitTaskName -ErrorAction SilentlyContinue)) { # -OutVariable TaskExist
            Write-Host "SubmitAgent task already exist - skipping ..."
        } else {
            $action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument ("-NoProfile -WindowStyle Hidden -command "+$SubmitAgent) -WorkingDirectory $ScriptBaseDir
            $trigger =  New-ScheduledTaskTrigger -Daily -DaysInterval 1 -At 9am 
            $Trigger.Repetition = $(New-ScheduledTaskTrigger -Once -At "09:00" -RepetitionDuration (New-TimeSpan -Days 1) -RepetitionInterval (New-TimeSpan -Hours $TaskInterval)).Repetition
            $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -Compatibility Win8
            if ($IsgMSA) {
                $RT = Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $SubmitTaskName -Description "Certificate submit agent" -Principal (New-ScheduledTaskPrincipal -UserId $AgentAccountName -LogonType Password) -Settings $settings
            } else {
                $RT = Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $SubmitTaskName -Description "Certificate submit agent" -Settings $settings -User $AgentAccountName -Password $PW
            }
            Write-Host ("Scheduled Task "+$Config.Config.Install.SubmitTaskName+" successfully created!")
        }
    
        if ((Get-ScheduledTask -TaskName $Config.Config.Install.EnrollTaskName -ErrorAction SilentlyContinue)) {
            Write-Host "EnrollAgent task already exist - skipping ..."
        } else {
            $action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument ("-NoProfile -WindowStyle Hidden -command "+$EnrollAgent) -WorkingDirectory $ScriptBaseDir
            $trigger =  New-ScheduledTaskTrigger -Daily -DaysInterval 1 -At 9:30am 
            $Trigger.Repetition = $(New-ScheduledTaskTrigger -Once -At "09:30" -RepetitionDuration (New-TimeSpan -Days 1) -RepetitionInterval (New-TimeSpan -Hours $TaskInterval)).Repetition
            $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -Compatibility Win8
            if ($IsgMSA) {
                $RT = Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $EnrollTaskName -Description "Certificate enroll agent" -Principal (New-ScheduledTaskPrincipal -UserId $AgentAccountName -LogonType Password) -Settings $settings
            } else {
                $RT = Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $EnrollTaskName -Description "Certificate enroll agent" -Settings $settings -User $AgentAccountName -Password $PW
            }
            Write-Host ("Scheduled Task "+$Config.Config.Install.EnrollTaskName+" successfully created!")
        }
#endregion


#region create registry keys
        Create-ConfigRegistry $ConfigFile
        Set-RegKeyPermissions "ControlFile" $AgentAccountName "FullControl"
#endregion

#region creating folder structure
        Write-Host "The installation routine is not checking for existents of working folder structure"
        Write-Host "nor will it create the necessary folder structure!`n`r"
        Write-Host "Please ensure the following working-folders structure exist at:"
        Write-Host ("-" + $workDir) -ForegroundColor Yellow
        Write-Host "-- inbox" -ForegroundColor Yellow
        Write-Host "-- outbox" -ForegroundColor Yellow
        Write-Host "-- archive`n`r" -ForegroundColor Yellow
        Write-Host "-- failed`n`r" -ForegroundColor Yellow
        Write-Host "-- rejected`n`r" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Follow the quick start guide for appropriate permissioning those folders!" -ForegroundColor Yellow
#endregion

        Write-Host ""
        Write-Host ""
        Write-Host ("Ensure the used account " + $AgentAccountName + " has appropriate logon permissions`n`rto this system and at CA level. " ) -ForegroundColor Yellow
        Write-Host "Refer to quick start guide for appropriate permissioning of the agent's account!" -ForegroundColor Yellow

        Write-Host "Installation succeeded!`n`rExiting ..." -BackgroundColor Green -ForegroundColor Yellow
    } else {
        Write-Host "Not enough permissions ..." -BackgroundColor DarkRed -ForegroundColor Yellow
        Write-Host "Installation failed!`n`rExiting ..." -BackgroundColor DarkRed -ForegroundColor Yellow
    }
    Trap {Continue} Stop-Transcript 
    If (Test-Path $TranscriptFile) {
        [string]::join("`r`n",(Get-content $TranscriptFile)) | Out-File $TranscriptFile
    }

}

Function Uninstall-Scripts {
    param (
        [Parameter(Mandatory=$True) ] [String]$ScriptBaseDir,
        [Parameter(Mandatory=$True) ] [String]$WorkDir
    )

    $EventLog = $Config.Config.Eventlog.EventLog
    $EventSource = $Config.Config.Eventlog.EventSource

    $SubmitAgent = $ScriptBaseDir+"\SubmitAgnt.ps1"
    $EnrollAgent = $ScriptBaseDir+"\EnrollAgnt.ps1"
    $SubmitTaskName = (Get-ScheduledTask -TaskName $Config.Config.Install.SubmitTaskName).TaskName
    $EnrollTaskName = (Get-ScheduledTask -TaskName $Config.Config.Install.EnrollTaskName).TaskName
    $TaskPath = (Get-ScheduledTask -TaskName $Config.Config.Install.EnrollTaskName).TaskPath
    $AgentAccountName = $Config.Config.Install.AgentAccountName
    [int32]$TaskInterval = $Config.Config.Install.TaskRepetitionInterval

    if (Check-AdminPrivileges) {
#region install scheduled tasks
        # check if task already exist
        if ((Get-ScheduledTask -TaskName $Config.Config.Install.SubmitTaskName -ErrorAction SilentlyContinue)) { # -OutVariable TaskExist
            Unregister-ScheduledTask -TaskName $SubmitTaskName -Confirm:$false
        } else {
            Write-Host "SubmitAgent task already deleted - skipping ..."
        }
    
        if ((Get-ScheduledTask -TaskName $Config.Config.Install.EnrollTaskName -ErrorAction SilentlyContinue)) {
            Unregister-ScheduledTask -TaskName $EnrollTaskName -Confirm:$false
        } else {
            Write-Host "EnrollAgent task already deleted - skipping ..."
        }
#endregion

#region removing registry keys
        Remove-ConfigRegistry
#endregion

#region removing folder structure and event log
        Write-Host "Please delete the following items manually if not needed anymore for auditing purposes ..."
        Write-Host ("Working folders in " + $workDir) -ForegroundColor Yellow
        Write-Host "-- inbox" -ForegroundColor Yellow
        Write-Host "-- outbox" -ForegroundColor Yellow
        Write-Host "-- archive`n`r" -ForegroundColor Yellow
        Write-Host "-- failed`n`r" -ForegroundColor Yellow
        Write-Host "-- rejected`n`r" -ForegroundColor Yellow
        Write-Host ""
        Write-Host ("Event log: " + $Eventlog) -ForegroundColor Yellow
        Write-Host ("Event source: " + $EventSource) -ForegroundColor Yellow
        Write-Host ""
        Write-Host ("Task path: " + $TaskPath) -ForegroundColor Yellow

#endregion
        Write-Host "Uninstallation succeeded!`n`rExiting ..." -BackgroundColor Green -ForegroundColor Yellow
        break
    } else {
        Write-Host "Not enough permissions ..." -BackgroundColor DarkRed -ForegroundColor Yellow
        Write-Host "Uninstallation failed!`n`rExiting ..." -BackgroundColor DarkRed -ForegroundColor Yellow
        break
    }
}

$ConfigFile = "Config.xml"
$ScriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
. ($ScriptDir+"\lib.helper.ps1")

$Config = Get-XmlConfig ($ScriptDir+"\"+$ConfigFile)
$BaseDir = $Config.Config.BaseDir

#region debug overwrites
#$InstallAgents=$true
#$UninstallAgents=$true
#$UpdateConfig=$true
#$ScriptDir = "C:\LabFiles\AutoReqCntl"
#endregion


if ($InstallAgents) {
    Install-Scripts $ScriptDir $BaseDir
}

if ($UninstallAgents) {
    Uninstall-Scripts $ScriptDir $BaseDir
}

If ($UpdateConfig) {
    Update-Config2Registry $ConfigFile
}
