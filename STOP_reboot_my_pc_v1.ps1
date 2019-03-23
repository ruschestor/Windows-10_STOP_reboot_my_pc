# Script: Windows 10 please STOP reboot my PC/Laptop
# Version: 1.0 30.12.2018
# Blog: https://itgeeknotes.blogspot.com

########## PREPARATIONS  ##########
$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding

# set-executionpolicy unrestricted
if ((get-executionpolicy) -ne "Unrestricted")
{
    set-executionpolicy Unrestricted -Confirm:$false -Scope CurrentUser -Force
}

# The script should be run as administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe " -File `"$PSCommandPath`"" -Verb RunAs; exit }

########## ACTIONS  ##########

##### PART 1 #####
# Disable Scheduled Tasks "UpdateOrchestrator - Reboot" and "UpdateOrchestrator - UpdateAssistantWakeupRun"
Get-ScheduledTask -TaskName Reboot -TaskPath "\Microsoft\Windows\UpdateOrchestrator\" | Disable-ScheduledTask
Get-ScheduledTask -TaskName UpdateAssistantWakeupRun -TaskPath "\Microsoft\Windows\UpdateOrchestrator\" | Disable-ScheduledTask
# http://johansenreidar.blogspot.com/2013/12/powershell-things-to-check-if-computer.html
# https://blog.hqcodeshop.fi/archives/375-Windows-10-Fall-Creators-Update-breaking-sleep.html
TAKEOWN /F $env:windir"\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot"
TAKEOWN /F $env:windir"\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan"
icacls $env:windir"\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot" /inheritance:r /grant *S-1-1-0:F /grant "SYSTEM:F" /grant "Local Service:F" /grant *S-1-5-32-544:F
icacls $env:windir"\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan" /inheritance:r /grant *S-1-1-0:F /grant "SYSTEM:F" /grant "Local Service:F" /grant *S-1-5-32-544:F
icacls $env:windir"\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantWakeupRun" /inheritance:r /grant *S-1-1-0:F /grant "SYSTEM:F" /grant "Local Service:F" /grant *S-1-5-32-544:F
Get-ScheduledTask | ? {$_.Settings.WakeToRun -eq $true} | % {$_.Settings.WakeToRun = $false; Set-ScheduledTask $_}
icacls $env:windir"\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot" /inheritance:r /deny *S-1-1-0:F /deny "SYSTEM:F" /deny "Local Service:F" /deny *S-1-5-32-544:F
icacls $env:windir"\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantWakeupRun" /inheritance:r /deny *S-1-1-0:F /deny "SYSTEM:F" /deny "Local Service:F" /deny *S-1-5-32-544:F

##### PART 2 #####
# Set NoAutoRebootWithLoggedOnUsers & AUOptions
$Reg_NoAutoRebootWithLoggedOnUsers_AUOptions_Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$Reg_NoAutoRebootWithLoggedOnUsers_Name = "NoAutoRebootWithLoggedOnUsers"
$Reg_NoAutoRebootWithLoggedOnUsers_Value = "1"
$Reg_AUOptions_Name = "AUOptions"
$Reg_AUOptions_Value = "3"
if (!(Test-Path $Reg_NoAutoRebootWithLoggedOnUsers_AUOptions_Path)) { New-Item -Path $Reg_NoAutoRebootWithLoggedOnUsers_AUOptions_Path -Force | Out-Null }
New-ItemProperty -Path $Reg_NoAutoRebootWithLoggedOnUsers_AUOptions_Path -Name $Reg_NoAutoRebootWithLoggedOnUsers_Name -Value $Reg_NoAutoRebootWithLoggedOnUsers_Value -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $Reg_NoAutoRebootWithLoggedOnUsers_AUOptions_Path -Name $Reg_AUOptions_Name -Value $Reg_AUOptions_Value -PropertyType DWORD -Force | Out-Null

##### PART 3 #####
# Deny Wake my PC by Power settings
# Get-ScheduledTask | where {$_.settings.waketorun}
# https://www.tenforums.com/tutorials/63070-enable-disable-wake-timers-windows-10-a.html
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0

##### PART 4 #####
# Turn On Show More Windows Update Restart Notifications in Settings
# https://www.tenforums.com/tutorials/76305-turn-off-windows-update-restart-notifications-windows-10-a.html
$Reg_RestartNotificationsAllowed_Path = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
$Reg_RestartNotificationsAllowed_Name = "RestartNotificationsAllowed"
$Reg_RestartNotificationsAllowed2_Name = "RestartNotificationsAllowed"
$Reg_RestartNotificationsAllowed_Value = "1"
if (!(Test-Path $Reg_RestartNotificationsAllowed_Path)) { New-Item -Path $Reg_RestartNotificationsAllowed_Path -Force | Out-Null }
New-ItemProperty -Path $Reg_RestartNotificationsAllowed_Path -Name $Reg_RestartNotificationsAllowed_Name -Value $Reg_RestartNotificationsAllowed_Value -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $Reg_RestartNotificationsAllowed_Path -Name $Reg_RestartNotificationsAllowed2_Name -Value $Reg_RestartNotificationsAllowed_Value -PropertyType DWORD -Force | Out-Null

##### PART 5 #####
# Prohibition of waking from sleep by external devices
# https://www.vistax64.com/threads/power-options-and-sleep-mode-problems.63567/
$AllDevicesWakeUp = powercfg -devicequery wake_armed
foreach ($Device in $AllDevicesWakeUp) { if ($Device -ne "") { powercfg -devicedisablewake $Device } }

pause
# Done #