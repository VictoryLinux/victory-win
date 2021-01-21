# This script gives setup options for Win 10
# Author - VictoryLinux

#####################################################################
#  ____    ____  __                                                 #
#  \   \  /   / |__| ____ ________    ____    _______ ___  ___      #
#   \   \/   /  ___ |   _|\__   __\ /   _  \ |  __   |\  \/  /      #
#    \      /  |   ||  |_   |  |   |   |_|  ||  | |__| \   /        #
#     \____/   |___||____|  |__|    \_____ / |__|       |_|         #
#                                                                   #
# Victory Linux Fedora Install script                               #
# https://github.com/VictoryLinux                                   #
#####################################################################

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }

Write-Host "Logging Output"
Start-Transcript -path C:\victory-win\Log.txt -append

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
$Button = [System.Windows.MessageBoxButton]::YesNoCancel
$ErrorIco = [System.Windows.MessageBoxImage]::Error
$Ask = 'Do you want to run this as an Administrator?
        Select "Yes" to Run as an Administrator
        Select "No" to not run this as an Administrator
        
        Select "Cancel" to stop the script.'

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    $Prompt = [System.Windows.MessageBox]::Show($Ask, "Run as an Administrator or not?", $Button, $ErrorIco) 
    Switch ($Prompt) {

        Yes {
            Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
            Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
            Exit
        }
        No {
            Break
        }
    }
}

$Form                             = New-Object system.Windows.Forms.Form
$Form.ClientSize                  = New-Object System.Drawing.Point(750,630)
$Form.text                        = "VictoryWin 1.0"
$Form.TopMost                     = $false

$PictureBox1                      = New-Object system.Windows.Forms.PictureBox
$PictureBox1.width                = 575
$PictureBox1.height               = 80
$PictureBox1.location             = New-Object System.Drawing.Point(80,14)
$PictureBox1.imageLocation        = "https://github.com/VictoryLinux/victory-ame/blob/master/victorylinux.png?raw=true"
$PictureBox1.SizeMode             = [System.Windows.Forms.PictureBoxSizeMode]::zoom

$NameText                         = New-Object system.Windows.Forms.Label
$NameText.text                    = "PC's Name"
$NameText.width                   = 150
$NameText.height                  = 30
$NameText.location                = New-Object System.Drawing.Point(100,100)
$NameText.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',14)
$NameText.SelectionAlignment      = New-Object RichTextBox2.SelectionAlignment (HorizontalAlignment.Center)

$Name                             = New-Object system.Windows.Forms.RichTextBox
$Name.text                        = $Env:Computername
$Name.width                       = 200
$Name.height                      = 30
$Name.location                    = New-Object System.Drawing.Point(50,135)
$Name.Font                        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$WEditionText                     = New-Object system.Windows.Forms.Label
$WEditionText.text                = "Windows Edition"
$WEditionText.width               = 150
$WEditionText.height              = 30
$WEditionText.location            = New-Object System.Drawing.Point(300,100)
$WEditionText.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',14)
$WEditionText.SelectionAlignment  = New-Object RichTextBox2.SelectionAlignment (HorizontalAlignment.Center)

$WEdition                         = New-Object system.Windows.Forms.RichTextBox
$WEdition.text                    = (Get-WmiObject -class Win32_OperatingSystem).Caption
$WEdition.width                   = 200
$WEdition.height                  = 30
$WEdition.location                = New-Object System.Drawing.Point(275,135)
$WEdition.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$WEdition.SelectionAlignment      = New-Object RichTextBox2.SelectionAlignment (HorizontalAlignment.Center)

$VersionText                      = New-Object system.Windows.Forms.Label
$VersionText.text                 = "Feature Version"
$VersionText.width                = 200
$VersionText.height               = 30
$VersionText.location             = New-Object System.Drawing.Point(510,100)
$VersionText.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',14)
$VersionText.SelectionAlignment   = New-Object RichTextBox2.SelectionAlignment (HorizontalAlignment.Center)

$Version                          = New-Object system.Windows.Forms.RichTextBox
$Version.text                     = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId
$Version.width                    = 200
$Version.height                   = 30
$Version.location                 = New-Object System.Drawing.Point(500,135)
$Version.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$Version.SelectionAlignment       = New-Object RichTextBox2.SelectionAlignment (HorizontalAlignment.Center)

$InstallLabel                     = New-Object system.Windows.Forms.Label
$InstallLabel.text                = "Install"
$InstallLabel.width               = 150
$InstallLabel.height              = 20
$InstallLabel.location            = New-Object System.Drawing.Point(125,175)
$InstallLabel.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',14)
$InstallLabel.SelectionAlignment  = New-Object RichTextBox2.SelectionAlignment (HorizontalAlignment.Center)

$RemoveLabel                      = New-Object system.Windows.Forms.Label
$RemoveLabel.text                 = "Remove"
$RemoveLabel.width                = 150
$RemoveLabel.height               = 20
$RemoveLabel.location             = New-Object System.Drawing.Point(340,175)
$RemoveLabel.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',14)
$RemoveLabel.SelectionAlignment   = New-Object RichTextBox2.SelectionAlignment (HorizontalAlignment.Center) 

$UtilityLabel                     = New-Object system.Windows.Forms.Label
$UtilityLabel.text                = "Utility"
$UtilityLabel.width               = 150
$UtilityLabel.height              = 20
$UtilityLabel.location            = New-Object System.Drawing.Point(575,175)
$UtilityLabel.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',14)
$UtilityLabel.SelectionAlignment  = New-Object RichTextBox2.SelectionAlignment (HorizontalAlignment.Center)

$AutomateLabel                    = New-Object system.Windows.Forms.Label
$AutomateLabel.text               = "Automate"
$AutomateLabel.width              = 150
$AutomateLabel.height             = 20
$AutomateLabel.location           = New-Object System.Drawing.Point(325,510)
$AutomateLabel.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',14)
$AutomateLabel.SelectionAlignment = New-Object RichTextBox2.SelectionAlignment (HorizontalAlignment.Center)

# Utility
$AStatus                         = New-Object system.Windows.Forms.Button
$AStatus.text                    = "Activation Status"
$AStatus.width                   = 200
$AStatus.height                  = 30
$AStatus.location                = New-Object System.Drawing.Point(500,195)
$AStatus.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$AWindows                        = New-Object system.Windows.Forms.Button
$AWindows.text                   = "Activate Windows"
$AWindows.width                  = 200
$AWindows.height                 = 30
$AWindows.location               = New-Object System.Drawing.Point(500,230)
$AWindows.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$CRestorePoint                   = New-Object system.Windows.Forms.Button
$CRestorePoint.text              = "Create Restore Point"
$CRestorePoint.width             = 200
$CRestorePoint.height            = 30
$CRestorePoint.location          = New-Object System.Drawing.Point(500,270)
$CRestorePoint.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$DUac                            = New-Object system.Windows.Forms.Button
$DUac.text                       = "Disable UAC"
$DUac.width                      = 200
$DUac.height                     = 30
$DUac.location                   = New-Object System.Drawing.Point(500,305)
$DUac.Font                       = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$essentialtweaks                 = New-Object system.Windows.Forms.Button
$essentialtweaks.text            = "Essential Tweaks"
$essentialtweaks.width           = 200
$essentialtweaks.height          = 30
$essentialtweaks.location        = New-Object System.Drawing.Point(500,340)
$essentialtweaks.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$FTimeZone                       = New-Object system.Windows.Forms.Button
$FTimeZone.text                  = "Fix Time Zone"
$FTimeZone.width                 = 200
$FTimeZone.height                = 30
$FTimeZone.location              = New-Object System.Drawing.Point(500,375)
$FTimeZone.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$RenameComputer                  = New-Object system.Windows.Forms.Button
$RenameComputer.text             = "Rename Computer"
$RenameComputer.width            = 200
$RenameComputer.height           = 30
$RenameComputer.location         = New-Object System.Drawing.Point(500,410)
$RenameComputer.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$VLog                            = New-Object system.Windows.Forms.Button
$VLog.text                       = "View Log"
$VLog.width                      = 200
$VLog.height                     = 30
$VLog.location                   = New-Object System.Drawing.Point(500,510)
$VLog.Font                       = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

# Remove
$UUpgrade                        = New-Object system.Windows.Forms.Button
$UUpgrade.text                   = "Clean-up Feature Upgrade"
$UUpgrade.width                  = 200
$UUpgrade.height                 = 30
$UUpgrade.location               = New-Object System.Drawing.Point(275,195)
$UUpgrade.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$Debloat                         = New-Object system.Windows.Forms.Button
$DeBloat.text                    = "Debloat Windows 10"
$DeBloat.width                   = 200
$DeBloat.height                  = 30
$DeBloat.location                = New-Object System.Drawing.Point(275,230)
$DeBloat.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

# Install
$FUpgrade                        = New-Object system.Windows.Forms.Button
$FUpgrade.text                   = "Install Feature Upgrade"
$FUpgrade.width                  = 200
$FUpgrade.height                 = 30
$FUpgrade.location               = New-Object System.Drawing.Point(50,195)
$FUpgrade.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$IWUpdates                       = New-Object system.Windows.Forms.Button
$IWUpdates.text                  = "Install Windows Updates"
$IWUpdates.width                 = 200
$IWUpdates.height                = 30
$IWUpdates.location              = New-Object System.Drawing.Point(50,230)
$IWUpdates.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$Ichoco                          = New-Object system.Windows.Forms.Button
$Ichoco.text                     = "Install Chocolatey PM"
$Ichoco.width                    = 200
$Ichoco.height                   = 30
$Ichoco.location                 = New-Object System.Drawing.Point(50,300)
$Ichoco.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$Ipackages                       = New-Object system.Windows.Forms.Button
$Ipackages.text                  = "Install All Packages"
$Ipackages.width                 = 200
$Ipackages.height                = 30
$Ipackages.location              = New-Object System.Drawing.Point(50,335)
$Ipackages.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$Igaming                         = New-Object system.Windows.Forms.Button
$Igaming.text                    = "Install All Gaming Packages"
$Igaming.width                   = 200
$Igaming.height                  = 30
$Igaming.location                = New-Object System.Drawing.Point(50,370)
$Igaming.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$Ibrowsers                       = New-Object system.Windows.Forms.Button
$Ibrowsers.text                  = "Install Web Browsers Only"
$Ibrowsers.width                 = 200
$Ibrowsers.height                = 30
$Ibrowsers.location              = New-Object System.Drawing.Point(50,405)
$Ibrowsers.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

# Automate
$Automate                        = New-Object system.Windows.Forms.Button
$Automate.text                   = "Automate Setup"
$Automate.width                  = 200
$Automate.height                 = 30
$Automate.location               = New-Object System.Drawing.Point(275,545)
$Automate.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

# Fin
$LogOut                          = New-Object system.Windows.Forms.Button
$LogOut.text                     = "Log Out"
$LogOut.width                    = 200
$LogOut.height                   = 30
$LogOut.location                 = New-Object System.Drawing.Point(50,580)
$LogOut.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$Restart                         = New-Object system.Windows.Forms.Button
$Restart.text                    = "Restart Computer"
$Restart.width                   = 200
$Restart.height                  = 30
$Restart.location                = New-Object System.Drawing.Point(275,580)
$Restart.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$ShutDown                        = New-Object system.Windows.Forms.Button
$ShutDown.text                   = "Shutdown Computer"
$ShutDown.width                  = 200
$ShutDown.height                 = 30
$ShutDown.location               = New-Object System.Drawing.Point(500,580)
$ShutDown.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',11)

$Form.controls.AddRange(@($PictureBox1,$NameText,$Name,$WEditionText,$WEdition,$VersionText,$InstallLabel,$RemoveLabel,$UtilityLabel,$Version,$AutomateLabel,$CRestorePoint,$AStatus,$AWindows,$FTimeZone,$RenameComputer,$RSystemUpdate,$VLog,$IWUpdates,$FUpgrade,$Ichoco,$Ipackages,$Igaming,$essentialtweaks,$UUpgrade,$DUac,$Automate,$LogOut,$Restart,$ShutDown))
$wshell.Popup("                    Welcome to VictoryLinux

                         Windows 10 Setup



          Select the Option that fits your needs.",0,"VictoryLinux-Win",0x0)

#########################
#                       #
#        Utility        #
#                       #
#########################

# Activation Status
$AStatus.Add_Click({
    clear
    Write-Host "Querying Windows Activation Status... "
    slmgr /xpr
    Write-Host "Complete - Activation Status displayed" -ForegroundColor Green
})

# Activate Windows 10.
$AWindows.Add_Click({ 
    clear
    Write-Host "Activating Windows 10... "
    changepk.exe
})

# Create a Restore Point.
$CRestorePoint.Add_Click({ 
    clear
    Write-Host "Creating a System Restore Point... "
    Enable-ComputerRestore -Drive "C:\"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Type DWord -Value 0
    Checkpoint-Computer -Description "VictoryBackup" -RestorePointType "MODIFY_SETTINGS"
    Write-Host "Complete - Restore Point Created" -ForegroundColor Green
    $wshell.Popup("Complete - Restore Point Created",0,"Complete",0x0)
})

# Disable UAC settings by moving it to the lowest security setting.
$DUac.Add_Click({
    clear
    Write-Host "Disabling UAC... "
    Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
    Write-Host "Complete - Windows UAC has been Disabled" -ForegroundColor Green
    $wshell.Popup("Complete - Windows UAC has been Disabled",0,"Complete",0x0)
})

# Fix the Time Zone by setting it to Central time zone.
$FTimeZone.Add_Click({
    clear
    Write-Host "Setting Time Zone... "
    Set-TimeZone -Name "Central Standard Time"
    $DateTime = Get-Date
    $DateTime
    $DateTime.ToUniversalTime()
    Write-Host "Complete - Time Zone set to Central Time" -ForegroundColor Green
    $wshell.Popup("Complete - Time Zone set to Central Time",0,"Complete",0x0)
})

# Rename your PC.
$RenameComputer.Add_Click({
    clear
    $wshell.Popup("Please respond to the prompt in the Powershell Window to Rename this PC.",0,"Notice",0x0)
    Write-Host "Renaming Computer... "
    Rename-Computer
    $wshell.Popup("Complete - Please Reboot.",0,"Complete",0x0)
})

$VLog.Add_Click({
    Write-Host "View Victory-Win Setup Log... "
    notepad C:\victory-win\Log.txt
    Write-Host "Complete - Victory-Win Log has launched." -ForegroundColor Green
})

    $DesktopPath = [Environment]::GetFolderPath("Desktop")

#########################
#                       #
#        Install        #
#                       #
#########################

# Install Windows 10 Upgrade Assistant & install latest feature Update.
$FUpgrade.Add_Click({
    clear
    $wshell.Popup("The Feature Upgrade has started
    DO NOT RESTART THIS PC UNTIL PROMPTED TO DO SO
    Once Finished, restart then Run Clean-up Feature Update Option to remove leftover files",0,"Complete",0x0)
    Write-Host "Starting Windows Feature Upgrade... "
    $dir = 'C:\WcsSetupLite\_Windows_FU\packages'
    mkdir $dir
    $webClient = New-Object System.Net.WebClient
    $url = 'https://go.microsoft.com/fwlink/?LinkID=799445'
    $file = "$($dir)\Win10Upgrade.exe"
    $webClient.DownloadFile($url,$file)
    Start-Process -FilePath $file -ArgumentList '<#/quietinstall#> /skipeula /auto upgrade /copylogs $dir' 
    Write-Host "The Feature Upgrade has started... " -BackgroundColor Red
    Write-Host "DO NOT RESTART THIS PC UNTIL PROMPTED TO DO SO... " -BackgroundColor Red
    Write-Host "Once Finished, restart then Run Clean-up Feature Update Option to remove leftover files... " -BackgroundColor Red
#    $wshell.Popup("Complete - Activ Driver is installed",0,"Complete",0x0)
})

$IWUpdates.Add_Click({
    clear
    Write-Host "Updating Windows Packages... "
    $wshell.Popup("Make sure you have installed Chocolatey PM before running this
        This update process will not work without it.",0,"Notice",0x0)
    choco upgrade all -y
    $wshell.Popup("This Action Requires Manual Intervention
You will have to respond to several prompts in the Powershell Window.",0,"Notice",0x0)
    Write-Host "Installing Windows Updates... "
#    Start-Sleep -s 25
    Install-Module PSWindowsUpdate
    Start-Sleep -s 15
    Import-Module PSWindowsUpdate
    Start-Sleep -s 15
    Get-WindowsUpdate
    Start-Sleep -s 25
    Install-WindowsUpdate
    Start-Sleep -s 25
    Write-Host "Complete - Windows Updates are finished running." -ForegroundColor Green
    $wshell.Popup("Complete - Windows Updates are finished running",0,"Complete",0x0)
})

$Ichoco.Add_Click({
    clear
    Write-Host "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco install chocolatey-core.extension -y
    Write-Host "Complete - Installed Chocolatey." -ForegroundColor Green
})

$Ipackages.Add_Click({
    clear
    Write-Host "Installing VictoryLinux-Win Packages..."
    start-sleep 6s
    Write-Host "Installing Git..."
    start-sleep 6s
    choco install git -y
    Write-Host "Complete - Installed Git." -ForegroundColor Green
    Write-Host "Installing Brave Browser..."
    start-sleep 6s
    choco install brave -y
    Write-Host "Complete - Installed Brave Browser." -ForegroundColor Green
    Write-Host "Installing Firefox Browser..."
    start-sleep 6s
    choco install firefox -y
    Write-Host "Complete - Installed Firefox Browser." -ForegroundColor Green
    Write-Host "Installing Chromium Browser..."
    start-sleep 6s
    choco install chromium -y
    Write-Host "Complete - Installed Chromium Browser." -ForegroundColor Green
    Write-Host "Installing Irfanview (Image Viewer)..."
    start-sleep 6s
    choco install irfanview -y
    Write-Host "Complete - Installed Irfanview (Image Viewer)." -ForegroundColor Green
    Write-Host "Installing Adobe Reader DC..."
    start-sleep 6s
    choco install adobereader -y
    Write-Host "Complete - Installed Adobe Reader DC." -ForegroundColor Green
    Write-Host "Installing Sublime Text 3..."
    start-sleep 6s
    choco install sublimetext3 -y
    Write-Host "Complete - Installed Sublime Text 3." -ForegroundColor Green
    Write-Host "Installing VLC Media Player..."
    start-sleep 6s
    choco install vlc -y
    Write-Host "Complete - Installed VLC Media Player." -ForegroundColor Green
    Write-Host "Installing 7-Zip..."
    start-sleep 6s
    choco install 7zip -y
    Write-Host "Complete - Installed 7-Zip." -ForegroundColor Green
    Write-Host "Installing WinRAR..."
    start-sleep 6s
    choco install winrar -y
    Write-Host "Complete - Installed WinRAR." -ForegroundColor Green
    Write-Host "Installing New Windows Terminal..."
    start-sleep 6s
    choco install microsoft-windows-terminal -y
    Write-Host "Complete - Installed New Windows Terminal." -ForegroundColor Green
    Write-Host "Installing Simplenote..."
    start-sleep 6s
    choco install simplenote -y
    Write-Host "Complete - Installed Simplenote." -ForegroundColor Green
    Write-Host "Installing Remote Desktop Packages..."
    start-sleep 6s
    choco install vnc-viewer vnc-connect teamviewer -y
    Write-Host "Complete - Installed Remote Desktop Packages." -ForegroundColor Green
    Write-Host "Installing Bitwarden..."
    start-sleep 6s
    choco install bitwarden -y
    Write-Host "Complete - Installed Bitwarden." -ForegroundColor Green
    Write-Host "Installing Onlyoffice..."
    start-sleep 6s
    choco install onlyoffice -y
    Write-Host "Complete - Installed Onlyoffice." -ForegroundColor Green
    Write-Host "Installing Partition Wizard..."
    start-sleep 6s
    choco install partitionwizard -y
    Write-Host "Complete - Installed Partition Wizard." -ForegroundColor Green
    Write-Host "Installing Virtualbox..."
    start-sleep 6s
    choco install virtualbox -y
    Write-Host "Complete - Installed Virtualbox." -ForegroundColor Green
    Write-Host "Installing Virtualbox..."
    start-sleep 6s
    choco install virtualbox -y
    Write-Host "Complete - Installed Virtualbox." -ForegroundColor Green
})

$Igaming.Add_Click({
    clear
    Write-Host "Installing VictoryLinux-Win Gaming Packages..."
    start-sleep 6s
    Write-Host "Installing Discord..."
    start-sleep 6s
    choco install discord -y
    Write-Host "Complete - Installed Discord." -ForegroundColor Green
    Write-Host "Installing tukui..."
    start-sleep 6s
    choco install discord -y
    Write-Host "Complete - Installed tukui." -ForegroundColor Green
    Write-Host "Installing Razer-Synapse-2..."
    start-sleep 6s
    choco install razer-synapse-2 -y
    Write-Host "Complete - Installed Razer-Synapse-2." -ForegroundColor Green
})

#########################
#                       #
#        Remove         #
#                       #
#########################

$essentialtweaks.Add_Click({ 
    Write-Host "Creating Restore Point incase something bad happens..."
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"

    Write-Host "Running O&O Shutup with Recommended Settings"
    Import-Module BitsTransfer      choco install shutup10 -y
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg" -Destination ooshutup10.cfg     OOSU10 ooshutup10.cfg /quiet
    Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe    
    ./OOSU10.exe ooshutup10.cfg /quiet

    Write-Host "Disabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
    Write-Host "Disabling Application suggestions..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    Write-Host "Disabling Activity History..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    Write-Host "Disabling Location Tracking..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    Write-Host "Disabling automatic Maps updates..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Write-Host "Disabling Feedback..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Disabling Tailored Experiences..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Write-Host "Disabling Advertising ID..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Write-Host "Disabling Error reporting..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
    Write-Host "Restricting Windows Update P2P only to local network..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
    Write-Host "Stopping and disabling Diagnostics Tracking Service..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
    Write-Host "Stopping and disabling WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
    Write-Host "Enabling F8 boot menu options..."
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
    Write-Host "Stopping and disabling Home Groups services..."
    Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
    Set-Service "HomeGroupListener" -StartupType Disabled
    Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
    Set-Service "HomeGroupProvider" -StartupType Disabled
    Write-Host "Disabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
    Write-Host "Disabling Storage Sense..."
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
    Write-Host "Stopping and disabling Superfetch service..."
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
    Write-Host "Setting BIOS time to UTC..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
    Write-Host "Disabling Hibernation..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
    Write-Host "Showing task manager details..."
    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
    Do {
        Start-Sleep -Milliseconds 100
        $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    } Until ($preferences)
    Stop-Process $taskmgr
    $preferences.Preferences[28] = 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    Write-Host "Showing file operations details..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
    Write-Host "Hiding Task View button..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
    Write-Host "Hiding People icon..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    Write-Host "Showing all tray icons..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
    Write-Host "Enabling NumLock after startup..."
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
    Add-Type -AssemblyName System.Windows.Forms
    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }

    Write-Host "Changing default Explorer view to This PC..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
    Write-Host "Hiding 3D Objects icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

    Write-Host "Changing default Explorer view to This PC..."


    Write-Host "Enabling Dark Mode"
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0

    Write-Output "Unpinning all Taskbar icons..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue

    Write-Output "Hiding Taskbar Search icon / box..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    taskkill /IM explorer.exe /F
    explorer.exe

$Bloatware = @(

        #Unnecessary Windows 10 AppX Apps
        "Microsoft.3DBuilder"
        "Microsoft.AppConnector"
        "Microsoft.BingFinance"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingTranslator"
        "Microsoft.BingWeather"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.SkypeApp"
        "Microsoft.StorePurchaseApp"
        "Microsoft.Wallet"
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"

        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
        "*Viber*"
        "*ACGMediaPlayer*"
        "*Netflix*"
        "*OneCalendar*"
        "*LinkedInforWindows*"
        "*HiddenCityMysteryofShadows*"
        "*Hulu*"
        "*HiddenCity*"
        "*AdobePhotoshopExpress*"
                     
        #Optional: Typically not removed but you can if you need to for some reason
        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
        #"*Microsoft.BingWeather*"
        #"*Microsoft.MSPaint*"
        #"*Microsoft.MicrosoftStickyNotes*"
        #"*Microsoft.Windows.Photos*"
        #"*Microsoft.WindowsCalculator*"
        #"*Microsoft.WindowsStore*"
    )
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Host "Trying to remove $Bloat."
    }

    Write-Host "Installing Windows Media Player..."
    Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null

    #Stops edge from taking over as the default .PDF viewer    
    Write-Host "Stopping Edge from taking over as the default .PDF viewer"
    # Identify the edge application class 
    $Packages = "HKCU:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" 
    $edge = Get-ChildItem $Packages -Recurse -include "MicrosoftEdge" 
        
    # Specify the paths to the file and URL associations 
    $FileAssocKey = Join-Path $edge.PSPath Capabilities\FileAssociations 
    $URLAssocKey = Join-Path $edge.PSPath Capabilities\URLAssociations 
        
    # get the software classes for the file and URL types that Edge will associate 
    $FileTypes = Get-Item $FileAssocKey 
    $URLTypes = Get-Item $URLAssocKey 
        
    $FileAssoc = Get-ItemProperty $FileAssocKey 
    $URLAssoc = Get-ItemProperty $URLAssocKey 
        
    $Associations = @() 
    $Filetypes.Property | foreach {$Associations += $FileAssoc.$_} 
    $URLTypes.Property | foreach {$Associations += $URLAssoc.$_} 
        
    # add registry values in each software class to stop edge from associating as the default 
    foreach ($Association in $Associations) 
            { 
            $Class = Join-Path HKCU:SOFTWARE\Classes $Association 
            #if (Test-Path $class) 
            #   {write-host $Association} 
            # Get-Item $Class 
            Set-ItemProperty $Class -Name NoOpenWith -Value "" 
            Set-ItemProperty $Class -Name NoStaticDefaultVerb -Value "" 
            } 
            
    
    #Removes Paint3D stuff from context menu
$Paint3Dstuff = @(
        "HKCR:\SystemFileAssociations\.3mf\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.bmp\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.fbx\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.gif\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.jfif\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.jpe\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.jpeg\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.jpg\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.png\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.tif\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.tiff\Shell\3D Edit"
    )
    #Rename reg key to remove it, so it's revertible
    foreach ($Paint3D in $Paint3Dstuff) {
        If (Test-Path $Paint3D) {
        $rmPaint3D = $Paint3D + "_"
        Set-Item $Paint3D $rmPaint3D
    }
    }
    
    taskkill /IM explorer.exe /F
    explorer.exe
    
    $wshell.Popup("Operation Completed",0,"Done",0x0)


})

$windowssearch.Add_Click({ 
    Write-Host "Disabling Bing Search in Start Menu..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    Write-Host "Stopping and disabling Windows Search indexing service..."
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
    Write-Host "Hiding Taskbar Search icon / box..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    $wshell.Popup("Operation Completed",0,"Done",0x0)
})

# Uninstall Windows 10 Upgrade Assistant and remove all leftover files.
$UUpgrade.Add_Click({
    clear
    Write-Host "Cleaning up Windows Feature Upgrade Leftovers... "
    C:\Windows10Upgrade\Windows10UpgraderApp.exe /ForceUninstall
    Start-Sleep -s 10
    Del C:\Windows\UpdateAssistant\*.* /F /Q
    Write-Host "Complete - Uninstalled Upgrade Assistant and leftover files removed" -ForegroundColor Green
    $wshell.Popup("Complete - Uninstalled Upgrade Assistant and leftover files removed",0,"Complete",0x0)
})

#########################
#                       #
#       Automate        #
#                       #
#########################

## Automate setting up a PC with the following:
# Create a restore Point
# Fix the Time Zone, Set to Central Time.
# Debloat Windows 10, removing Unnecessary and bloatware software.

$Automate.Add_Click({ 
    clear
    Write-Host "Creating a System Restore Point... "
    Enable-ComputerRestore -Drive "C:\"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Type DWord -Value 0
    Checkpoint-Computer -Description "VictoryBackup" -RestorePointType "MODIFY_SETTINGS"
    Start-Sleep -s 50
    Write-Host "Complete - Restore Point Created" -ForegroundColor Green
    start-sleep -s 15

    # Essential Tweaks
    Write-Host "Running O&O Shutup with Recommended Settings"
    Import-Module BitsTransfer      choco install shutup10 -y
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg" -Destination ooshutup10.cfg     OOSU10 ooshutup10.cfg /quiet
    Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe    
    ./OOSU10.exe ooshutup10.cfg /quiet

    Write-Host "Disabling UAC... "
    Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
    Write-Host "Complete - Windows UAC has been Disabled" -ForegroundColor Green
    
    # Fix the Time Zone by setting it to Central time zone.
    Write-Host "Setting Time Zone... "
    Set-TimeZone -Name "Central Standard Time"
    $DateTime = Get-Date
    $DateTime
    $DateTime.ToUniversalTime()
    Write-Host "Complete - Time Zone set to Central Time" -ForegroundColor Green
    
    # Rename your PC.
    $wshell.Popup("Please respond to the prompt in the Powershell Window to Rename this PC.",0,"Notice",0x0)
    Write-Host "Renaming Computer... "
    Rename-Computer

    Write-Host "Disabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
    Write-Host "Disabling Application suggestions..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    Write-Host "Disabling Activity History..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    Write-Host "Disabling Location Tracking..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    Write-Host "Disabling automatic Maps updates..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Write-Host "Disabling Feedback..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Disabling Tailored Experiences..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Write-Host "Disabling Advertising ID..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Write-Host "Disabling Error reporting..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
    Write-Host "Restricting Windows Update P2P only to local network..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
    Write-Host "Stopping and disabling Diagnostics Tracking Service..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
    Write-Host "Stopping and disabling WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
    Write-Host "Enabling F8 boot menu options..."
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
    Write-Host "Stopping and disabling Home Groups services..."
    Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
    Set-Service "HomeGroupListener" -StartupType Disabled
    Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
    Set-Service "HomeGroupProvider" -StartupType Disabled
    Write-Host "Disabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
    Write-Host "Disabling Storage Sense..."
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
    Write-Host "Stopping and disabling Superfetch service..."
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
    Write-Host "Setting BIOS time to UTC..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
    Write-Host "Disabling Hibernation..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
    Write-Host "Showing task manager details..."
    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
    Do {
        Start-Sleep -Milliseconds 100
        $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    } Until ($preferences)
    Stop-Process $taskmgr
    $preferences.Preferences[28] = 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    Write-Host "Showing file operations details..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
    Write-Host "Hiding Task View button..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
    Write-Host "Hiding People icon..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    Write-Host "Showing all tray icons..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
    Write-Host "Enabling NumLock after startup..."
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
    Add-Type -AssemblyName System.Windows.Forms
    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }

    Write-Host "Changing default Explorer view to This PC..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
    Write-Host "Hiding 3D Objects icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

    Write-Host "Changing default Explorer view to This PC..."


    Write-Host "Enabling Dark Mode"
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0

    Write-Output "Unpinning all Taskbar icons..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue

    Write-Output "Hiding Taskbar Search icon / box..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    taskkill /IM explorer.exe /F
    explorer.exe

$Bloatware = @(

        #Unnecessary Windows 10 AppX Apps
        "Microsoft.3DBuilder"
        "Microsoft.AppConnector"
        "Microsoft.BingFinance"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingTranslator"
        "Microsoft.BingWeather"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.SkypeApp"
        "Microsoft.StorePurchaseApp"
        "Microsoft.Wallet"
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"

        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
        "*Viber*"
        "*ACGMediaPlayer*"
        "*Netflix*"
        "*OneCalendar*"
        "*LinkedInforWindows*"
        "*HiddenCityMysteryofShadows*"
        "*Hulu*"
        "*HiddenCity*"
        "*AdobePhotoshopExpress*"
                     
        #Optional: Typically not removed but you can if you need to for some reason
        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
        #"*Microsoft.BingWeather*"
        #"*Microsoft.MSPaint*"
        #"*Microsoft.MicrosoftStickyNotes*"
        #"*Microsoft.Windows.Photos*"
        #"*Microsoft.WindowsCalculator*"
        #"*Microsoft.WindowsStore*"
    )
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Host "Trying to remove $Bloat."
    }

    Write-Host "Installing Windows Media Player..."
    Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null

    #Stops edge from taking over as the default .PDF viewer    
    Write-Host "Stopping Edge from taking over as the default .PDF viewer"
    # Identify the edge application class 
    $Packages = "HKCU:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" 
    $edge = Get-ChildItem $Packages -Recurse -include "MicrosoftEdge" 
        
    # Specify the paths to the file and URL associations 
    $FileAssocKey = Join-Path $edge.PSPath Capabilities\FileAssociations 
    $URLAssocKey = Join-Path $edge.PSPath Capabilities\URLAssociations 
        
    # get the software classes for the file and URL types that Edge will associate 
    $FileTypes = Get-Item $FileAssocKey 
    $URLTypes = Get-Item $URLAssocKey 
        
    $FileAssoc = Get-ItemProperty $FileAssocKey 
    $URLAssoc = Get-ItemProperty $URLAssocKey 
        
    $Associations = @() 
    $Filetypes.Property | foreach {$Associations += $FileAssoc.$_} 
    $URLTypes.Property | foreach {$Associations += $URLAssoc.$_} 
        
    # add registry values in each software class to stop edge from associating as the default 
    foreach ($Association in $Associations) 
            { 
            $Class = Join-Path HKCU:SOFTWARE\Classes $Association 
            #if (Test-Path $class) 
            #   {write-host $Association} 
            # Get-Item $Class 
            Set-ItemProperty $Class -Name NoOpenWith -Value "" 
            Set-ItemProperty $Class -Name NoStaticDefaultVerb -Value "" 
            } 
            
    
    #Removes Paint3D stuff from context menu
$Paint3Dstuff = @(
        "HKCR:\SystemFileAssociations\.3mf\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.bmp\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.fbx\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.gif\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.jfif\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.jpe\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.jpeg\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.jpg\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.png\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.tif\Shell\3D Edit"
    "HKCR:\SystemFileAssociations\.tiff\Shell\3D Edit"
    )
    #Rename reg key to remove it, so it's revertible
    foreach ($Paint3D in $Paint3Dstuff) {
        If (Test-Path $Paint3D) {
        $rmPaint3D = $Paint3D + "_"
        Set-Item $Paint3D $rmPaint3D
    }
    }
    start-sleep -s 15
    Write-Host "Disabling Bing Search in Start Menu..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    Write-Host "Stopping and disabling Windows Search indexing service..."
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
    Write-Host "Hiding Taskbar Search icon / box..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    taskkill /IM explorer.exe /F
    explorer.exe
    start-sleep -s 15

    # Installing Packages
    clear
    Write-Host "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco install chocolatey-core.extension -y
    Write-Host "Complete - Installed Chocolatey." -ForegroundColor Green

    Write-Host "Installing VictoryLinux-Win Packages..."
    start-sleep 6s
    Write-Host "Installing Git..."
    start-sleep 6s
    choco install git -y
    Write-Host "Complete - Installed Git." -ForegroundColor Green
    Write-Host "Installing Brave Browser..."
    start-sleep 6s
    choco install brave -y
    Write-Host "Complete - Installed Brave Browser." -ForegroundColor Green
    Write-Host "Installing Firefox Browser..."
    start-sleep 6s
    choco install firefox -y
    Write-Host "Complete - Installed Firefox Browser." -ForegroundColor Green
    Write-Host "Installing Chromium Browser..."
    start-sleep 6s
    choco install chromium -y
    Write-Host "Complete - Installed Chromium Browser." -ForegroundColor Green
    Write-Host "Installing Irfanview (Image Viewer)..."
    start-sleep 6s
    choco install irfanview -y
    Write-Host "Complete - Installed Irfanview (Image Viewer)." -ForegroundColor Green
    Write-Host "Installing Adobe Reader DC..."
    start-sleep 6s
    choco install adobereader -y
    Write-Host "Complete - Installed Adobe Reader DC." -ForegroundColor Green
    Write-Host "Installing Sublime Text 3..."
    start-sleep 6s
    choco install sublimetext3 -y
    Write-Host "Complete - Installed Sublime Text 3." -ForegroundColor Green
    Write-Host "Installing VLC Media Player..."
    start-sleep 6s
    choco install vlc -y
    Write-Host "Complete - Installed VLC Media Player." -ForegroundColor Green
    Write-Host "Installing 7-Zip..."
    start-sleep 6s
    choco install 7zip -y
    Write-Host "Complete - Installed 7-Zip." -ForegroundColor Green
    Write-Host "Installing WinRAR..."
    start-sleep 6s
    choco install winrar -y
    Write-Host "Complete - Installed WinRAR." -ForegroundColor Green
    Write-Host "Installing New Windows Terminal..."
    start-sleep 6s
    choco install microsoft-windows-terminal -y
    Write-Host "Complete - Installed New Windows Terminal." -ForegroundColor Green
    Write-Host "Installing Simplenote..."
    start-sleep 6s
    choco install simplenote -y
    Write-Host "Complete - Installed Simplenote." -ForegroundColor Green
    Write-Host "Installing Remote Desktop Packages..."
    start-sleep 6s
    choco install vnc-viewer vnc-connect teamviewer -y
    Write-Host "Complete - Installed Remote Desktop Packages." -ForegroundColor Green
    Write-Host "Installing Bitwarden..."
    start-sleep 6s
    choco install bitwarden -y
    Write-Host "Complete - Installed Bitwarden." -ForegroundColor Green
    Write-Host "Installing Onlyoffice..."
    start-sleep 6s
    choco install onlyoffice -y
    Write-Host "Complete - Installed Onlyoffice." -ForegroundColor Green
    Write-Host "Installing Partition Wizard..."
    start-sleep 6s
    choco install partitionwizard -y
    Write-Host "Complete - Installed Partition Wizard." -ForegroundColor Green
    Write-Host "Installing Virtualbox..."
    start-sleep 6s
    choco install virtualbox -y
    Write-Host "Complete - Installed Virtualbox." -ForegroundColor Green
    
    $wshell.Popup("Automate Script Complete",0,"Complete",0x0)
    
})

#########################
#                       #
#          Fin          #
#                       #
#########################

$LogOut.Add_Click({ 
    clear
    Write-Host "Signing Out current User... "
    ((Get-WmiObject -Class Win32_Process).getowner().user | Select-Object -Unique) |% {query session $_ | where-object {($_ -notmatch 'console') -and ($_ -match 'disc') -and ($_ -notmatch 'services')}| logoff}
    Write-Host "Complete - Signing Out." -ForegroundColor Green
})

$Restart.Add_Click({ 
    clear
    Write-Host "Restarting Computer... "
    Restart-Computer
    Write-Host "Complete - Restarting" -ForegroundColor Green
})

$ShutDown.Add_Click({ 
    clear
    Write-Host "Shutting Down Computer... "
    Stop-Computer
    Write-Host "Complete - Shutting Down Computer" -ForegroundColor Green
})



[void]$Form.ShowDialog()

Stop-Transcript
