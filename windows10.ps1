

function Set-Defender {
    Set-MpPreference -DisableRealtimeMonitoring $False
    Set-MpPreference -DisableIOAVProtection $False
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
    start-service WinDefend
    start-service WdNisSvc
    Set-MpPreference -AllowDatagramProcessingOnWinServer $False
    Set-MpPreference -AllowNetworkProtectionDownLevel $False
    Set-MpPreference -AllowNetworkProtectionOnWinServer $False
    Set-MpPreference -AllowSwitchToAsyncInspection $False
    Set-MpPreference -AttackSurfaceReductionOnlyExclusions ""
    Set-MpPreference -AttackSurfaceReductionRules_Actions ""
    Set-MpPreference -AttackSurfaceReductionRules_Ids ""
    Set-MpPreference -CheckForSignaturesBeforeRunningScan $False
    Set-MpPreference -CloudBlockLevel 0
    Set-MpPreference -CloudExtendedTimeout 0
    Set-MpPreference -ControlledFolderAccessAllowedApplications ""
    Set-MpPreference -ControlledFolderAccessProtectedFolders ""
    Set-MpPreference -DefinitionUpdatesChannel 0
    Set-MpPreference -DisableArchiveScanning $False
    Set-MpPreference -DisableAutoExclusions $False
    Set-MpPreference -DisableBehaviorMonitoring $False
    Set-MpPreference -DisableBlockAtFirstSeen $False
    Set-MpPreference -DisableCatchupFullScan $True
    Set-MpPreference -DisableCatchupQuickScan $True
    Set-MpPreference -DisableCpuThrottleOnIdleScans $True
    Set-MpPreference -DisableDatagramProcessing $False
    Set-MpPreference -DisableDnsOverTcpParsing $False
    Set-MpPreference -DisableDnsParsing $False
    Set-MpPreference -DisableEmailScanning $True
    Set-MpPreference -DisableFtpParsing $False
    Set-MpPreference -DisableGradualRelease $False
    Set-MpPreference -DisableHttpParsing $False
    Set-MpPreference -DisableInboundConnectionFiltering $False
    Set-MpPreference -DisableNetworkProtectionPerfTelemetry $False
    Set-MpPreference -DisablePrivacyMode $False
    Set-MpPreference -DisableRdpParsing $False
    Set-MpPreference -DisableRemovableDriveScanning $True
    Set-MpPreference -DisableRestorePoint $True
    Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $True
    Set-MpPreference -DisableScanningNetworkFiles $False
    Set-MpPreference -DisableScriptScanning $False
    Set-MpPreference -DisableSshParsing $False
    Set-MpPreference -DisableTDTFeature $False
    Set-MpPreference -DisableTlsParsing $False
    Set-MpPreference -EnableControlledFolderAccess 0
    Set-MpPreference -EnableDnsSinkhole $True
    Set-MpPreference -EnableFileHashComputation $False
    Set-MpPreference -EnableFullScanOnBatteryPower $False
    Set-MpPreference -EnableLowCpuPriority $False
    Set-MpPreference -EnableNetworkProtection 0
    Set-MpPreference -EngineUpdatesChannel 0
    Set-MpPreference -ExclusionExtension ""
    Set-MpPreference -ExclusionIpAddress ""
    Set-MpPreference -ExclusionPath ""
    Set-MpPreference -ExclusionProcess ""
    Set-MpPreference -ForceUseProxyOnly $False
    Set-MpPreference -HighThreatDefaultAction 0
    Set-MpPreference -LowThreatDefaultAction 0
    Set-MpPreference -MAPSReporting 2
    Set-MpPreference -MeteredConnectionUpdates $False
    Set-MpPreference -ModerateThreatDefaultAction 0
    Set-MpPreference -PlatformUpdatesChannel 0
    Set-MpPreference -ProxyBypass ""
    Set-MpPreference -ProxyPacUrl ""
    Set-MpPreference -ProxyServer ""
    Set-MpPreference -PUAProtection 0
    Set-MpPreference -QuarantinePurgeItemsAfterDelay 90
    Set-MpPreference -RandomizeScheduleTaskTimes $True
    Set-MpPreference -RealTimeScanDirection 0
    Set-MpPreference -RemediationScheduleDay 0
    Set-MpPreference -RemediationScheduleTime 020000
    Set-MpPreference -ReportingAdditionalActionTimeOut 10080
    Set-MpPreference -ReportingCriticalFailureTimeOut 10080
    Set-MpPreference -ReportingNonCriticalTimeOut 1440
    Set-MpPreference -ScanAvgCPULoadFactor 50
    Set-MpPreference -ScanOnlyIfIdleEnabled $True
    Set-MpPreference -ScanParameters 1
    Set-MpPreference -ScanPurgeItemsAfterDelay 15
    Set-MpPreference -ScanScheduleDay 0
    Set-MpPreference -ScanScheduleOffset 120
    Set-MpPreference -ScanScheduleQuickScanTime 000000
    Set-MpPreference -ScanScheduleTime 020000
    Set-MpPreference -SchedulerRandomizationTime 4
    Set-MpPreference -ServiceHealthReportInterval 60
    Set-MpPreference -SevereThreatDefaultAction 0
    Set-MpPreference -SharedSignaturesPath ""
    Set-MpPreference -SignatureAuGracePeriod 0
    Set-MpPreference -SignatureBlobFileSharesSources ""
    Set-MpPreference -SignatureBlobUpdateInterval 60
    Set-MpPreference -SignatureDefinitionUpdateFileSharesSources ""
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $False
    Set-MpPreference -SignatureFallbackOrder MicrosoftUpdateServer|MMPC
    Set-MpPreference -SignatureFirstAuGracePeriod 120
    Set-MpPreference -SignatureScheduleDay Everyday
    Set-MpPreference -SignatureScheduleTime 120
    Set-MpPreference -SignatureUpdateCatchupInterval 1
    Set-MpPreference -SignatureUpdateInterval 0
    Set-MpPreference -SubmitSamplesConsent 1
    Set-MpPreference -ThreatIDDefaultAction_Actions ""
    Set-MpPreference -ThreatIDDefaultAction_Ids ""
    Set-MpPreference -ThrottleForScheduledScanOnly $True
    Set-MpPreference -TrustLabelProtectionStatus 0
    Set-MpPreference -UILockdown False ""
    Set-MpPreference -UnknownThreatDefaultAction 0
    Set-MpPreference -PSComputerName ""

    #potentionally unwanted software
    Set-MpPreference -PUAProtection enable

    #WMI persistance
    Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
    #smb lateral movement
    Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D -AttackSurfaceReductionRules_Actions Enabled
    #ransomeware protection
    Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
    #prevent stealing from LSASS
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Updating Windows Defender"
    Update-MpSignature
}

function Set-AuditPolicy {
    Write-Host "Setting Audit Policies"
    auditpol /set /category:* /failure:enable /success:enable
    auditpol /set /category:"Account Logon" /success:enable
    auditpol /set /category:"Account Logon" /failure:enable
    auditpol /set /category:"Account Management" /success:enable
    auditpol /set /category:"Account Management" /failure:enable
    auditpol /set /category:"DS Access" /success:enable
    auditpol /set /category:"DS Access" /failure:enable
    auditpol /set /category:"Logon/Logoff" /success:enable
    auditpol /set /category:"Logon/Logoff" /failure:enable
    auditpol /set /category:"Object Access" /success:enable
    auditpol /set /category:"Object Access" /failure:enable
    auditpol /set /category:"Policy Change" /success:enable
    auditpol /set /category:"Policy Change" /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable
    auditpol /set /category:"Privilege Use" /failure:enable
    auditpol /set /category:"Detailed Tracking" /success:enable
    auditpol /set /category:"Detailed Tracking" /failure:enable
    auditpol /set /category:"System" /success:enable
    auditpol /set /category:"System" /failure:enable
    Write-Host "Audit Poliies Set"
}

function Set-UAC {
    Write-Host "Setting up UAC"
    secedit /export /cfg c:\secpol.cfg
    (Get-Content C:\secpol.cfg) -replace "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin.*", "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2" | Out-File C:\secpol.cfg
    (Get-Content C:\secpol.cfg) -replace "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser.*", "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,3" | Out-File C:\secpol.cfg
    (Get-Content C:\secpol.cfg) -replace "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop.*", "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1" | Out-File C:\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
    Remove-Item -force c:\secpol.cfg -confirm:$false
    Write-Host "UAC Set"
}

function Get-SharedDrives {
    Write-Output "Checking for Shared Drives`n"
    $shares = Get-WmiObject -class Win32_Share | Select-Object Name
    foreach ($share in $shares) {
        Write-Output $share.Name
        $String = Write-Output "Would you like to remove the above shared drive (ADMIN$, C$, and IPC$ are default, but can be deleted anyway)? (y/n)"
        $Selection = Read-Host $String
        switch ($Selection) {
            'y' {
                Write-Output "Removing " + $share.Name
                Remove-SmbShare -Name $share.Name
                Write-Output "Removed `n"
            }
        }
    }
}

function Disable-Accounts {
    Write-Output "Disabling Guest and Admin"
    Disable-LocalUser -Name "Guest"
    Disable-LocalUser -Name "DefaultAccount"
    Disable-LocalUser -Name "Administrator"
    Disable-LocalUser -Name "WDAGUtilityAccount"
}

function Clear-DNS {
    Write-Output "Clear DNS Cache"
    ipconfig /flushdns
}

function Disable-WindowsFeatures {
    Write-Output "Disable Features"
    dism /online /disable-feature /featurename:IIS-WebServerRole
	dism /online /disable-feature /featurename:IIS-WebServer
	dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
	dism /online /disable-feature /featurename:IIS-HttpErrors
	dism /online /disable-feature /featurename:IIS-HttpRedirect
	dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
	dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
	dism /online /disable-feature /featurename:IIS-HttpLogging
	dism /online /disable-feature /featurename:IIS-LoggingLibraries
	dism /online /disable-feature /featurename:IIS-RequestMonitor
	dism /online /disable-feature /featurename:IIS-HttpTracing
	dism /online /disable-feature /featurename:IIS-Security
	dism /online /disable-feature /featurename:IIS-URLAuthorization
	dism /online /disable-feature /featurename:IIS-RequestFiltering
	dism /online /disable-feature /featurename:IIS-IPSecurity
	dism /online /disable-feature /featurename:IIS-Performance
	dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
	dism /online /disable-feature /featurename:IIS-WebServerManagementTools
	dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
	dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
	dism /online /disable-feature /featurename:IIS-Metabase
	dism /online /disable-feature /featurename:IIS-HostableWebCore
	dism /online /disable-feature /featurename:IIS-StaticContent
	dism /online /disable-feature /featurename:IIS-DefaultDocument
	dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
	dism /online /disable-feature /featurename:IIS-WebDAV
	dism /online /disable-feature /featurename:IIS-WebSockets
	dism /online /disable-feature /featurename:IIS-ApplicationInit
	dism /online /disable-feature /featurename:IIS-ASPNET
	dism /online /disable-feature /featurename:IIS-ASPNET45
	dism /online /disable-feature /featurename:IIS-ASP
	dism /online /disable-feature /featurename:IIS-CGI
	dism /online /disable-feature /featurename:IIS-ISAPIExtensions
	dism /online /disable-feature /featurename:IIS-ISAPIFilter
	dism /online /disable-feature /featurename:IIS-ServerSideIncludes
	dism /online /disable-feature /featurename:IIS-CustomLogging
	dism /online /disable-feature /featurename:IIS-BasicAuthentication
	dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
	dism /online /disable-feature /featurename:IIS-ManagementConsole
	dism /online /disable-feature /featurename:IIS-ManagementService
	dism /online /disable-feature /featurename:IIS-WMICompatibility
	dism /online /disable-feature /featurename:IIS-LegacyScripts
	dism /online /disable-feature /featurename:IIS-LegacySnapIn
	$String = Write-Output "Would you like to disable FTP?"
	$Selection = Read-Host $String
	switch ($Selection) {
	    "y"{
	        dism /online /disable-feature /featurename:IIS-FTPServer
	        dism /online /disable-feature /featurename:IIS-FTPSvc
	        dism /online /disable-feature /featurename:IIS-FTPExtensibility
	        dism /online /disable-feature /featurename:TFTP
	    }
	}
	dism /online /disable-feature /featurename:TelnetClient
	dism /online /disable-feature /featurename:TelnetServer
    dism /online /disable-feature /featurename:"SMB1Protocol"
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

function Enable-Firewall {
    Write-Output "Enabling Firewall"
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
	Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
    netsh advfirewall set allprofiles state on
    netsh advfirewall show allprofiles
    netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no
    netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no
    netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no
    netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no
    netsh advfirewall firewall set rule name="Telnet Server" new enable=no
    netsh advfirewall firewall set rule name="netcat" new enable=no
    #disable network discovery hopefully
    netsh advfirewall firewall set rule group="Network Discovery" new enable=No
    #disable file and printer sharing hopefully
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No

    netsh advfirewall firewall add rule name="block_RemoteRegistry_in" dir=in service="RemoteRegistry" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RemoteRegistry_out" dir=out service="RemoteRegistry" action=block enable=yes

    New-NetFirewallRule -DisplayName "sshTCP" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block #ssh
    New-NetFirewallRule -DisplayName "ftpTCP" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block #ftp
    New-NetFirewallRule -DisplayName "telnetTCP" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block #telnet
    New-NetFirewallRule -DisplayName "SMTPTCP" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block #SMTP
    New-NetFirewallRule -DisplayName "POP3TCP" -Direction Inbound -LocalPort 110 -Protocol TCP -Action Block #POP3
    New-NetFirewallRule -DisplayName "SNMPTCP" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block #SNMP
    New-NetFirewallRule -DisplayName "RDPTCP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block #RDP
    netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
}

function Disable-RemoteDesktop {
    Write-Output "Disable Remote Desktop"
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Conferencing" /v "NoRDS" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d 80 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d 0 /f
}

function Set-AutomaticUpdates {
    Write-Output "Setting Windows Automatic Updates"
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
}

function Set-RandomRegistries {
    #Restrict CD ROM drive
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

    #disable remote access to floppy disk
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f

    #disable auto admin login
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

    #clear page file
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f

    #no printer drivers
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

    #auditing to LSASS.exe
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f

    #Enable LSA protection
    reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f

    #Limit use of blank passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

    #Auditing access of Global System Objects
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f

    #Auditing Backup and Restore
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f

    #Restrict Anonymous Enumeration #1
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f

    #Restrict Anonymous Enumeration #2
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f

    #Disable storage of domain passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f

    #Take away Anonymous user Everyone permissions
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f

    #Allow Machine ID for NTLM
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f

    #Do not display last user on logon
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f

    #Enable UAC
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

    #UAC set high
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1

    #UAC setting (Prompt on Secure Desktop)
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f

    #Enable Installer Detection
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f

    #Disable undocking without logon
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f

    #Enable CTRL+ALT+DEL
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f

    #Max password age
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f

    #Disable machine account password changes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f

    #Require strong session key
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f

    #Require Sign/Seal
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f

    #Sign Channel
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f

    #Seal Channel
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f

    #Set idle time to 45 minutes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f

    #Require Security Signature - Disabled pursuant to checklist:::
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f

    #Enable Security Signature - Disabled pursuant to checklist:::
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f

    #Clear null session pipes
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f

    #Restict Anonymous user access to named pipes and shares
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f

    #Encrypt SMB Passwords
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f

    #Clear remote registry paths
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f

    #Clear remote registry paths and sub-paths
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f

    #Prevent guest logins to SMB
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f

    #Enable smart screen for IE8
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f

    #Enable smart screen for IE9 and up
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f

    #Disable IE password caching
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f

    #Warn users if website has a bad certificate
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f

    #Warn users if website redirects
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f

    #Enable Do Not Track
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f

    #Show hidden files
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f

    #Disable sticky keys
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f

    #Show super hidden files
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f

    #Disable dump file creation
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f

    #Disable autoruns
    Write-Output "Disable Autoruns"
    reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

    #enable internet explorer phishing filter
    Write-Output "Internet Explorer"
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f

    #block macros and other content execution
    Write-Output "Macros and Executions"
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f

    #Enable Windows Defender
    Write-Output "Windows Defender"
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f

    # Detachable Storage
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f

	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

    # UAC
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f

    # Installers
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
    reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

    # Hidden Files
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f

    # Microsoft Office Suite
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f

    # Internet Explorer
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f

    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
}

function Configure-Services {
    Write-Output "Disabling Bad Services"

    $String = Write-Output "Is telnet necessary [y/n]?"
	$Selection = Read-Host $String
	switch ($Selection) {
	    "y"{
            cmd.exe /c 'sc start tlntsvr'
            cmd.exe /c 'sc config tlntvr start= auto'
	    }
	    "n"{
            cmd.exe /c 'sc stop tlntsvr'
	        cmd.exe /c 'sc config tlntsvr start= disabled'
		}
    }
    $String = Write-Output "Is FTP necessary [y/n]?"
	$Selection = Read-Host $String
	switch ($Selection) {
	    "y"{
	        Start-Service msftpsvc
            cmd.exe /c 'sc start msftpsvc'
            cmd.exe /c 'sc config msftpsvc start= auto'
            cmd.exe /c 'sc start Msftpsvc'
            cmd.exe /c 'sc config Msftpsvc start= auto'
            cmd.exe /c 'sc start ftpsvc'
            cmd.exe /c 'sc config ftpsvc start= auto'
	    }
	    "n"{
            cmd.exe /c 'sc stop msftpsvc'
	        cmd.exe /c 'sc config msftpsvc start= disabled'
            cmd.exe /c 'sc stop Msftpsvc'
            cmd.exe /c 'sc config Msftpsvc start= disabled'
            cmd.exe /c 'sc stop ftpsvc'
            cmd.exe /c 'sc config ftpsvc start= disabled'
		}
    }
    $String = Write-Output "Is SMTP necessary [y/n]?"
	$Selection = Read-Host $String
	switch ($Selection) {
	    "y"{
            cmd.exe /c 'sc start Smtpsvc'
            cmd.exe /c 'sc config Smtpsvc start= auto'
	    }
	    "n"{
            cmd.exe /c 'sc stop Smtpsvc'
	        cmd.exe /c 'sc config Smtpsvc start= disabled'
		}
    }
    $String = Write-Output "Is Remote Desktop necessary [y/n]?"
	$Selection = Read-Host $String
	switch ($Selection) {
	    "y"{
	        Start-Service TermService
	        Set-Service -Name TermService -StartupType Automatic
	    }
	    "n"{
	        Stop-Service TermService
	        Set-Service -Name TermService -StartupType Disabled
            Stop-Service SessionEnv
            Set-Service -Name SessionEnv -StartupType Disabled
            Stop-Service RemoteRegistry
            Set-Service -Name RemoteRegistry -StartupType Disabled
		}
    }
	Stop-Service SNMPTRAP
	Set-Service -Name SNMPTRAP -StartupType Disabled
	Stop-Service SSDPSRV
	Set-Service -Name SSDPSRV -StartupType Disabled
	try{
        cmd.exe /c 'sc stop Messenger'
        cmd.exe /c 'sc config Messenger start= disabled'
	}catch{
        Write-Host "Messenger doesn't exist"
	}
	Stop-Service upnphost
	Set-Service -Name upnphost -StartupType Disabled
	try{
	cmd.exe /c 'sc stop WAS'
	cmd.exe /c 'sc config WAS start= disabled'
	}
	#might be remote desktop stuff
	Stop-Service RemoteAccess
	Set-Service -Name RemoteAccess -StartupType Disabled
	Stop-Service RasMan
	Set-Service -Name RasMan -StartupType Disabled
	Stop-Service RpcSs
	Set-Service -Name RpcSs -StartupType Disabled
	Stop-Service RasAuto
	Set-Service -Name RasAuto -StartupType Disabled
	Stop-Service UmRdpService
	Set-Service -Name UmRdpService -StartupType Disabled
    try{
	cmd.exe /c 'sc stop mnmsrvc'
	cmd.exe /c 'sc config mnmsrvc start= disabled'
	}
	try{
	cmd.exe /c 'sc stop NetTcpPortSharing'
	cmd.exe /c 'sc config NetTcpPortSharing start= disabled'
	}
	Stop-Service TabletInputService
	Set-Service -Name TabletInputService -StartupType Disabled
	Stop-Service SENS
	Set-Service -Name SENS -StartupType Disabled
	Stop-Service EventSystem
	Set-Service -Name EventSystem -StartupType Disabled

	Write-Output "Disabling XBox services"
	Stop-Service XblAuthManager
	Set-Service -Name XblAuthManager -StartupType Disabled
	Stop-Service XblGameSave
	Set-Service -Name XblGameSave -StartupType Disabled
	Stop-Service XboxGipSvc
	Set-Service -Name XboxGipSvc -StartupType Disabled
	Stop-Service XboxNetApiSvc
	Set-Service -Name XboxNetApiSvc -StartupType Disabled
	try{
	cmd.exe /c 'sc stop xboxgip'
	cmd.exe /c 'sc config xboxgip start= disabled'
	}
	try{
	cmd.exe /c 'sc stop xbgm'
	cmd.exe /c 'sc config xbgm start= disabled'
	}

	Stop-Service SysMain
	Set-Service -Name SysMain -StartupType Disabled
	Stop-Service seclogon
	Set-Service -Name seclogon -StartupType Disabled
	Stop-Service TapiSrv
	Set-Service -Name TapiSrv -StartupType Disabled
	Stop-Service p2pimsvc
	Set-Service -Name p2pimsvc -StartupType Disabled
	try{
    cmd.exe /c 'sc stop simptcp'
    cmd.exe /c 'sc config simptcp start= disabled'
    }
    try{
    cmd.exe /c 'sc stop fax'
    cmd.exe /c 'sc config fax start= disabled'
    }
    try{
    cmd.exe /c 'sc stop iprip'
    cmd.exe /c 'sc config iprip start= disabled'
    }
    try{
    cmd.exe /c 'sc stop W3svc'
    cmd.exe /c 'sc config W3svc start= disabled'
    }
    try{
    cmd.exe /c 'sc stop Dfs'
    cmd.exe /c 'sc config Dfs start= disabled'
    }
	Stop-Service TrkWks
	Set-Service -Name TrkWks -StartupType Disabled
	Stop-Service MSDTC
	Set-Service -Name MSDTC -StartupType Disabled
    try{
    cmd.exe /c 'sc stop ERSvc'
    cmd.exe /c 'sc config ERSvc start= disabled'
    }
    try{
    cmd.exe /c 'sc stop NtFrs'
    cmd.exe /c 'sc config NtFrs start= disabled'
    }
    try{
    cmd.exe /c 'sc stop Iisadmin'
    cmd.exe /c 'sc config Iisadmin start= disabled'
    }
    try{
    cmd.exe /c 'sc stop IsmServ'
    cmd.exe /c 'sc config IsmServ start= disabled'
    }
    try{
    cmd.exe /c 'sc stop WmdmPmSN'
    cmd.exe /c 'sc config WmdmPmSN start= disabled'
    }
    try{
    cmd.exe /c 'sc stop helpsvc'
    cmd.exe /c 'sc config helpsvc start= disabled'
    }
	Stop-Service Spooler
	Set-Service -Name Spooler -StartupType Disabled
    try{
    cmd.exe /c 'sc stop RDSessMgr'
    cmd.exe /c 'sc config RDSessMgr start= disabled'
    }
    try{
    cmd.exe /c 'sc stop RSoPProv'
    cmd.exe /c 'sc config RSoPProv start= disabled'
    }
	Stop-Service SCardSvr
	Set-Service -Name SCardSvr -StartupType Disabled
	Stop-Service LanmanServer
	Set-Service -Name LanmanServer -StartupType Disabled
    try{
    cmd.exe /c 'sc stop Sacsvr'
    cmd.exe /c 'sc config Sacsvr start= disabled'
    }
    try{
    cmd.exe /c 'sc stop uploadmgr'
    cmd.exe /c 'sc config uploadmgr start= disabled'
    }
	Stop-Service vds
	Set-Service -Name vds -StartupType Disabled
	Stop-Service VSS
	Set-Service -Name VSS -StartupType Disabled
    try{
    cmd.exe /c 'sc stop WINS'
    cmd.exe /c 'sc config WINS start= disabled'
    }
	Stop-Service CscService
	Set-Service -Name CscService -StartupType Disabled
	Stop-Service hidserv
	Set-Service -Name hidserv -StartupType Disabled
    try{
    cmd.exe /c 'sc stop IPBusEnum'
    cmd.exe /c 'sc config IPBusEnum start= disabled'
    }
	Stop-Service PolicyAgent
	Set-Service -Name PolicyAgent -StartupType Disabled
	Stop-Service SharedAccess
	Set-Service -Name SharedAccess -StartupType Disabled
	Stop-Service SSDPSRV
	Set-Service -Name SSDPSRV -StartupType Disabled
	Stop-Service Themes
	Set-Service -Name Themes -StartupType Disabled
    try{
    cmd.exe /c 'sc stop nfssvc'
    cmd.exe /c 'sc config nfssvc start= disabled'
    }
    try{
    cmd.exe /c 'sc stop nfsclnt'
    cmd.exe /c 'sc config nfsclnt start= disabled'
    }
    try{
    cmd.exe /c 'sc stop MSSQLServerADHelper'
    cmd.exe /c 'sc config MSSQLServerADHelper start= disabled'
    }
    try{
    cmd.exe /c 'sc stop Server'
    cmd.exe /c 'sc config Server start= disabled'
    }
    try{
    cmd.exe /c 'sc stop TeamViewer'
    cmd.exe /c 'sc config TeamViewer start= disabled'
    }
    try{
    cmd.exe /c 'sc stop TeamViewer7'
    cmd.exe /c 'sc config TeamViewer7 start= disabled'
    }
    try{
    cmd.exe /c 'sc stop HomeGroupListener'
    cmd.exe /c 'sc config HomeGroupListener start= disabled'
    }
    try{
    cmd.exe /c 'sc stop HomeGroupProvider'
    cmd.exe /c 'sc config HomeGroupProvider start= disabled'
    }
	Stop-Service AxInstSV
	Set-Service -Name AxInstSV -StartupType Disabled
	Stop-Service Netlogon
	Set-Service -Name Netlogon -StartupType Disabled
	Stop-Service lltdsvc
	Set-Service -Name lltdsvc -StartupType Disabled
	Stop-Service iphlpsvc
	Set-Service -Name iphlpsvc -StartupType Disabled
    try{
    cmd.exe /c 'sc stop AdobeARMservice'
    cmd.exe /c 'sc config AdobeARMservice start= disabled'
    }

    #goodservices
    Write-Output "Enabling Good Services"

    Start-Service wuauserv
    Set-Service -Name wuauserv -StartupType Automatic
    Start-Service EventLog
    Set-Service -Name EventLog -StartupType Automatic
    Start-Service mpssvc
    Set-Service -Name mpssvc -StartupType Automatic
    Start-Service WinDefend
    Set-Service -Name WinDefend -StartupType Automatic
    Start-Service WdNisSvc
    Set-Service -Name WdNisSvc -StartupType Automatic
    Start-Service Sense
    Set-Service -Name Sense -StartupType Automatic
    Start-Service Schedule
    Set-Service -Name Schedule -StartupType Automatic
    Start-Service SCardSvr
    Set-Service -Name SCardSvr -StartupType Automatic
    Start-Service ScDeviceEnum
    Set-Service -Name ScDeviceEnum -StartupType Automatic
    Start-Service SCPolicySvc
    Set-Service -Name SCPolicySvc -StartupType Automatic
    Start-Service wscsvc
    Set-Service -Name wscsvc -StartupType Automatic

    Write-Output "Services Configured"
}

function Find-Files{
    $String = Write-Output "Enter username: "
    $user = Read-Host $String
    New-Item -Path C:\Users\$user\Desktop\file_finder -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\file_finder\userfiles -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\file_finder\programfiles -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\file_finder\programfilesx86 -ItemType directory
    New-Item -Path C:\Users\$user\Desktop\file_finder\documents -ItemType directory
	New-Item -Path C:\Users\$user\Desktop\file_finder\OS_search_engine -ItemType directory
	$media_extensions = @("*.jpg","*.jpeg","*.png","*.avi","*.mp4","*.mp3","*.wav","*.bmp","*.dcm","*.djvu","*.gif","*.heic","*.psd","*.tga","*.tif")
	Write-Warning "finding media files"
    Get-ChildItem -Path C:\Users -Include $media_extensions -Recurse -ErrorAction SilentlyContinue | Out-File -filepath C:\Users\$user\Desktop\file_finder\mediafiles.txt
    Write-Warning "grabbing user files"
    Get-ChildItem -Path C:\Users -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\file_finder\userfiles -Force
    Write-Warning "grabbing program files"
    Get-ChildItem -Path "C:\Program Files\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\file_finder\programfiles -Force
    Get-ChildItem -Path "C:\Program Files (x86)\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\file_finder\programfilesx86 -Force
    Write-Warning "grabbing Documents"
    Get-ChildItem -Path "C:\Users\$user\Documents\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\Users\$user\Desktop\file_finder\documentsandsettings -Force
}

function Audit-Powershell {
    #transcripts
    reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 1 /f

    #logging
    reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
}

function Password-Policies {
    net accounts
    net accounts /minpwlen:10
    net accounts /maxpwage:30
    net accounts /minpwage:10
    net accounts /uniquepw:5
    net accounts /lockoutthreshold:5
    secedit /export /cfg c:\secpol.cfg
    (Get-Content C:\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Out-File C:\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
    Remove-Item -force c:\secpol.cfg -confirm:$false
    net accounts /lockoutduration:15
    net accounts /lockoutwindow:15
    wmic UserAccount set PasswordExpires=True
    wmic UserAccount set PasswordChangeable=True
    wmic UserAccount set PasswordRequired=True
    Write-Output "Remember to doublecheck this in secpol.msc"
}

function Secure-RDP {
    Write-Output "Secure Remote Desktop"
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v UserAuthentication /t REG_DWORD /d 1 /f
    Enable-NetFirewallRule -DisplayGroup ???Remote Desktop???
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisablePNPRedir /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableAutoReconnect /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v MinEncryptionLevel /t REG_DWORD /d 3 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v SecurityLayer /t REG_DWORD /d 2 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v SecurityLayer /t REG_DWORD /d 2 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel /t REG_DWORD /d 3 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fPromptForPassword /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
}

$var = 1
while($var -le 5){
    Write-Host "Deep Run HBI Windows 10 Script"
    Write-Host "1. Enable Firewall"
    Write-Host "2. Set Windows Defender"
    Write-Host "3. Set Audit Policies"
    Write-Host "4. Enable UAC"
    Write-Host "5. Look at Shared Drives"
    Write-Host "6. Disable Guest and Admin Accounts"
    Write-Host "7. Clear DNS Cache"
    Write-Host "8. Configure Windows Features"
    Write-Host "9. Configure Services"
    Write-Host "10. Disable Remote Desktop"
    Write-Host "11. Set Automatic Updates"
    Write-Host "12. Lots Of Registries :)"
    Write-Host "13. Password Policies"
    Write-Host "14. Powershell Audits"
    Write-Host "15. Find Media Files"
    Write-Host "16. Secure RDP"
    $Selection = Read-Host "Choose an Option: "
    switch($Selection) {
        "1"{
            Enable-Firewall
        }
        "2"{
            Set-Defender
        }
        "3"{
            Set-AuditPolicy
        }
        "4"{
            Set-UAC
        }
        "5"{
            Get-SharedDrives
        }
        "6"{
            Disable-Accounts
        }
        "7"{
            Clear-DNS
        }
        "8"{
            Disable-WindowsFeatures
        }
        "9"{
            Configure-Services
        }
        "10"{
            Disable-RemoteDesktop
        }
        "11"{
            Set-AutomaticUpdates
        }
        "12"{
            Set-RandomRegistries
        }
        "13"{
            Password-Policies
        }
        "14"{
            Audit-PowerShell
        }
        "15"{
            Find-Files
        }
        "16"{
            Secure-RDP
        }
    }
}
