function Users {
    $selection = Read-Host "Have you created users.txt and admins.txt [y/n]"
    if ($selection -eq 'y')
    {
        $user_data = Get-Content "$($PSScriptRoot)\users\users.txt"
        $admin_data = Get-Content "$($PSScriptRoot)\users\admins.txt"
        $all_users = Get-WMIObject Win32_UserAccount -filter 'LocalAccount=TRUE' | select-object -ExpandProperty Name
        Write-Output $all_users
        for($i = 0; $i -lt $user_data.Length; $i++)
        {
            $current_user = $user_data[$i]
            if($all_users -contains $current_user)
            {
                Write-Output "User Exists"
                $UserAccount = Get-LocalUser -Name $current_user
                $UserAccount | Set-LocalUser -Password 'Sup3rS3cur3P@55w0rd@123'
            }else
            {
                Write-Output "Creating Account for User " + $current_user
                New-LocalUser $current_user -Password 'Sup3rS3cur3P@55w0rd@123' -FullName $current_user
            }
            Remove-LocalGroupMember -Group "Administrators" -Member $current_user
        }
        for($i = 0; $i -lt $admin_data.Length; $i++)
        {
            $current_admin = $admin_data[$i]
            if($all_users -contains $current_admin)
            {
                Write-Output "Admin exists"
            }else
            {
                Write-Output "Creating Account for User " + $current_admin
                New-LocalUser $current_admin -Password 'Sup3rS3cur3P@55w0rd@123' -FullName $current_admin
            }
            Add-LocalGroupMember -Group "Administrators" -Member $current_admin
        }
        for($i = 0; $i -lt $all_users.Length; $i++)
        {
            $current_user = $all_users[$i]
            if(-not($user_data -contains $current_user) -and -not($admin_data -contains $current_user) -and -not(@('Administrator','DefaultAccount','Guest','WDAGUtilityAccount') -contains $current_user))
            {
                Disable-LocalUser -Name $current_user
            }
        }
        Disable-LocalUser -Name "Guest"
        Disable-LocalUser -Name "DefaultAccount"
        Disable-LocalUser -Name "Administrator"
        Disable-LocalUser -Name "WDAGUtilityAccount"
    }
    net accounts
    net accounts /minpwlen:10
    net accounts /maxpwage:90
    net accounts /minpwage:30
    net accounts /uniquepw:5
    net accounts /lockoutthreshold:5
    secedit /export /cfg c:\secpol.cfg
    (Get-Content C:\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Out-File C:\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
    Remove-Item -force c:\secpol.cfg -confirm:$false
    net accounts /lockoutduration:30
    net accounts /lockoutwindow:30
    wmic UserAccount set PasswordExpires=True
    wmic UserAccount set PasswordChangeable=True
    wmic UserAccount set PasswordRequired=True
    Write-Output "Remember to double check users and password policies in secpol.msc"
}

function Files {
    Write-host "Searching for unauthorized files..."
    $extensions =@("aac","ac3","avi","aiff","bat","bmp","exe","flac","gif","jpeg","jpg","mov","m3u","m4p",
    "mp2","mp3","mp4","mpeg4","midi","msi","ogg","png","txt","sh","wav","wma","vqf")
    $tools =@("Cain","nmap","keylogger","Armitage","Wireshark","Metasploit","netcat")
    Write-host "Checking $extensions"
    foreach($ext in $extensions)
    {
        Write-host "Checking for .$ext files"
        if(Test-path "$($PSScriptRoot)\files_output\$ext.txt"){
            Clear-content "$($PSScriptRoot)\files_output\$ext.txt"
        }
        C:\Windows\System32\cmd.exe /C dir C:\*.$ext /s /b | Out-File "$($PSScriptRoot)\files_output\$ext.txt"
    }
    Write-host "Finished searching by extension"
    Write-host "Checking for $tools"
    foreach($tool in $tools){
        Write-host "Checking for $tool"
        if(Test-path "$($PSScriptRoot)\files_output\$tool.txt"){
            Clear-content "$($PSScriptRoot)\files_output\$tool.txt"
        }
        C:\Windows\System32\cmd.exe /C dir C:\*$tool* /s /b | Out-File "$($PSScriptRoot)\files_output\$tool.txt"
    }
    Write-host "Finished searching for tools"
}

function Auditing {
    Write-Output "============================================"
    Write-Output "Setting Audit Policies and Powershell Audits"
    auditpol /set /category:* /success:enable
    auditpol /set /category:* /failure:enable
    echo Set auditing success and failure
    #transcripts
    reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 1 /f

    #logging
    reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

}

function AutoUpdates {
    Write-Output "================================="
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

function Enable-Firewall {
    Write-Output "================="
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

function Remote-Desktop {
    Write-Output("================================")
    $choice = Read-Host "Is Remote Desktop Critical [y/n]"
    if($choice -eq "y"){
        Write-Output "======================="
        Write-Output "Securing Remote Desktop"
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v UserAuthentication /t REG_DWORD /d 1 /f
        Enable-NetFirewallRule -DisplayGroup “Remote Desktop”
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
    }else{
        Write-Output "========================"
        Write-Output "Disabling Remote Desktop"
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
    Write-Host 'Remote Desktop Configured'
}

function Disable-WindowsFeatures {
    Write-Host("===============")
    Write-Host("Installing Dism")
    Copy-Item "$($PSScriptRoot)\resources\Dism.exe" -Destination "C:\Windows\System32"
    Write-Host "=============================="
    Write-Host "--- Disabling IIS Services ---" -ForegroundColor Blue -BackgroundColor White

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

    $confirmation = Read-Host "Disable FTP? [y/n]"
    if ($confirmation -eq "y") {
        dism /online /disable-feature /featurename:IIS-FTPServer
        dism /online /disable-feature /featurename:IIS-FTPSvc
        dism /online /disable-feature /featurename:IIS-FTPExtensibility
        dism /online /disable-feature /featurename:TFTP
    }
    $confirmation = Read-Host "Disable SMB? [y/n]"
    if ($confirmation -eq "y") {
        dism /online /disable-feature /featurename:"SMB1Protocol"
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    }
}

function UserRights {
    Write-Host("===================")
    Write-Host("Installing NTRights")
    Copy-Item "$($PSScriptRoot)\resources\ntrights.exe" -Destination "C:\Windows\System32"
    Write-Host("===================")
    Write-Host("Setting User Rights")
    $remove = @("Backup Operators","Everyone","Power Users","Users","NETWORK SERVICE","LOCAL SERVICE","Remote Desktop User","ANONOYMOUS LOGON","Guest","Performance Log Users")
    foreach ($person in $remove) {
        ntrights -U %%a -R SeNetworkLogonRight
        ntrights -U %%a -R SeIncreaseQuotaPrivilege
        ntrights -U %%a -R SeInteractiveLogonRight
        ntrights -U %%a -R SeRemoteInteractiveLogonRight
        ntrights -U %%a -R SeSystemtimePrivilege
        ntrights -U %%a +R SeDenyNetworkLogonRight
        ntrights -U %%a +R SeDenyRemoteInteractiveLogonRight
        ntrights -U %%a -R SeProfileSingleProcessPrivilege
        ntrights -U %%a -R SeBatchLogonRight
        ntrights -U %%a -R SeUndockPrivilege
        ntrights -U %%a -R SeRestorePrivilege
        ntrights -U %%a -R SeShutdownPrivilege
    }
    ntrights -U "Administrators" -R SeImpersonatePrivilege
    ntrights -U "Administrator" -R SeImpersonatePrivilege
    ntrights -U "SERVICE" -R SeImpersonatePrivilege
    ntrights -U "LOCAL SERVICE" +R SeImpersonatePrivilege
    ntrights -U "NETWORK SERVICE" +R SeImpersonatePrivilege
    ntrights -U "Administrators" +R SeMachineAccountPrivilege
    ntrights -U "Administrator" +R SeMachineAccountPrivilege
    ntrights -U "Administrators" -R SeIncreaseQuotaPrivilege
    ntrights -U "Administrator" -R SeIncreaseQuotaPrivilege
    ntrights -U "Administrators" -R SeDebugPrivilege
    ntrights -U "Administrator" -R SeDebugPrivilege
    ntrights -U "Administrators" +R SeLockMemoryPrivilege
    ntrights -U "Administrator" +R SeLockMemoryPrivilege
    ntrights -U "Administrators" -R SeBatchLogonRight
    ntrights -U "Administrator" -R SeBatchLogonRight
}

function Get-SharedDrives {
    Write-Output "=========================="
    Write-Output "Checking for Shared Drives"
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

function UAC {
    Write-Host "=============="
    Write-Host "Setting up UAC"
    secedit /export /cfg c:\secpol.cfg
    (Get-Content C:\secpol.cfg) -replace "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin.*", "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2" | Out-File C:\secpol.cfg
    (Get-Content C:\secpol.cfg) -replace "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser.*", "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,3" | Out-File C:\secpol.cfg
    (Get-Content C:\secpol.cfg) -replace "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop.*", "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1" | Out-File C:\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
    Remove-Item -force c:\secpol.cfg -confirm:$false
    Write-Host "UAC Set"
}

function WindowsDefender {
    Write-Host("======================================")
    Write-Host("Configuring Windows Defender Policies:")
    $x = Get-MpPreference

    # Get exclusion path
    if ($x.ExclusionPath -ne $NULL) {
        Write-Host("================================================")
        Write-Host("Removing the following ExclusionPath entries:")
        foreach ($i in $x.ExclusionPath) {
            Remove-MpPreference -ExclusionPath $i
            Write-Host($i)
        }
        Write-Host("================================================")
        Write-Host("Total ExclusionPath entries deleted:", $x.ExclusionPath.Count)
    }
    else {
        Write-Host("No ExclusionPath entries present. Skipping...")
    }

    # Get exclusion process
    if ($x.ExclusionProcess -ne $NULL) {
        Write-Host("================================================")
        Write-Host("Removing the following ExclusionProcess entries:")
        foreach ($i in $x.ExclusionProcess) {
            Remove-MpPreference -ExclusionProcess $i
            Write-Host($i)
        }
        Write-Host("================================================")
        Write-Host("Total ExclusionProcess entries deleted:", $x.ExclusionProcess.Count)
    }
    else {
        Write-Host("No ExclusionProcess entries present. Skipping...")
    }

    # Get exclusion extension
    if ($x.ExclusionExtension -ne $NULL) {
        Write-Host("================================================")
        Write-Host("Removing the following ExclusionExtension entries:")
        foreach ($i in $x.ExclusionExtension) {
            Remove-MpPreference -ExclusionExtension $i
            Write-Host($i)
        }
        Write-Host("================================================")
        Write-Host("Total ExclusionExtension entries deleted:", $x.ExclusionExtension.Count)
    }
    else {
        Write-Host("No ExclusionExtension entries present. Skipping...")
    }

    # Summary
    Write-Host("================================================")
    Write-Host("SUMMARY")
    Write-Host($x.ExclusionPath.Count, "ExclusionPath entries deleted.")
    Write-Host($x.ExclusionProcess.Count, "ExclusionProcess entries deleted.")
    Write-Host($x.ExclusionProcess.Count, "ExclusionExtension entries deleted.")
    Write-Host(($x.ExclusionPath.Count + $x.ExclusionProcess.Count + $x.ExclusionExtension.Count), "Total entries deleted")

    Write-Host("==================================================")
    Write-Host("Setting Scans for Both Incoming and Outgoing Files")
    Set-MpPreference -RealTimeScanDirection 0
    Write-Host("=======================================")
    Write-Host("Purging Quarantined Items after 90 days")
    Set-MpPreference -QuarantinePurgeItemsAfterDelay 90
    Write-Host("=====================================")
    Write-Host("Setting Remediation Scans to Everyday")
    Set-MpPreference -RemediationScheduleDay 0
    Write-Host("========================================")
    Write-Host("Setting Remediation Scans to run at 2 AM")
    Set-MpPreference -RemediationScheduleTime 020000
    Write-Host("=============================================")
    Write-Host("Setting Action Time Out and Failure Time Outs")
    Set-MpPreference -ReportingAdditionalActionTimeOut 10080
    Set-MpPreference -ReportingCriticalFailureTimeOut 10080
    Set-MpPreference -ReportingNonCriticalTimeOut 1440
    Write-Host("===================================")
    Write-Host("Setting Scan CPU Load Factor to 50%")
    Set-MpPreference -ScanAvgCPULoadFactor 50
    Write-Host("==========================================")
    Write-Host("Check for new virus signatures before scan")
    Set-MpPreference -CheckForSignaturesBeforeRunningScan $True
    Set-MpPreference -ScanPurgeItemsAfterDelay 15
    Write-Host("============================")
    Write-Host("Enabling Realtime Monitoring")
    Set-MpPreference -DisableRealtimeMonitoring $False
    Write-Host("========================")
    Write-Host("Enabling IOAV Protection")
    Set-MpPreference -DisableIOAVProtection $False
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
    start-service WinDefend
    start-service WdNisSvc
    Set-MpPreference -AllowNetworkProtectionDownLevel $False
    Set-MpPreference -CloudBlockLevel 1
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
    Set-MpPreference -DisableEmailScanning $False
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
    Set-MpPreference -PUAProtection 1
    Set-MpPreference -RandomizeScheduleTaskTimes $True
    Set-MpPreference -ScanOnlyIfIdleEnabled $True
    Set-MpPreference -ScanParameters 1
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

    #potentionally unwanted software
    Set-MpPreference -PUAProtection 1

    #WMI persistance
    Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
    #smb lateral movement
    Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D -AttackSurfaceReductionRules_Actions Enabled
    #ransomeware protection
    Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
    #prevent stealing from LSASS
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
    Write-Host "========================="
    Write-Host "Updating Windows Defender"
    Update-MpSignature
}

function Registries {
    Write-Output "========================="
    Write-Output "Running Random Registries"
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
}

function Configure-Services {
    Write-Host("=================================")
    Write-Host("Configuring Good and Bad Services")
    $services = Import-Csv -Path "$($PSScriptRoot)\resources\services.csv"
    foreach ($service in $services) {

        if ((Get-Service | where name -eq $service.Process) -eq $null) {
            Write-Host "$($service.Name) is not installed on this computer. Ignoring."
            continue
        }

        if ((Get-Service | where name -eq $service.Process).StartType -eq $service.Mode) {
            Write-Host "$($service.Name) is already configured correctly. No action taken."
            continue
        }

        try {
            Set-Service -Name $service.Process -StartupType $service.Mode -ErrorAction Stop
            Write-Host "$($service.Name) was configured incorrectly. Startup type has been switched to $($service.Mode)." -ForegroundColor green
        } catch {
            Write-Host "Failed to change startup type for $($service.Name) to $($service.Mode)." -ForegroundColor red
            continue
        }

        if (($service.Mode -eq 'Automatic') -and -not ((Get-Service | where name -eq $service.Process).Status -eq 'Running')) {
            try {
                Start-Service -Name $service.Process -ErrorAction Stop | Out-Null
                Write-Host "$($service.Name) is now started." -ForegroundColor green
            } catch {
                Write-Host "Failed to start the $($service.Name) service." -ForegroundColor red
                continue
            }
        }

        if (($service.Mode -eq 'Disabled') -and -not ((Get-Service | where name -eq $service.Process).Status -eq 'Stopped')) {
            try {
                Stop-Service -Name $service.Process -Force -ErrorAction Stop | Out-Null
                Write-Host "$($service.Name) is now stopped." -ForegroundColor green
            } catch {
                Write-Host "Failed to stop the $($service.Name) service." -ForegroundColor red
                continue
            }

        }
    }
    Write-Host("===================")
    Write-Host("Services Configured")
}

function Other {
    Write-Output "=================="
    Write-Output "Clearing DNS Cache"
    ipconfig /flushdns
    Write-Output "======================="
    Write-Output "Emptying Recycling Bins"
    Clear-RecycleBin -DriveLetter C
    Write-Output "======================"
    Write-Output "Setting Power Settings"
    powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
    powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
    powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
    Write-Ouput "==================="
    Write-Output "Getting Hosts File"
    Copy-Item "C:\Windows\System32\drivers\etc\hosts" -Destination "$($PSScriptRoot)\hosts"
}

function Firefox-Config {
    Copy-Item "$($PSScriptRoot)\resources\mozilla.cfg" -Destination "C:\Program Files (x86)\Mozilla Firefox\"
    Copy-Item "$($PSScriptRoot)\resources\mozilla.cfg" -Destination "C:\Program Files\Mozilla Firefox\"
}

function System-Integrity {
    Write-Output("=============================")
    Write-Output("Running System Integrity Scan")
    sfc /scannow
}

function Security-Policies {
    Write-Output("==========================")
    Write-Output("Applying Security Policies")
    secedit /configure /db "$($Env:WinDir)\security\local.sdb" /cfg "$($PSScriptRoot)\resources\secpol_config.inf" | Out-Null
}

function Group-Policies {
    Write-Output("=====================================")
    Write-Output("Configuring Applications and Services")
    #List of services to be configured
    $services =@('WinUpdate', 'WinDefender', 'EventLog', 'Powershell', 'WinRM', 'SMBv1','Firefox','Chrome','IExplorer','MSEdge','RDP')

    #Add to the list of services from user input
    if((Read-Host -Prompt "Enable remote desktop? (y/n)") -eq "y") {
        $services = $services + 'RDPOn'
    } else {
        $services = $services + 'RDPOff'
    }

    #Import the GroupPolicies.csv file into a variable
    $pols = Import-Csv -Path "$($PSScriptRoot)\resources\gp\GroupPolicies.csv"

    #Copy over required .admx and .adml files
    foreach ($pol in $pols) {
        if(($pol.Enabled -eq 'TRUE') -and (($pol.Service -eq [string]::Empty) -or ($services -contains $pol.Service))) {
            $admxImportPath = "$($env:SystemRoot)\PolicyDefinitions\$($pol.Template).admx"
            $admxExportPath = "$($PSScriptRoot)\resources\gp\Administrative Templates\$($pol.Template).admx"

            if(-not ($pol.Template -eq [string]::Empty) -and -not (Test-Path -Path $admxImportPath)) {
                try {
                    Copy-Item $admxExportPath -Destination $admxImportPath -ErrorAction Stop
                    Write-Output "Imported necessary file: $($admxExportPath) to $($admxImportPath)"
                } catch {
                    Write-Output "Failed to import file: $($admxExportPath) to $($admxImportPath)"
                }
            }

            $admlImportPath = "$($env:SystemRoot)\PolicyDefinitions\en-us\$($pol.Template).adml"
            $admlExportPath = "$($PSScriptRoot)\resources\gp\Administrative Templates\en-us\$($pol.Template).adml"

            if(-not ($pol.Template -eq [string]::Empty) -and -not (Test-Path -Path $admlImportPath)) {
                try {
                    Copy-Item $admlExportPath -Destination $admlImportPath -ErrorAction Stop
                    Write-Output "Imported necessary file: $($admlExportPath) to $($admlImportPath)"
                } catch {
                    Write-Output "Failed to import file: $($admlExportPath) to $($admlImportPath)"
                }
            }
        }
    }

    #Set the path to the policy file that will be edited by the script
    $polPath = "$($env:SystemRoot)\System32\GroupPolicy\Machine\registry.pol"

    #Create a backup of the current computer configuration policy file
    try {
        $backupPath = "$($PSScriptRoot)\Backups\Registry($(Get-Date -Format "HH-mm-ss")).pol"
        New-Item -ItemType Directory -Force -Path ($backupPath | Split-Path -Parent) | Out-Null
        Copy-Item $polPath $backupPath -ErrorAction Stop
        Write-Output "Created a backup of the policy file at $($backupPath)"
    } catch {
        Write-Output "Failed to create a backup of the policy file. The script will not continue."
        cmd /c pause
        exit
    }

    #Install PolicyFileEditor to enable manipulation of the pol file using scripts
    #For some reason Tls1.2 specifically is required to install the module
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -Force | Out-Null
    Install-Module -Name PolicyFileEditor -Force

    #Go through each row in the array of group policy changes and apply them
    foreach ($pol in $pols) {
        #Only edit the policy if it is enabled in the csv and is for a service that needs to be configured
        if(($pol.Enabled -eq 'TRUE') -and (($pol.Service -eq '') -or ($services -contains $pol.Service))) {
            #Opional data type "Remove" will tell the program to delete the setting (set it to not configured)
            if($pol.Type -eq 'Remove') {
                Remove-PolicyFileEntry -Path $polPath -Key $pol.Key -ValueName $pol.Value
            } else {
                Set-PolicyFileEntry -Path $polPath -Key $pol.Key -ValueName $pol.Value -Data $pol.Data -Type $pol.Type
            }
            Write-Output "$($pol.Service) - $($pol.Name) is now set to $($pol.Setting)"
        }
    }

    #Force Windows to recognize all of the changes and update group policy
    Write-Output ""
    gpupdate /force
}


$var = 1
while($var -le 5){
    Write-Host "=================================="
    Write-Host ""
    Write-Host "  _    _   ____    _____ "
    Write-Host " | |  | | |  _ \  |_   _|"
    Write-Host " | |__| | | |_) |   | |  "
    Write-Host " |  __  | |  _ <    | |  "
    Write-Host " | |  | | | |_) |  _| |_ "
    Write-Host " |_|  |_| |____/  |_____|"
    Write-Host ""
    Write-Host "=================================="
    Write-Host "Windows 10 by Lakshay Kansal"
    Write-Host "============================================================="
    Write-Host "1. User Config                      2. Firewall"
    Write-Host "3. Windows Features                 4. Shared Drives"
    Write-Host "5. Windows Defender                 6. User Rights"
    Write-Host "7. Remote Desktop                   8. Auditing"
    Write-Host "9. Automatic Updates                10. Registries"
    Write-Host "11. Find Files                      12. Enable UAC"
    Write-Host "13. Configure Services              14. Firefox Config"
    Write-Host "15. Security Policies               16. Group Policies"
    Write-Host "17. System Integrity Scan (Takes Time)"
    Write-Host "98. Other                           99. Exit"
    Write-Host "=============================================================="
    $Selection = Read-Host "Choose an Option"
    switch($Selection) {
        "1"{
            Users
        }
        "2"{
            Enable-Firewall
        }
        "3"{
            Disable-WindowsFeatures
        }
        "4"{
            Get-SharedDrives
        }
        "5"{
            WindowsDefender
        }
        "6"{
            UserRights
        }
        "7"{
            Remote-Desktop
        }
        "8"{
            Auditing
        }
        "9"{
            AutoUpdates
        }
        "10"{
            Registries
        }
        "11"{
            Files
        }
        "12"{
            UAC
            Write-Host "Search Bar - Type 'UAC' - Set to highest level"
        }
        "13"{
            Configure-Services
        }
        "14"{
            Firefox-Config
        }
        "15"{
            Security-Policies
        }
        "16"{
            Group-Policies
        }
        "17"{
            System-Integrity
        }
        "98"{
            Other
        }
        "99"{
            $var = 6
        }
    }
    if($var -lt 5){
        Read-Host "Enter to Continue"
        Clear-Host
    }
}