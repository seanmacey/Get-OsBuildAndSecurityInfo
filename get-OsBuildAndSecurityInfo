#_requires -RunAsAdministrator
# and you may need 'unblock-file' in order for it to be trusted

param(
    [string]$minverSCCM = "5.0.9040.1044",
    [string]$minverSCOM = "10.19.10014.0",
    [string]$minvervmtools = "11.2.5.17337674",
    [string]$minverSEP = "14.2.5323.2000",
    [string]$minverNETFramework = "460798",
    [string]$minverMcAfee = "0.0.0.0",
    [string]$minverTrend = "0.0.0.0",
    [string]$minverNable = "0.0.0.0",
    [string]$minverConnectwise = "0.0.0.0",
    [parameter(Mandatory = $false, HelpMessage = "the path to the log file")]
    [string]$logfile = "C:\Test-Build\Test-Buildlog.txt",
    [PSCredential]$SCCMcredential = $null,
    [parameter(Mandatory = $false, HelpMessage = "enable (for automation) to ensure script will not prompt user for credentials etc")]
    [switch]$runUnattended = $false,
    [ValidateSet("text", "json", "psobject", "html")]
    [string]$outputFormat = "text",
    [switch]$dontCheckUpdateBatch
   
)


$buildErrors = @()
$buildnotes = @()


$ciphers12 = @("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA") #In Windows 2012 3DES is disabled later using an specific registry entry 

$ciphers16 = @("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    #"TLS_RSA_WITH_RC4_128_SHA",
    #"TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_NULL_SHA256",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_PSK_WITH_AES_256_CBC_SHA384",
    "TLS_PSK_WITH_AES_128_CBC_SHA256",
    "TLS_PSK_WITH_NULL_SHA384",
    "TLS_PSK_WITH_NULL_SHA256")
#"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",

$ciphers19 = @("TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_NULL_SHA256",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_PSK_WITH_AES_256_CBC_SHA384",
    "TLS_PSK_WITH_AES_128_CBC_SHA256",
    "TLS_PSK_WITH_NULL_SHA384",
    "TLS_PSK_WITH_NULL_SHA256")


function Test-TLSversion {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('TLS 1.2\Server', 'TLS 1.2\Client', 'TLS 1.1\Server', 'TLS 1.1\Client', 'TLS 1.0\Server', 'TLS 1.0\Client', 'SSL 2.0\Server', 'SSL 2.0\Client', 'SSL 3.0\Server', 'SSL 3.0\Client')]
        [string]
        $TLStype = 'TLS 1.2\Server',
        [string]
        [ValidateSet("Best", "Okay", "Bad")]
        $rating
    )
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$TLStype"
    #$TLS11 = "Not Disabled, and may allow connection"
    if (Test-Path $key) {
        $tls11i = Get-ItemProperty $key
        if ($TLS11i.DisabledByDefault -ne 0 -or $TLS11i.Enabled -eq 0) {
            # the protocol is specifically enabled
            #$TLS11 = "Disabled"
            Write-LogText "$TLStype is Disabled"  
        }
        else {
            # the protocol is specifically enabled
            #$TLS11 = "Enabled"
            switch ($rating) {
                "Best" {
                    Write-LogText "$TLStype is enabled - and is Best" 
                    break
                }
                "Okay" {
                    Write-LogText "$TLStype is enabled - this is accetable"  -style warn
                    break
                }
                "Bad" {
                    Write-LogText "$TLStype is enabled - but should NOT be"  -style error
                    $alogError += "$TLStype is enabled - but should NOT be"
                    return "** $TLStype is enabled - but should NOT be"
                    break
                }
                default {
                    Write-LogText "$TLStype is enabled - but risk is unknown"  -style warn
                    $alogError += "$TLStype is enabled - but risk is unknown"
                    return "** $TLStype is enabled - but risk is unknown"
                }
            }
        }
    }
    else {
        # no registry setting to restrict this.. 
        switch ($rating) {
            "Best" {
                Write-LogText "$TLStype may allow connection - and is safe" 
                break
            }
            "Okay" {
                Write-LogText "$TLStype may allow connection - this is accetable"  -style warn
                break
            }
            "Bad" {
                Write-LogText "$TLStype is not specifically Disabled - Older OS versions might allow connection"  -style error
                $alogError += "$TLStype is not specifically Disabled - Older OS versions might allow connection"
                return "** $TLStype is not specifically Disabled - Older OS versions might allow connection"
                break
            }
            default {
                Write-LogText "$TLStype is not specifically Disabled - Older OS versions might allow connection - risk unknown"  -style warn
                $alogError += "$TLStype is not specifically Disabled - Older OS versions might allow connection - risk unknown"
                return "$TLStype is not specifically Disabled - Older OS versions might allow connection - risk unknown"
            }
        }
        # return # return indicating the TLS settings were not 
    }
}



function Write-LogObject {
    param (
        [parameter(Mandatory = $true, HelpMessage = "the Object to log")]
        [PSObject]$outObj,
        [parameter(Mandatory = $false, HelpMessage = "FT= table format, FL = List format")]
        [ValidateSet("FT", "FL")]
        [string]$format = "FT"
    )
    switch ($format) {
        "FT" { if ($outputFormat -eq "text" ) { $outObj | Format-Table } }
        "FL" { if ($outputFormat -eq "text" ) { $outObj | Format-List } }
    }
 
    if ($logfile) {
        $render = $PSStyle.OutputRendering 
        if ($render) { $PSStyle.OutputRendering = 'Host' } #this avoids outputting special formatting chars
        $outObj   | Format-List  | Out-File $logfile -Append  # -Encoding  utf8 }
        #       Out-String -InputObject $outObj  | Format-List  | Out-File $logfile -Append  # -Encoding  utf8 }
        if ($render ) { $PSStyle.OutputRendering = $render }       
    }

} 
function Write-LogText {
    param( 
        [parameter(Mandatory = $true, HelpMessage = "the text to log")]
        [string]$outtext,
        [parameter(Mandatory = $false, HelpMessage = "indicate the style of logging error or normal etc")]
        [ValidateSet("error", "warn")]
        [string]$style#,

    )
    switch ($style) {
        "error" {
            if ($outputFormat -eq "text" ) { Write-Host $outtext  -ForegroundColor Red }
            if ($logfile) { "**ERROR**  $outtext" >> $logfile }#Out-File -FilePath $logfile}
            # $buildErrors += $outtext
            break
        }
        "warn" {
            if ($outputFormat -eq "text" ) { Write-Host $outtext  -ForegroundColor yellow }
            if ($logfile) { "$outtext" >> $logfile }
            # $buildErrors += $outtext
            break
        }

        default {
            if ($outputFormat -eq "text" ) { Write-Host $outtext }
            if ($logfile) { "$outtext" >> $logfile }
            # $buildnotes += $outtext
        }
    }
}

function test-versionOkay {
    param(
        [string]$checkthis,
        [string]$minver = "0.0.0.0"
    )
    $c = $checkthis.split(".")
    $min = $minver.split(".")
    if ($c[0] -gt $min[0]) { return $true }
    if ($c[0] -lt $min[0]) { return $false }
    if ($c[1] -gt $min[1]) { return $true }
    if ($c[1] -lt $min[1]) { return $false }
    if ($c[2] -gt $min[2]) { return $true }
    if ($c[2] -lt $min[2]) { return $false }
    if ($c[3] -gt $min[3]) { return $true }
    if ($c[3] -lt $min[3]) { return $false }
    return $true
    
}

function get-appdetails {
    param(
        [string] $Name,
        [string] $ServiceSearchName,
        [string] $AppsearchName,
        [string] $minversion = $null,
        [switch] $ignoreIfNotFound
    )
    $alogError = @()
    $i = Get-CimInstance win32_service | Where-Object Name -Like $ServiceSearchName | Select-Object @{n = 'Name'; e = { $Name } }, State, Status, Caption, Version, @{n = 'ServiceName'; e = { $ServiceSearchName } }, @{n = 'Comment'; e = { $null } }, InstallDate, DisplayName
    if ($i) {
       
        $u = $i.PathName -split ("\\")
        if (!$version -and $u.count -gt 1) {
            $i.version = $u[($u.count - 2)]
        }
    }
    if (!$i) {
        if (!$ignoreIfNotFound) {
            Write-LogText "$Name has not been installed"   -style error
            $alogError += "$Name has not been installed" 
            $i = [PSCustomObject]@{
                Name        = $Name
                State       = "Not Installed"
                Status      = "FAIL"
                #  InstallDate = $null
                Caption     = $Name
                Version     = $null
                ServiceName = $ServiceSearchName
                Comment     = $null
                InstallDate = $null
                Displayname = $name
                #  PathName    = $null

            }
        }
    }
    else {
        $s = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object displayname -like $AppsearchName | Select-Object DisplayVersion, Installdate
        $i.Version = $s.DisplayVersion
        if ($minversion ) {
            if (!(test-versionOkay -checkthis $s.DisplayVersion -minver $minversion)) {
                Write-LogText "$Name is an OLD version, and needs updating"  -style error
                $alogError += "$Name is an OLD version, and needs updating"
                $i.Status = "$($i.Status) expired-Version"
            }
        }
        $i.InstallDate = $s.InstallDate
        if (($i.State -ne "Running") -and ($i.Status -ne "OK")) {
            Write-LogText "S$Name is installed but not working well: status:$($i.status) state:$($i.state)" -style error
            $alogError += "S$Name is installed but not working well: status:$($i.status) state:$($i.state)"
        }

        switch ($Name) {
            "SCCM" {
                $i.Comment = "MP = $((Get-ItemProperty HKLM:\Software\Microsoft\CCMSetup).LastValidMP)" 
            }
            "SEP" {
                $u = Get-ItemProperty "HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\Common Client\ccGenericEvent\Global\Instance" | Select-Object Active
                if ($u.Active -ne 1) { $i.comment = "FAIL ($u)" }
                $u = Get-ItemProperty "HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\public-opstate" | Select-Object LatestVirusDefsDate , LastSuccessfulScanDateTime
                $i.comment = "$($i.comment) virusdefs:$($u.LatestVirusDefsDate) last scanned $(Get-Date($u.LastSuccessfulScanDateTime) -Format yyyy-MM-dd)"
            } 
            "SCOM" {
                $SCOMAgent = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
                try {
                    $u = $SCOMAgent.GetManagementGroups()[0]
                }
                catch {
                    Write-LogText "Not able to check SCOM config -make sure you runas administrator" -style error
                    $alogError += "Not able to check SCOM config -make sure you runas administrator"
                    $i.Comment = "Not able to check SCOM config -make sure you runas administrator" 
                }
                if ($u) {
                    $i.comment = "$($u.managementGroupName) $($u.ManagementServer)"
                }
                elseif (!$i.Comment) {
                    $i.comment = "NOT configured to a SCOM management group"
                    Write-LogText "SCOM installed but not configured with a management group" -style error
                    $alogError += "SCOM installed but not configured with a management group" 
                }
            }
        }
    }
    # $alogError += "test"
    $r = [PSCustomObject]@{
        data  = $i
        error = $alogError
    }
    return $r

}
if ($logfile) {
    New-Item -Path $logfile -ItemType File -Force  | Out-Null
    write-host "log will be written to $logfile and .html"    
}


$buildErrors = @()
$buildnotes = @()
$antivirusRunning = @()
$softwares = @()




$buildnotes += "checking the build configuration on $(get-date)"
Write-LogText "checking the build configuration on $(get-date)"



$cinfo = Get-ComputerInfo | Select-Object @{n = 'Name'; e = { $_.CsName } }, @{n = 'Hostname'; e = { $_.CsDNSHostName } }   , @{n = 'Domain'; e = { $_.CsDomain } } , WindowsProductName , @{n = 'Model'; e = { $_.CsModel } }, @{n = 'Uptime'; e = { $_.OsUptime } } , OsStatus, @{n = 'CPU'; e = { $_.CsNumberOfProcessors } } , @{n = 'LogicalProcessors'; e = { $_.CsNumberOfLogicalProcessors } }, @{n = 'ProcessorType'; e = { $_.CsProcessors[0].Name } }, @{n = 'MemGiB'; e = { [math]::Round( $_.CsTotalPhysicalMemory / 1073741824) } }
# CsMOdel, CsNumberOfProcessors, CsNumberOfLogicalProcessors ,CsProcessors,OsUptime


$winLicense = Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | where-Object { $_.PartialProductKey } | Select-Object Description, LicenseStatus, TrustedTime

if ($winLicense.LicenseStatus -eq 1) {
    $cinfo | Add-Member -NotePropertyName LicenseStatus -NotePropertyValue 'Licensed'
}
else {
    $cinfo | Add-Member -NotePropertyName LicenseStatus -NotePropertyValue "NOT-Licensed/Activated"
    Write-LogText "OS is NOT LICENSED - either KMS is not configured, or is not Activated" -style error
    $buildErrors += "OS is NOT LICENSED - either KMS is not configured, or is not Activated"
}


$cinfo | Add-Member -NotePropertyName LastUpdateOn -NotePropertyValue (Get-CimInstance -class win32_quickfixengineering | Sort-Object InstalledOn -Descending).InstalledOn[0].tostring("yyyy-MM-dd")



$i = get-appdetails -Name 'SCCM' -ServiceSearchName "ccmExec" -AppsearchName "Configuration Manager Client" -clientserver $cinfo.Hostname -minversion $minverSCCM -ignoreIfNotFound
if ($i) {
    $sccm = $i.data
    $buildErrors += $i.error
    $softwares += $sccm
    $batch = $null
    if ($sccm.version) {

        try {
            $sccmhub = (Get-ItemProperty "HKLM:\SOFTWARE\\Microsoft\SMS\Mobile Client").AssignedSiteCode
        }
        catch {  }  

        switch ($sccmhub) {
            "HVL" { $sccmsrv = "dfs-sccmps-53.dpko.un.org" }
            "HBD" { $sccmsrv = "dfs-sccmps-03.dpko.un.org" }
            #  "HUB" { $sccmsrv = "dfs-sccmcas-52.dpko.un.org" ; Write-LogText "Could identify if SCCM Site code" -style error}
            default {
                $sccmsrv = "dfs-sccmcas-52.dpko.un.org"; Write-LogText "Could not identify if SCCM Site code as either HBD or HVL" -style error
                $cinfo | Add-Member -NotePropertyName SCCM-SiteCodeError -NotePropertyValue "SCCM might be installed but not configured properly"
                $sccmhub = "HUB"
            }
        }  
        $cinfo | Add-Member -NotePropertyName SCCM-SiteCode -NotePropertyValue $sccmhub

        if (!$dontCheckUpdateBatch) {
            try {
                if ($SCCMcredential -or ($cinfo.Domain -notlike "dpko.un.org" ) ) {
                    if (!$SCCMcredential -and !$runUnattended) { $SCCMcredential = Get-Credential -Message "your login details for SCCM (-su DPKO)" }
                    $batch = (Get-CimInstance -Namespace "root\sms\site_$sccmhub" -ComputerName $sccmsrv -Query "SELECT CollectionID, name FROM sms_collection WHERE CollectionID in (SELECT CollectionID FROM SMS_FullCollectionMembership WHERE name = '$($cinfo.Name)') AND name Like '%Updates - HUB %'" -Credential $SCCMcredential -ErrorAction stop).Name
                }
                else {
                    $batch = (Get-CimInstance -Namespace "root\sms\site_$sccmhub" -ComputerName $sccmsrv -Query "SELECT CollectionID, name FROM sms_collection WHERE CollectionID in (SELECT CollectionID FROM SMS_FullCollectionMembership WHERE name = '$($cinfo.Name)') AND name Like '%Updates - HUB %'" -ErrorAction stop).Name
                }
            }
            catch {
                $batch = "**** Could not retrieve Update Batch information ****"
                Write-LogText "Could not retrieve Update Batch information" -style error
                $buildErrors += "Could not retrieve Update Batch information" 
            } 

  
            if ($batch) {
                $cinfo | Add-Member -NotePropertyName UpdateBatch -NotePropertyValue $batch
            }
            else {
                $cinfo | Add-Member -NotePropertyName UpdateBatch -NotePropertyValue "**** no Update Batch assigned ****"
                Write-LogText "no update batch assigned" -style error
                $buildErrors += "no update batch assigned"
            }
        }
        else {
            $cinfo | Add-Member -NotePropertyName UpdateBatch -NotePropertyValue "this script was run without checking for update batch"
 
        }
    }
}

$softwareNames = @(
    @{
        Name              = 'VMtools'
        ServiceSearchName = 'Vmtools'
        AppsearchName     = 'vmware tools'
        MinVersion        = $minvervmtools
        av                = $false
    }
    <#
    @{
        Name              = 'SCOM'
        ServiceSearchName = 'HealthService'
        AppsearchName     = 'Microsoft Monitoring Agent'
        MinVersion        = $minverSCOM
        av                = $false
    }
    #>
    @{
        Name              = 'Antivirus:Symantec'
        ServiceSearchName = 'SEPMasterService'
        AppsearchName     = 'Symantec Endpoint Protection'
        IgnoreIfNotFound  = $true
        av                = $true

    }
    @{
        Name              = 'Antivirus:McAfee'
        ServiceSearchName = 'McAPExe'
        AppsearchName     = 'McAfee Antivirus'
        IgnoreIfNotFound  = $true
        av                = $true
    }
    @{
        Name              = 'Antivirus:Trend'
        ServiceSearchName = 'svcGenericHost'
        AppsearchName     = 'Trend'
        IgnoreIfNotFound  = $true
        av                = $true
    }
    @{
        Name              = 'Antivirus:MS Defender'
        ServiceSearchName = 'WinDefend'
        AppsearchName     = 'Defender'
        IgnoreIfNotFound  = $true
        av                = $true
    }
    @{
        Name              = 'Antivirus:MalwareBytes'
        ServiceSearchName = 'MBEndpointAgent'
        AppsearchName     = 'MalwareBytes'
        IgnoreIfNotFound  = $true
        av                = $true
    }
    @{
        Name              = 'N-able'
        ServiceSearchName = 'BASupportExpressStandaloneService_LOGICnow'
        AppsearchName     = 'N-Able'
        IgnoreIfNotFound  = $false
        av                = $false
    }
    @{
        Name              = 'StorageCraft Control (Conectwise?)'
        ServiceSearchName = 'stc_endpt_svc'
        AppsearchName     = 'StorageCraft Control (Conectwise?)'
        IgnoreIfNotFound  = $true
        av                = $false
    }
    @{
        Name              = 'Kiss IT Monitoring'
        ServiceSearchName = 'LTService'
        AppsearchName     = 'Kiss IT Monitoring'
        IgnoreIfNotFound  = $false
        av                = $false
    }
    @{
        Name              = 'Backup: ShadowProtectSPX'
        ServiceSearchName = 'SPXService'
        AppsearchName     = 'Backup: ShadowProtect-SPX'
        IgnoreIfNotFound  = $true
        av                = $false
    }
    @{
        Name              = 'Backup: Datto'
        ServiceSearchName = 'DattoBackupAgentService'
        AppsearchName     = 'Backup: Datto Backup Agent'
        IgnoreIfNotFound  = $true
        av                = $false
    }


)



foreach ($Software in $softwareNames) {
    $i = Get-AppDetails -Name $Software.Name -ServiceSearchName $Software.ServiceSearchName -AppsearchName $Software.AppSearchName -ignoreIfNotFound:$software.IgnoreIfNotFound
    $softwares += $i.data
    $buildErrors += $i.error
    if (($Software.av -eq $true) -and ($i.State -notlike 'Running')) {
        $antivirusRunning += $i
    }
}





# $i = get-appdetails -Name 'VMtools' -ServiceSearchName "Vmtools" -AppsearchName "vmware tools" -minversion $minvervmtools -ignoreIfNotFound
# $softwares += $i.data
# $buildErrors += $i.error
# $i = get-appdetails -Name 'SCOM' -ServiceSearchName "HealthService" -AppsearchName "Microsoft Monitoring Agent" -minversion $minverSCOM -ignoreIfNotFound
# $softwares += $i.data
# $buildErrors += $i.error

# $i = get-appdetails -Name 'Antivirus:Symantec ' -ServiceSearchName "SEPMasterService" -AppsearchName "Symantec Endpoint Protection" -ignoreIfNotFound
# $softwares += $i.data
# $buildErrors += $i.error
# if ($i.State -notlike "Running") { $antivirusRunning += $i}
# $i = get-appdetails -Name 'Antivirus:McAfee' -ServiceSearchName "McAPExe" -AppsearchName "McAfee Antivirus" -ignoreIfNotFound
# $softwares += $i.data
# $buildErrors += $i.error
# if ($i.State -notlike "Running") { $antivirusRunning += $i}
# $i = get-appdetails -Name 'Antivirus:Trend' -ServiceSearchName "svcGenericHost" -AppsearchName "Trend" -ignoreIfNotFound
# $softwares += $i.data
# $buildErrors += $i.error
# if ($i.State -notlike "Running") { $antivirusRunning += $i}
# $i = get-appdetails -Name 'Antivirus:MS Defender' -ServiceSearchName "WinDefend" -AppsearchName "Defender" -ignoreIfNotFound
# $softwares += $i.data
# $buildErrors += $i.error
# if ($i.State -notlike "Running") { $antivirusRunning += $i}
# $i = get-appdetails -Name 'Antivirus:MalwareBytes' -ServiceSearchName "MBEndpointAgent" -AppsearchName "MalwareBytes" -ignoreIfNotFound
# $softwares += $i.data
# $buildErrors += $i.error
# if ($i.State -notlike "Running") { $antivirusRunning += $i}


# $i = get-appdetails -Name 'N-ABle' -ServiceSearchName "BASupportExpressStandaloneService_LOGICnow" -AppsearchName "N-Able" 
# $softwares += $i.data
# $buildErrors += $i.error

# $i = get-appdetails -Name 'StorageCraft Control (Conectwise?)' -ServiceSearchName "stc_endpt_svc" -AppsearchName "StorageCraft Control" -ignoreIfNotFound
# $softwares += $i.data
# $buildErrors += $i.error

# $i = get-appdetails -Name 'Kiss IT Monitoring' -ServiceSearchName "LTService" -AppsearchName "Kiss IT Monitoring" 
# $softwares += $i.data
# $buildErrors += $i.error

# $i = get-appdetails -Name 'Backup: ShadowProtect' -ServiceSearchName "SPXService" -AppsearchName "Backup: ShadowprotectSPX" 
# $softwares += $i.data
# $buildErrors += $i.error

if (!$antivirusRunning) {
     Write-LogText "There is NO antivirus running !!" -style error 
    $buildErrors += "There is NO antivirus running"
    }

$i = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" | Select-Object release , version
if ($i) {
    if ($i.release -ge $minverNETFramework) {
        $cinfo | Add-Member -NotePropertyName 'Net-Framework' -NotePropertyValue "Net Framework installed -good version $($i.version)"
        write-LogText "Net Framework installed -good version $($i.version)" 

    }
    else {
        $cinfo | Add-Member -NotePropertyName 'Net-Framework' -NotePropertyValue "**Net Framework -BAD version $($i.version)"
        write-LogText "Net Framework -BAD version $($i.version)" -style error
        $buildErrors += "Net Framework -BAD version $($i.version)"
    
    }
}

$OS = (Get-CimInstance -class Win32_OperatingSystem).Caption
$i = -TLSversion -TLStype 'SSL 2.0\Server' -rating Bad #-OS $OS
if ($i) { $cinfo | Add-Member -NotePropertyName 'SSL 2.0 Server' -NotePropertyValue $i }
$i = Test-TlsVersion -TLStype 'SSL 3.0\Server' -rating Bad #-OS $OS
if ($i) { $cinfo | Add-Member -NotePropertyName 'SSL 3.0 Server' -NotePropertyValue $i }

$i = Test-TlsVersion -TLStype 'TLS 1.0\Server' -rating Bad
if ($i) { $cinfo | Add-Member -NotePropertyName 'TLS 1.0 Server' -NotePropertyValue $i }
Test-TlsVersion -TLStype  'TLS 1.1\Server' -rating Okay 
if ($i) { $cinfo | Add-Member -NotePropertyName 'TLS 1.1 Server' -NotePropertyValue $i }
Test-TlsVersion -TLStype  'TLS 1.2\Server' -rating Best
if ($i) { $cinfo | Add-Member -NotePropertyName 'TLS 1.2 Server' -NotePropertyValue $i }

Test-TlsVersion -TLStype  'SSL 2.0\Client' | Out-Null
Test-TlsVersion -TLStype  'SSL 3.0\Client'  | Out-Null
Test-TlsVersion -TLStype  'TLS 1.0\Client' | Out-Null
Test-TlsVersion -TLStype  'TLS 1.1\Client' -rating Okay | Out-Null
Test-TlsVersion -TLStype  'TLS 1.2\Client' -rating Best | Out-Null



if ($OS -match "2012") { $ciphers = $ciphers12 }
elseif ($OS -match "2016") { $ciphers = $ciphers16 }
else { $ciphers = $ciphers19 } #else {Write-Host "OS version not compatible"; exit}
$enabledCiphers = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002').functions
$unexpectedCiphers = $enabledciphers | where-object { $_ -notin $ciphers }

if ($unexpectedCiphers) {
    Write-LogText "Ciphers are enabled that are not on the approved list, see below" -style error
    $cinfo | Add-Member -NotePropertyName Ciphers -NotePropertyValue "***Ciphers are enabled that are not on the approved list"
    write-LogText "$($unexpectedCiphers -join ", `n")`n" -style error
    $buildErrors += "Ciphers are enabled that are not on the approved list, see below"
    $buildErrors += "$($unexpectedCiphers -join ", `n")`n"

}
else {
    write-LogText "there are NO unexpected ciphers in use" 
    $cinfo | Add-Member -NotePropertyName Ciphers -NotePropertyValue "there are NO unexpected ciphers in use"

}


if ((Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol).EnableSMB1Protocol) {
    write-LogText "SMBv1 is enabled and should be disabled`n" -style error
    $cinfo | Add-Member -NotePropertyName SMBv1 -NotePropertyValue "**SMBv1 is enabled and should be disabled"
    $buildErrors += "SMBv1 is enabled and should be disabled"
}

#display results on screen
Write-LogObject $cinfo -format FL
Write-LogObject $softwares

#HKEY_LOCAL_MACHINE\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\Common Client\ccGenericEvent\Global\Instance Active==1
#HKEY_LOCAL_MACHINE\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\public-opstate Avrunningstatus ==1, LatestVirusDefsDate, LastSuccessfulScanDateTime


#$diskInfo = Get-CimInstance -Class Win32_LogicalDisk | Where-Object { $_. DriveType -eq 3 } | Select-Object @{n = 'DriveLabel'; e = { $_.DeviceID } }, VolumeName, @{n = 'SizeGB'; e = { [math]::Round( $_.Size / 1073741824) } }, @{n = 'FreeGB'; e = { [math]::Round( $_.FreeSpace / 1073741824) } }
$diskInfo = Get-CimInstance -Class Win32_LogicalDisk | Where-Object { $_. DriveType -eq 3 } | Select-Object @{n = 'DriveLabel'; e = { $_.DeviceID } }, VolumeName, @{n = 'SizeGB'; e = { [math]::Round( $_.Size / 1073741824) } }, @{n = 'FreeGB'; e = { [math]::Round( $_.FreeSpace / 1073741824) } }
Write-LogObject $diskInfo
if ($buildErrors) {
    $terr = $buildErrors | Select-Object @{label = 'Errors'; expression = { $_ } } | ConvertTo-HTML -Fragment -as Table -Property "Errors"
} 
else { $terr = $null }
$tnotes = $buildnotes | Select-Object @{label = 'Notes'; expression = { $_ } } | ConvertTo-HTML -Fragment -As Table -Property "Notes"
$tinfo = $cinfo | ConvertTo-Html  -As List -Fragment
$tsoftw = $softwares | ConvertTo-Html  -As table -Fragment
$tdisk = $diskInfo | ConvertTo-Html   -As table -Fragment 
# $ti = "<h3>Notes</h3>$tnotes"
# if ($buildErrors) { $ti = "<h3>$terr</h3>$ti" }
$thtml = ConvertTo-Html -Body "$($terr)$tnotes<h3>Details</h3>$tinfo<h3>Software</h3>$tsoftw<h3>Partitions</h3>$tdisk" -Title "test-build results for $($cinfo.name)" 
#return $buildErrors
if ($logfile) {
    $f = $logfile -replace ".txt", ""
    $thtml > "$f.html"
}
if ($outputFormat -eq "text") { return }
if ($outputFormat -eq "html") { return $thtml }
$cinfo | Add-Member -NotePropertyName Applications -NotePropertyValue $softwares
$cinfo | Add-Member -NotePropertyName Partitions -NotePropertyValue $diskInfo
$cinfo | Add-Member -NotePropertyName ERRORS -NotePropertyValue $buildErrors
$cinfo | Add-Member -NotePropertyName Notes -NotePropertyValue $buildnotes
if ($outputFormat -eq "psobject") { return $cinfo }
if ($outputFormat -eq "json") { return $cinfo | ConvertTo-Json }
