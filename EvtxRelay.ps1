#Requires -Version 5.1
<#
.SYNOPSIS
    takes a csv file (from hayabusa, chainsaw, evtxecmd, or apt-hunter) and
    loads it into elasticsearch, then makes sure kibana has a matching data
    view and saved search ready to open.

.DESCRIPTION
    reads a csv made by one of the four tools, cleans up its column names
    (removes the hidden byte at the start of the file, swaps dots for
    underscores), uploads every row in batches, double checks that no column
    got dropped along the way, and sets up a kibana data view and saved
    search if they don't already exist. if the target index already exists,
    it warns and asks whether to delete and replace it or use a different
    name instead, so you don't silently pile duplicate rows into an old
    index.

    apt-hunter is different: it writes a whole folder of csv files instead of
    one, so use -Folder with -Tool apt-hunter instead of -File, and every csv
    in the folder gets uploaded into its own index in one run.

    -Tool auto and -Tool log also accept -Folder, for a folder of same-kind
    files (the same export tool run against several hosts, or a rotated log
    directory). unlike apt-hunter, every file in the folder shares one index
    instead of getting its own, with a source_file field on each document so
    you can still tell which file a given row or line came from.

    kibana changed how data views are managed between versions, so this
    script tries the newer way first and automatically falls back to the
    older way if that fails.

.EXAMPLE
    .\EvtxRelay.ps1 -File .\crownjewel2.csv -Tool hayabusa

.EXAMPLE
    .\EvtxRelay.ps1 -File .\path.csv -Tool chainsaw -ElkHost 10.10.10.5

.EXAMPLE
    .\EvtxRelay.ps1 -File .\path.csv -Tool evtxecmd -UseSshTunnel `
        -SshUser security-engineer -SshKeyPath ~\.ssh\engineer.pem

    first run with -UseSshTunnel: use this when elasticsearch/kibana can only
    be reached from inside the server itself, not from outside. the script
    opens a background connection through ssh to reach them, and reuses that
    same connection on later runs if it's still open. the ssh username, key,
    and ports are remembered after the first run, so later runs only need
    -File and -Tool.

.EXAMPLE
    .\EvtxRelay.ps1 -Folder .\apt-hunter-output -Tool apt-hunter

    apt-hunter writes a whole folder of csv files, one per event category,
    instead of a single csv. point -Folder at that folder instead of using
    -File, and every csv in it gets uploaded into its own index in one run.

.EXAMPLE
    .\EvtxRelay.ps1 -File .\unknown-tool-output.csv -Tool auto

    for a csv from a tool evtxrelay doesn't know about. columns that match a
    small set of common concepts (timestamp, source/dest ip, hostname, user
    name, event id, process name) get renamed to a shared name, using the
    table in .evtxrelay\field-aliases.json (created with built-in defaults
    the first time -tool auto runs, and editable after that). every other
    column passes through untouched, same as the other three tools.

.EXAMPLE
    .\EvtxRelay.ps1 -Folder .\exports -Tool auto

    for a folder of csvs of the same kind (for example, the same export tool
    run against several hosts). every file is detected independently, but
    they all land in one shared index instead of one each, with a
    source_file field on every row so you can still tell them apart.

.EXAMPLE
    .\EvtxRelay.ps1 -File .\auth.log -Tool log

    for a plain .log file instead of a csv, like syslog/auth.log, firewall
    logs, or web server access logs. each line becomes one event with a raw
    message field and, when elasticsearch can reliably detect a per-line
    timestamp pattern, a parsed @timestamp field. a line that doesn't match
    the pattern still gets uploaded, just tagged grok_parse_failed instead
    of timed.

.EXAMPLE
    .\EvtxRelay.ps1 -Folder .\var-log -Tool log

    for a folder of log files, like a rotated auth.log directory
    (auth.log, auth.log.1, auth.log.2). every file in the folder is picked
    up except compressed ones (.gz/.zip/.bz2, skipped rather than
    decompressed), each gets its own timestamp detection, and they all land
    in one shared index tagged with source_file.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$File,

    [Parameter(Mandatory)]
    [ValidateSet('hayabusa', 'chainsaw', 'evtxecmd', 'apt-hunter', 'auto', 'log')]
    [string]$Tool,

    [string]$Folder,
    [string]$IndexName,
    [switch]$ExactIndexName,
    [string]$ElkHost,
    [int]$ElasticPort = 9200,
    [int]$KibanaPort = 5601,
    [int]$BatchSize = 2000,
    [string]$TimestampField,
    [switch]$SkipCertificateCheck,
    [switch]$ResetCredential,

    [switch]$UseSshTunnel,
    [string]$SshUser,
    [string]$SshKeyPath,
    [int]$RemoteElasticPort,
    [int]$RemoteKibanaPort
)

$ErrorActionPreference = 'Stop'

# make sure this computer offers modern https, even if its own default setting is older
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# lets -skipcertificatecheck work on older windows powershell (5.1), which
# can't do this the normal, simpler way. newer powershell handles this on
# its own elsewhere in the script.
if (-not ('EvtxRelay.TrustAllCertsPolicy' -as [type])) {
    Add-Type @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
namespace EvtxRelay {
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
            return true;
        }
    }
}
'@
}

# builds the final index name out of the tool, the sub-part of it (an
# apt-hunter category, or "events" for tools that don't have one), and the
# optional custom name from -indexname, e.g. "hayabusa-events" or, with a
# custom name of "case42", "case42-hayabusa-events". with -exact, the custom
# name is used as-is instead of getting the tool name mixed in ("case42"), or
# for apt-hunter, as-is plus just the category ("case42-logon_events"), since
# apt-hunter still needs each category kept in its own index
function Get-EvtxRelayIndexName {
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$SubModule,
        [string]$CustomName,
        [switch]$Exact
    )
    if ($CustomName -and $Exact) {
        if ($Tool -eq 'apt-hunter') { return "$CustomName-$SubModule" }
        return $CustomName
    }
    $baseName = "$Tool-$SubModule"
    if ($CustomName) { return "$CustomName-$baseName" }
    return $baseName
}


# SETUP


$ConfigDir = '.evtxrelay'
if (-not (Test-Path -LiteralPath $ConfigDir)) {
    New-Item -Path $ConfigDir -ItemType Directory -Force | Out-Null
}
$LogPath = Join-Path $ConfigDir 'evtxrelay.log'
$ElkHostPlaceholder = '<ISI_IP_ATAU_HOSTNAME_ELK_DI_SINI>'
if (-not $IndexName -and $ExactIndexName) { throw '-ExactIndexName requires -IndexName to be given as well.' }
if ($Tool -ne 'apt-hunter') { $IndexName = Get-EvtxRelayIndexName -Tool $Tool -SubModule 'events' -CustomName $IndexName -Exact:$ExactIndexName }

# best guess at which column holds the date/time for each tool, used only if
# -timestampfield isn't given by hand. apt-hunter names this column
# differently in each of its category csvs, so all three names it uses are
# listed; the first one actually present in a given file wins.
$TimestampCandidates = @{
    hayabusa     = @('Timestamp')
    chainsaw     = @('timestamp', 'Timestamp', 'Event_System_TimeCreated_SystemTime')
    evtxecmd     = @('TimeCreated')
    'apt-hunter' = @('Date and Time', 'DateTime', 'datetime')
}

# elasticsearch only auto-recognizes a few common date styles. hayabusa,
# evtxecmd, and apt-hunter don't match, so their exact format is spelled out
# here. chainsaw already matches on its own, so it isn't listed. without
# this, the date column would silently be stored as plain text instead of a
# real date.
$TimestampFormats = @{
    hayabusa     = 'yyyy-MM-dd HH:mm:ss.SSS XXX||strict_date_optional_time||epoch_millis'
    evtxecmd     = 'yyyy-MM-dd HH:mm:ss.SSSSSSS||strict_date_optional_time||epoch_millis'
    'apt-hunter' = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX||strict_date_optional_time||epoch_millis"
}

# for -tool auto, there's no single known format to trust up front like the
# four known tools above. instead, sample values from the resolved
# event_timestamp column are tested against these, in order, until one fits
# every sample. each pairs a .net format (to test locally) with the matching
# elasticsearch mapping format (used once a fit is found).
$AutoTimestampFormatCandidates = @(
    [PSCustomObject]@{ DotNetFormat = 'yyyy-MM-ddTHH:mm:ss.ffffffK'; EsFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX||strict_date_optional_time||epoch_millis" }
    [PSCustomObject]@{ DotNetFormat = 'yyyy-MM-ddTHH:mm:ssK'; EsFormat = "yyyy-MM-dd'T'HH:mm:ssXXX||strict_date_optional_time||epoch_millis" }
    [PSCustomObject]@{ DotNetFormat = 'yyyy-MM-dd HH:mm:ss.fff K'; EsFormat = 'yyyy-MM-dd HH:mm:ss.SSS XXX||strict_date_optional_time||epoch_millis' }
    [PSCustomObject]@{ DotNetFormat = 'yyyy-MM-dd HH:mm:ss.fff'; EsFormat = 'yyyy-MM-dd HH:mm:ss.SSS||strict_date_optional_time||epoch_millis' }
    [PSCustomObject]@{ DotNetFormat = 'yyyy-MM-dd HH:mm:ss'; EsFormat = 'yyyy-MM-dd HH:mm:ss||strict_date_optional_time||epoch_millis' }
    [PSCustomObject]@{ DotNetFormat = 'MM/dd/yyyy HH:mm:ss'; EsFormat = 'MM/dd/yyyy HH:mm:ss||strict_date_optional_time||epoch_millis' }
)


# LOGGING


# prints a message to the screen and also saves it to the log file
function Write-EvtxRelayLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO',
        [Parameter(Mandatory)][string]$LogPath
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        'WARN' { Write-Warning $Message }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
    Add-Content -LiteralPath $LogPath -Value $line
}


# SETTINGS AND SAVED LOGIN


# creates a blank settings file for the user to fill in on first run
function New-EvtxRelayConfigTemplate {
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$Placeholder,
        [Parameter(Mandatory)][string]$LogPath
    )
    $template = [PSCustomObject]@{
        ElkHost           = $Placeholder
        UseSshTunnel      = $false
        SshUser           = ''
        SshKeyPath        = ''
        RemoteElasticPort = 9200
        RemoteKibanaPort  = 443
    }
    $template | ConvertTo-Json | Set-Content -LiteralPath $ConfigPath
    Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "No config found. Created a template at '$ConfigPath'. Edit 'ElkHost' (and the SSH fields, if you need -UseSshTunnel) before running again."
}

# loads the saved settings file, mixes in any values passed on the command
# line, and makes sure everything needed is actually set before continuing
function Get-EvtxRelayConfig {
    param(
        [Parameter(Mandatory)][string]$ConfigDir,
        [string]$ElkHostOverride,
        [Parameter(Mandatory)][hashtable]$SshOverrides,
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$ElkHostPlaceholder
    )
    $configPath = Join-Path $ConfigDir 'config.json'

    if (-not (Test-Path -LiteralPath $configPath)) {
        New-EvtxRelayConfigTemplate -ConfigPath $configPath -Placeholder $ElkHostPlaceholder -LogPath $LogPath
        throw "config.json did not exist, so a template was created at '$configPath'. Fill in 'ElkHost' (and SSH fields if you use -UseSshTunnel), then run again."
    }

    try {
        $cached = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Cached config at '$configPath' is corrupt or unreadable ($($_.Exception.Message)). Fix or delete the file, then run again; it will not be overwritten automatically."
    }

    $elkHostValue = if ($ElkHostOverride) { $ElkHostOverride } elseif ($cached.ElkHost) { $cached.ElkHost } else { $null }

    if ([string]::IsNullOrWhiteSpace($elkHostValue) -or $elkHostValue -eq $ElkHostPlaceholder) {
        throw "No ELK host is set. Pass -ElkHost explicitly, or edit 'ElkHost' in '$configPath' (it's currently unset or still the placeholder value)."
    }

    $useSshTunnelValue = if ($SshOverrides.ContainsKey('UseSshTunnel')) { [bool]$SshOverrides.UseSshTunnel }
    elseif ($null -ne $cached.UseSshTunnel) { [bool]$cached.UseSshTunnel }
    else { $false }

    $sshUserValue = if ($SshOverrides.SshUser) { $SshOverrides.SshUser }
    elseif ($cached.SshUser) { $cached.SshUser }
    else { $null }

    $sshKeyPathValue = if ($SshOverrides.SshKeyPath) { $SshOverrides.SshKeyPath }
    elseif ($cached.SshKeyPath) { $cached.SshKeyPath }
    else { $null }

    $remoteElasticPortValue = if ($SshOverrides.ContainsKey('RemoteElasticPort')) { [int]$SshOverrides.RemoteElasticPort }
    elseif ($cached.RemoteElasticPort) { [int]$cached.RemoteElasticPort }
    else { 9200 }

    $remoteKibanaPortValue = if ($SshOverrides.ContainsKey('RemoteKibanaPort')) { [int]$SshOverrides.RemoteKibanaPort }
    elseif ($cached.RemoteKibanaPort) { [int]$cached.RemoteKibanaPort }
    else { 443 }

    if ($useSshTunnelValue) {
        if ([string]::IsNullOrWhiteSpace($sshUserValue)) {
            throw 'SSH tunnel is enabled (-UseSshTunnel) but no SSH username is set. Pass -SshUser once so it can be cached.'
        }
        if ([string]::IsNullOrWhiteSpace($sshKeyPathValue)) {
            throw 'SSH tunnel is enabled (-UseSshTunnel) but no SSH key path is set. Pass -SshKeyPath once so it can be cached.'
        }
    }

    $configObject = [PSCustomObject]@{
        ElkHost           = $elkHostValue
        UseSshTunnel      = $useSshTunnelValue
        SshUser           = $sshUserValue
        SshKeyPath        = $sshKeyPathValue
        RemoteElasticPort = $remoteElasticPortValue
        RemoteKibanaPort  = $remoteKibanaPortValue
    }
    $configObject | ConvertTo-Json | Set-Content -LiteralPath $configPath

    return $configObject
}

# gets the saved login for elastic/kibana, or asks the user to type it in if
# there isn't one saved yet (or -resetcredential was passed)
function Get-EvtxRelayCredential {
    param(
        [Parameter(Mandatory)][string]$ConfigDir,
        [switch]$Reset,
        [Parameter(Mandatory)][string]$LogPath
    )
    $credPath = Join-Path $ConfigDir 'credential.xml'
    if (-not $Reset -and (Test-Path -LiteralPath $credPath)) {
        try {
            $cred = Import-Clixml -LiteralPath $credPath
            if (-not $cred -or -not $cred.UserName) {
                throw 'cached credential file is empty or missing a username'
            }
            return $cred
        }
        catch {
            Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Could not use cached credential at '$credPath' ($($_.Exception.Message)). This usually happens if the cache was copied from a different Windows user/machine. Re-prompting for credentials."
        }
    }

    Write-EvtxRelayLog -LogPath $LogPath -Message 'No usable cached credential found. Enter your Elastic/Kibana credentials below.'

    $userName = Read-Host -Prompt 'Elastic/Kibana username'
    if ([string]::IsNullOrWhiteSpace($userName)) {
        throw 'No username was entered. Re-run the script to try again.'
    }
    $securePassword = Read-Host -Prompt 'Elastic/Kibana password' -AsSecureString
    if ($securePassword.Length -eq 0) {
        throw 'No password was entered. Re-run the script to try again.'
    }

    $cred = New-Object System.Management.Automation.PSCredential($userName, $securePassword)
    $cred | Export-Clixml -LiteralPath $credPath
    return $cred
}


# SSH TUNNEL


# checks whether something is already listening on a given port on this
# computer
function Test-LocalPortOpen {
    param([Parameter(Mandatory)][int]$Port)
    $result = Test-NetConnection -ComputerName 'localhost' -Port $Port -WarningAction SilentlyContinue -InformationLevel Quiet
    return [bool]$result
}

# opens a background ssh connection to reach elasticsearch/kibana, or reuses
# one that's already open
function Confirm-SshTunnel {
    param(
        [Parameter(Mandatory)][string]$ElkHost,
        [Parameter(Mandatory)][string]$SshUser,
        [Parameter(Mandatory)][string]$SshKeyPath,
        [Parameter(Mandatory)][int]$LocalElasticPort,
        [Parameter(Mandatory)][int]$RemoteElasticPort,
        [Parameter(Mandatory)][int]$LocalKibanaPort,
        [Parameter(Mandatory)][int]$RemoteKibanaPort,
        [Parameter(Mandatory)][string]$LogPath
    )

    # turn the key path into a full path ourselves first. if the path starts
    # with '~' (short for "home folder") and we don't expand it here, ssh
    # would get the literal text '~\...' and misread it as part of a
    # username instead of a folder.
    try {
        $resolvedKeyPath = (Resolve-Path -LiteralPath $SshKeyPath -ErrorAction Stop).ProviderPath
    }
    catch {
        throw "SSH key file not found at '$SshKeyPath'."
    }

    if ((Test-LocalPortOpen -Port $LocalElasticPort) -and (Test-LocalPortOpen -Port $LocalKibanaPort)) {
        Write-EvtxRelayLog -LogPath $LogPath -Message "SSH tunnel already up on local ports $LocalElasticPort/$LocalKibanaPort; reusing it."
        return
    }

    Write-EvtxRelayLog -LogPath $LogPath -Message "Starting background SSH tunnel to ${SshUser}@${ElkHost}: local $LocalElasticPort -> remote localhost:$RemoteElasticPort (Elasticsearch), local $LocalKibanaPort -> remote localhost:$RemoteKibanaPort (Kibana)."

    $sshArgs = @(
        '-i', $resolvedKeyPath,
        '-N',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ExitOnForwardFailure=yes',
        '-o', 'BatchMode=yes',
        '-L', "${LocalElasticPort}:localhost:${RemoteElasticPort}",
        '-L', "${LocalKibanaPort}:localhost:${RemoteKibanaPort}",
        "$SshUser@$ElkHost"
    )
    # a working tunnel stays open and never "finishes", so we start ssh in
    # the background and check the local ports instead of waiting on it.
    # a passphrase-protected key fails fast here instead of hanging forever.
    Start-Process -FilePath 'ssh' -ArgumentList $sshArgs -NoNewWindow | Out-Null

    $deadline = (Get-Date).AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 500
        $up = (Test-LocalPortOpen -Port $LocalElasticPort) -and (Test-LocalPortOpen -Port $LocalKibanaPort)
    } while (-not $up -and (Get-Date) -lt $deadline)

    if (-not $up) {
        throw "SSH tunnel did not come up within 10 seconds on local ports $LocalElasticPort/$LocalKibanaPort. Try connecting manually to check: ssh -i `"$SshKeyPath`" $SshUser@$ElkHost"
    }

    Write-EvtxRelayLog -LogPath $LogPath -Message 'SSH tunnel is up.'
}


# WEB REQUESTS


# sends one web request to elasticsearch or kibana and returns the response
function Invoke-ElkRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Method,
        [hashtable]$Headers,
        [string]$Body,
        [string]$ContentType,
        [switch]$SkipCertificateCheck
    )

    $params = @{ Uri = $Uri; Method = $Method; Headers = $Headers }
    if ($Body) {
        # older windows powershell can quietly use the wrong text encoding
        # and corrupt special characters, so convert to bytes ourselves
        $params.Body = [System.Text.Encoding]::UTF8.GetBytes($Body)
    }
    if ($ContentType) { $params.ContentType = $ContentType }

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        if ($SkipCertificateCheck) { $params.SkipCertificateCheck = $true }
    }
    elseif ($SkipCertificateCheck) {
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object EvtxRelay.TrustAllCertsPolicy
    }

    return Invoke-RestMethod @params
}


# CLEANING UP THE CSV


# builds a lookup of original column name to cleaned up column name, and
# makes sure no two columns end up with the same cleaned up name
function Get-SanitizedHeaderMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Headers
    )

    $map = [ordered]@{}
    $seen = @{}

    for ($i = 0; $i -lt $Headers.Count; $i++) {
        $name = $Headers[$i]
        if ($i -eq 0) {
            # some csv files start with a hidden marker character, strip it
            # off the first column only
            $name = $name.TrimStart([char]0xFEFF)
        }
        $sanitized = $name -replace '\.', '_'

        if ($seen.ContainsKey($sanitized)) {
            throw "Column name collision after sanitization: '$($Headers[$i])' and '$($seen[$sanitized])' both map to '$sanitized'. Rename one of the source columns before re-running."
        }
        $seen[$sanitized] = $Headers[$i]
        $map[$Headers[$i]] = $sanitized
    }

    return $map
}

# rebuilds one row of data using the cleaned up column names. -sourcefile is only passed in
# folder batch mode, where several files share one index and a tag is needed to tell them apart
function ConvertTo-SanitizedRecord {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)]$HeaderMap,
        [string]$SourceFile
    )
    $out = [ordered]@{}
    foreach ($original in $HeaderMap.Keys) {
        $out[$HeaderMap[$original]] = $Record.$original
    }
    if ($SourceFile) { $out['source_file'] = $SourceFile }
    return $out
}

# turns a batch of rows into the specific text format elasticsearch expects
# for uploading many rows at once
function ConvertTo-BulkBody {
    param(
        [Parameter(Mandatory)][string]$IndexName,
        [Parameter(Mandatory)][array]$Records
    )
    $actionLine = '{"index":{"_index":"' + $IndexName + '"}}'
    $lines = foreach ($rec in $Records) {
        $actionLine
        ($rec | ConvertTo-Json -Compress -Depth 5)
    }
    return ($lines -join "`n") + "`n"
}


# INDEX SETUP


# checks whether the index we're about to use already exists. if it does,
# warns and asks whether to delete and replace it or type a different custom
# name instead, looping until the name is free or the old index gets replaced
function Resolve-EvtxRelayAvailableIndexName {
    param(
        [Parameter(Mandatory)][string]$ElasticBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$SubModule,
        [Parameter(Mandatory)][string]$IndexName,
        [switch]$Exact,
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory)][string]$LogPath
    )

    $candidate = $IndexName
    while ($true) {
        $exists = $true
        try {
            Invoke-ElkRequest -Uri "$ElasticBaseUri/$candidate" -Method Get `
                -Headers $AuthHeaders -SkipCertificateCheck:$SkipCertificateCheck | Out-Null
        }
        catch {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound) {
                $exists = $false
            }
            else {
                throw
            }
        }

        if (-not $exists) { return $candidate }

        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Index '$candidate' already exists."
        $answer = Read-Host -Prompt "Replace it? This deletes everything already in '$candidate' (y/n)"
        if ($answer -match '^(?i)y') {
            Invoke-ElkRequest -Uri "$ElasticBaseUri/$candidate" -Method Delete `
                -Headers $AuthHeaders -SkipCertificateCheck:$SkipCertificateCheck | Out-Null
            Write-EvtxRelayLog -LogPath $LogPath -Message "Deleted existing index '$candidate'."
            return $candidate
        }

        $newCustomName = Read-Host -Prompt 'Enter a different custom index name'
        if ([string]::IsNullOrWhiteSpace($newCustomName)) {
            throw 'No index name was entered. Re-run the script to try again.'
        }
        $candidate = Get-EvtxRelayIndexName -Tool $Tool -SubModule $SubModule -CustomName $newCustomName -Exact:$Exact
    }
}

# creates the index if it doesn't exist yet, telling elasticsearch ahead of
# time which column holds the date/time and what format it's in
function Confirm-IndexWithTimestampMapping {
    param(
        [Parameter(Mandatory)][string]$ElasticBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [Parameter(Mandatory)][string]$IndexName,
        [string]$TimestampField,
        [string]$TimestampFormat,
        [switch]$SkipCertificateCheck
    )

    try {
        Invoke-ElkRequest -Uri "$ElasticBaseUri/$IndexName" -Method Get `
            -Headers $AuthHeaders -SkipCertificateCheck:$SkipCertificateCheck | Out-Null
        return $false
    }
    catch {
        if (-not ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound)) {
            throw
        }
    }

    # the index doesn't exist yet, so create it. if we know the date format,
    # tell elasticsearch up front instead of letting it guess. a wrong guess
    # silently turns the date column into plain text and breaks kibana's
    # time-based graphs later.
    $body = @{}
    if ($TimestampField -and $TimestampFormat) {
        $body = @{
            mappings = @{
                properties = @{
                    $TimestampField = @{ type = 'date'; format = $TimestampFormat }
                }
            }
        }
    }

    Invoke-ElkRequest -Uri "$ElasticBaseUri/$IndexName" -Method Put `
        -Headers $AuthHeaders -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' `
        -SkipCertificateCheck:$SkipCertificateCheck | Out-Null

    return $true
}


# VERIFICATION


# compares the columns we uploaded against the columns elasticsearch actually
# ended up with, and returns any that are missing
function Test-IndexColumnCoverage {
    param(
        [Parameter(Mandatory)][string]$ElasticBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [Parameter(Mandatory)][string]$IndexName,
        [Parameter(Mandatory)][string[]]$ExpectedFields,
        [switch]$SkipCertificateCheck
    )
    $resp = Invoke-ElkRequest -Uri "$ElasticBaseUri/$IndexName/_mapping" -Method Get `
        -Headers $AuthHeaders -SkipCertificateCheck:$SkipCertificateCheck

    $props = $resp.$IndexName.mappings.properties
    $mappedFields = @()
    if ($props) { $mappedFields = @($props.PSObject.Properties.Name) }

    # a column only shows up here once elasticsearch has seen a real value
    # for it, so a missing column usually just means every row was blank
    return @($ExpectedFields | Where-Object { $mappedFields -notcontains $_ })
}


# KIBANA SETUP


# makes sure kibana has a data view (its name for "which index to look at")
# pointing at our index, creating one if it doesn't already exist
function Confirm-KibanaDataView {
    param(
        [Parameter(Mandatory)][string]$KibanaBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [Parameter(Mandatory)][string]$IndexName,
        [string]$TimestampField,
        [switch]$SkipCertificateCheck
    )

    # newer kibana versions have a dedicated way to manage data views. older
    # versions don't have it and return a plain "not found" instead, so fall
    # back to the older method in that case.
    $useLegacyApi = $false
    $existing = $null
    try {
        $listResp = Invoke-ElkRequest -Uri "$KibanaBaseUri/api/data_views" -Method Get `
            -Headers $AuthHeaders -SkipCertificateCheck:$SkipCertificateCheck
        $existing = $listResp.data_view | Where-Object { $_.title -eq $IndexName } | Select-Object -First 1
    }
    catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound) {
            $useLegacyApi = $true
        }
        else {
            throw
        }
    }

    if ($useLegacyApi) {
        $findResp = Invoke-ElkRequest -Uri "$KibanaBaseUri/api/saved_objects/_find?type=index-pattern&per_page=1000" -Method Get `
            -Headers $AuthHeaders -SkipCertificateCheck:$SkipCertificateCheck
        $existingObj = $findResp.saved_objects | Where-Object { $_.attributes.title -eq $IndexName } | Select-Object -First 1
        if ($existingObj) {
            return @{ Id = $existingObj.id; Created = $false }
        }

        $legacyBody = @{ attributes = @{ title = $IndexName } }
        if ($TimestampField) { $legacyBody.attributes.timeFieldName = $TimestampField }

        $createHeaders = $AuthHeaders.Clone()
        $createHeaders['kbn-xsrf'] = 'true'

        $legacyCreateResp = Invoke-ElkRequest -Uri "$KibanaBaseUri/api/saved_objects/index-pattern" -Method Post `
            -Headers $createHeaders -Body ($legacyBody | ConvertTo-Json -Depth 5) -ContentType 'application/json' `
            -SkipCertificateCheck:$SkipCertificateCheck

        return @{ Id = $legacyCreateResp.id; Created = $true }
    }

    if ($existing) {
        return @{ Id = $existing.id; Created = $false }
    }

    $body = @{ data_view = @{ title = $IndexName } }
    if ($TimestampField) {
        $body.data_view.timeFieldName = $TimestampField
    }

    $createHeaders = $AuthHeaders.Clone()
    $createHeaders['kbn-xsrf'] = 'true'

    $createResp = Invoke-ElkRequest -Uri "$KibanaBaseUri/api/data_views/data_view" -Method Post `
        -Headers $createHeaders -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' `
        -SkipCertificateCheck:$SkipCertificateCheck

    return @{ Id = $createResp.data_view.id; Created = $true }
}

# makes sure a ready-to-open saved search exists in kibana for our index,
# creating one if it doesn't already exist
function Confirm-KibanaSavedSearch {
    param(
        [Parameter(Mandatory)][string]$KibanaBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [Parameter(Mandatory)][string]$IndexName,
        [Parameter(Mandatory)][string]$DataViewId,
        [string]$TimestampField,
        [switch]$SkipCertificateCheck
    )

    $title = "$IndexName (EvtxRelay)"

    $findResp = Invoke-ElkRequest -Uri "$KibanaBaseUri/api/saved_objects/_find?type=search&per_page=1000" `
        -Method Get -Headers $AuthHeaders -SkipCertificateCheck:$SkipCertificateCheck
    $existing = $findResp.saved_objects | Where-Object { $_.attributes.title -eq $title } | Select-Object -First 1
    if ($existing) {
        return @{ Id = $existing.id; Created = $false }
    }

    # sort order must be written as [direction, column name], the reverse of
    # what you'd expect. writing it the other way causes confusing errors.
    $sort = @()
    if ($TimestampField) {
        $sort = @(, @('desc', $TimestampField))
    }

    # the saved search must point at the data view using this specific
    # linking style, matching how kibana itself saves these.
    $searchSource = @{
        indexRefName = 'kibanaSavedObjectMeta.searchSourceJSON.index'
        query        = @{ query = ''; language = 'kuery' }
        filter       = @()
        sort         = $sort
    }

    $body = @{
        attributes = @{
            title                 = $title
            sort                  = $sort
            columns               = @('_source')
            kibanaSavedObjectMeta = @{
                searchSourceJSON = ($searchSource | ConvertTo-Json -Compress -Depth 5)
            }
        }
        references = @(
            @{
                id   = $DataViewId
                name = 'kibanaSavedObjectMeta.searchSourceJSON.index'
                type = 'index-pattern'
            }
        )
    }

    $createHeaders = $AuthHeaders.Clone()
    $createHeaders['kbn-xsrf'] = 'true'

    $createResp = Invoke-ElkRequest -Uri "$KibanaBaseUri/api/saved_objects/search" -Method Post `
        -Headers $createHeaders -Body ($body | ConvertTo-Json -Depth 6) -ContentType 'application/json' `
        -SkipCertificateCheck:$SkipCertificateCheck

    return @{ Id = $createResp.id; Created = $true }
}


# FIELD ALIAS MAPPING (-TOOL AUTO)


# loads .evtxrelay/field-aliases.json, creating it with the built-in default
# table on first use instead of blocking like config.json does, since there's
# no placeholder value here that only the user could fill in
function Get-EvtxRelayFieldAliasMap {
    param(
        [Parameter(Mandatory)][string]$ConfigDir,
        [Parameter(Mandatory)][string]$LogPath
    )
    $aliasPath = Join-Path $ConfigDir 'field-aliases.json'

    if (-not (Test-Path -LiteralPath $aliasPath)) {
        $defaults = [ordered]@{
            event_timestamp = @('Timestamp', 'timestamp', 'TimeCreated', 'Date and Time', 'DateTime', 'datetime', '@timestamp', 'Time')
            source_ip       = @('SourceIp', 'SourceIP', 'Source IP', 'src_ip', 'srcip', 'ClientIp', 'Client IP')
            dest_ip         = @('DestinationIp', 'DestIp', 'Destination IP', 'dst_ip', 'dstip', 'TargetIp', 'Target IP')
            hostname        = @('Computer', 'ComputerName', 'Hostname', 'Host', 'Host Name', 'Machine', 'MachineName')
            user_name       = @('User', 'UserName', 'User Name', 'TargetUserName', 'AccountName', 'Account Name')
            event_id        = @('EventID', 'EventId', 'Event ID', 'EventCode')
            process_name    = @('ProcessName', 'Process Name', 'Image', 'NewProcessName', 'ParentProcessName')
        }
        $defaults | ConvertTo-Json | Set-Content -LiteralPath $aliasPath
        Write-EvtxRelayLog -LogPath $LogPath -Message "No field alias table found. Created one with built-in defaults at '$aliasPath'. Edit it to add or change concepts."
    }

    try {
        $loaded = Get-Content -LiteralPath $aliasPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Field alias table at '$aliasPath' is corrupt or unreadable ($($_.Exception.Message)). Fix or delete the file, then run again; it will not be overwritten automatically."
    }

    $aliasMap = [ordered]@{}
    foreach ($prop in $loaded.PSObject.Properties) {
        $aliasMap[$prop.Name] = @($prop.Value)
    }
    return $aliasMap
}

# renames every sanitized column that matches a concept's candidate spellings
# to that concept's canonical name, so data from different unrecognized
# sources ends up under the same field names. exact-case match wins first, in
# table order, then a case-insensitive pass, the same precedence rule already
# used for timestamp detection on the four known tools
function Resolve-EvtxRelayFieldConcepts {
    param(
        [Parameter(Mandatory)]$HeaderMap,
        [Parameter(Mandatory)]$AliasMap,
        [Parameter(Mandatory)][string]$LogPath
    )

    $allFields = @($HeaderMap.Values)
    $claimedBy = @{}
    $matchedCount = 0

    foreach ($concept in $AliasMap.Keys) {
        $candidates = @($AliasMap[$concept])

        $matchedFields = New-Object System.Collections.Generic.List[string]
        foreach ($candidate in $candidates) {
            foreach ($field in $allFields) {
                if (-not $claimedBy.ContainsKey($field) -and ($field -ceq $candidate) -and ($matchedFields -notcontains $field)) {
                    $matchedFields.Add($field)
                }
            }
        }
        if ($matchedFields.Count -eq 0) {
            foreach ($candidate in $candidates) {
                foreach ($field in $allFields) {
                    if (-not $claimedBy.ContainsKey($field) -and ($field -eq $candidate) -and ($matchedFields -notcontains $field)) {
                        $matchedFields.Add($field)
                    }
                }
            }
        }

        # a candidate spelling that only matches a field another concept
        # already claimed means the two concepts collide on that name
        foreach ($candidate in $candidates) {
            foreach ($field in $allFields) {
                if ($claimedBy.ContainsKey($field) -and ($field -eq $candidate)) {
                    Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Concept '$concept' candidate '$candidate' also matches column '$field', already claimed by concept '$($claimedBy[$field])'. Column '$field' stays mapped to '$($claimedBy[$field])'."
                }
            }
        }

        if ($matchedFields.Count -eq 0) { continue }

        $winner = $matchedFields[0]
        $claimedBy[$winner] = $concept
        $matchedCount++

        if ($matchedFields.Count -gt 1) {
            $runnersUp = $matchedFields | Select-Object -Skip 1
            Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Concept '$concept' matched more than one column ($($matchedFields -join ', ')); using '$winner'. Column(s) $($runnersUp -join ', ') kept their own name(s). Tighten .evtxrelay/field-aliases.json if this isn't right."
        }
    }

    if ($matchedCount -eq 0) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message 'No columns in this file matched any concept in the field alias table; every column kept its own sanitized name.'
    }

    # renaming to a concept's canonical name can land two original columns on
    # the same final name (one of them may not even be renamed), which would
    # silently overwrite one column's data with the other's later on
    $finalNameOwner = @{}
    foreach ($originalName in @($HeaderMap.Keys)) {
        $sanitizedField = $HeaderMap[$originalName]
        $finalName = if ($claimedBy.ContainsKey($sanitizedField)) { $claimedBy[$sanitizedField] } else { $sanitizedField }
        if ($finalNameOwner.ContainsKey($finalName)) {
            throw "Concept rename collision: '$originalName' and '$($finalNameOwner[$finalName])' would both end up named '$finalName'. Rename one of the source columns, or edit .evtxrelay/field-aliases.json, before re-running."
        }
        $finalNameOwner[$finalName] = $originalName
    }

    foreach ($originalName in @($HeaderMap.Keys)) {
        $sanitizedField = $HeaderMap[$originalName]
        if ($claimedBy.ContainsKey($sanitizedField)) {
            $HeaderMap[$originalName] = $claimedBy[$sanitizedField]
        }
    }

    return $HeaderMap
}

# tests sample values from the resolved timestamp column against a curated
# list of common date formats and returns the elasticsearch mapping string
# for the first one that fits every sample, or $null if none do
function Resolve-EvtxRelayTimestampFormat {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$SampleValues,
        [Parameter(Mandatory)][array]$FormatCandidates
    )
    $samples = @($SampleValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 20)
    if ($samples.Count -eq 0) { return $null }

    foreach ($candidate in $FormatCandidates) {
        $allParse = $true
        foreach ($sample in $samples) {
            $parsed = [datetime]::MinValue
            $ok = [datetime]::TryParseExact(
                $sample, $candidate.DotNetFormat, [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None, [ref]$parsed)
            if (-not $ok) { $allParse = $false; break }
        }
        if ($allParse) { return $candidate.EsFormat }
    }
    return $null
}

# last-resort fallback for -tool auto when field-aliases.json matched nothing at all: sends
# a raw sample of the file to elasticsearch's own structure finder and asks it to guess the
# timestamp column and its date format. never throws; any failure just means no fallback was
# found and the caller proceeds exactly like it already does when nothing can be detected
function Resolve-EvtxRelayTimestampViaFindStructure {
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)]$HeaderMap,
        [Parameter(Mandatory)][string]$ElasticBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory)][string]$LogPath
    )

    # a sample of up to 1000 raw lines (header plus up to 999 data rows) is plenty for the
    # structure finder to work with, and keeps a huge csv from turning into a huge request.
    # shorter files just send everything, since get-content stops at end of file on its own
    $sampleLines = @(Get-Content -LiteralPath $File -TotalCount 1000)
    $sampleBody = $sampleLines -join "`n"

    try {
        $response = Invoke-ElkRequest -Uri "$ElasticBaseUri/_ml/find_file_structure" -Method Post `
            -Headers $AuthHeaders -Body $sampleBody -ContentType 'application/json' `
            -SkipCertificateCheck:$SkipCertificateCheck
    }
    catch {
        $detail = $_.ErrorDetails.Message
        $msg = if ($detail) { "$($_.Exception.Message): $detail" } else { $_.Exception.Message }
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Elasticsearch's structure finder could not analyze this file ($msg); continuing without it."
        return $null
    }

    $timestampField = $response.timestamp_field
    if (-not $timestampField -or -not $HeaderMap.Contains($timestampField)) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Elasticsearch's structure finder did not find a usable timestamp column in this file; continuing without it."
        return $null
    }

    $esFormat = $response.mappings.properties.$timestampField.format
    if (-not $esFormat) {
        # java_timestamp_formats can hold special ingest-processor names instead of a real
        # mapping format string. only translate the ones with a known mapping-legal equivalent;
        # anything else (a raw java.time pattern, or a name like tai64n with no equivalent) isn't
        # safe to hand to elasticsearch's date mapping, so it's treated as not found
        $specialFormatMap = @{
            ISO8601 = 'strict_date_optional_time'
            UNIX_MS = 'epoch_millis'
            UNIX    = 'epoch_second'
        }
        $guessedFormat = $response.java_timestamp_formats | Select-Object -First 1
        if ($guessedFormat -and $specialFormatMap.Contains($guessedFormat)) {
            $esFormat = $specialFormatMap[$guessedFormat]
        }
    }
    if (-not $esFormat) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Elasticsearch's structure finder found column '$timestampField' but no usable date format for it; continuing without it."
        return $null
    }

    return [PSCustomObject]@{
        OriginalColumnName = $timestampField
        EsFormat            = "$esFormat||strict_date_optional_time||epoch_millis"
    }
}


# PER-FILE PROCESSING


# picks which sanitized column to use as the date/time field, given a
# priority list of candidate names and an optional manual override
function Resolve-EvtxRelayTimestampField {
    param(
        [Parameter(Mandatory)][string[]]$SanitizedFields,
        [string[]]$Candidates = @(),
        [string]$Override
    )
    if ($Override) { return $Override }
    # check for an exact-case match first, in priority order, before falling back to a
    # case-insensitive one. otherwise a lower-priority candidate that only matches by case
    # (like 'DateTime' matching a real column named 'datetime') could win over the real
    # match further down the list, and we'd return a field name that doesn't actually exist.
    foreach ($candidate in $Candidates) {
        foreach ($field in $SanitizedFields) {
            if ($field -ceq $candidate) { return $field }
        }
    }
    foreach ($candidate in $Candidates) {
        foreach ($field in $SanitizedFields) {
            if ($field -eq $candidate) { return $field }
        }
    }
    return $null
}

# works out a short category name for each apt-hunter csv by stripping
# whatever filename prefix every file in the folder has in common (apt-hunter
# lets you pick your own output name per run, so this can't be hardcoded)
function Get-AptHunterCategoryMap {
    param(
        [Parameter(Mandatory)][string[]]$CsvPaths
    )

    $baseNames = @($CsvPaths | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) })

    $prefixLength = $baseNames[0].Length
    for ($i = 1; $i -lt $baseNames.Count; $i++) {
        $maxCompare = [Math]::Min($prefixLength, $baseNames[$i].Length)
        $j = 0
        while ($j -lt $maxCompare -and $baseNames[0][$j] -ceq $baseNames[$i][$j]) { $j++ }
        $prefixLength = $j
    }
    $commonPrefix = $baseNames[0].Substring(0, $prefixLength).TrimEnd('_')

    $map = [ordered]@{}
    $seen = @{}
    for ($i = 0; $i -lt $CsvPaths.Count; $i++) {
        $remainder = $baseNames[$i]
        if ($commonPrefix -and $baseNames.Count -gt 1) {
            $remainder = $baseNames[$i].Substring($commonPrefix.Length).TrimStart('_')
        }
        if (-not $remainder) { $remainder = $baseNames[$i] }
        $category = $remainder.ToLowerInvariant() -replace '[\s-]+', '_'

        if ($seen.ContainsKey($category)) {
            throw "Two APT-Hunter csv files both map to category '$category': '$($seen[$category])' and '$($CsvPaths[$i])'. Rename one of the source files before re-running."
        }
        $seen[$category] = $CsvPaths[$i]
        $map[$CsvPaths[$i]] = $category
    }

    return $map
}

# uploads one already-loaded csv's rows into elasticsearch, creates the
# index and kibana data view/saved search if needed, and returns a
# summary of what happened
function Invoke-EvtxRelayFileUpload {
    param(
        [Parameter(Mandatory)][array]$Records,
        [Parameter(Mandatory)]$HeaderMap,
        [Parameter(Mandatory)][string[]]$SanitizedFields,
        [Parameter(Mandatory)][string]$IndexName,
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$SubModule,
        [switch]$Exact,
        [string]$TimestampField,
        [string]$TimestampFormat,
        [Parameter(Mandatory)][string]$ElasticBaseUri,
        [Parameter(Mandatory)][string]$KibanaBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [Parameter(Mandatory)][int]$BatchSize,
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory)][string]$LogPath
    )

    $IndexName = Resolve-EvtxRelayAvailableIndexName -ElasticBaseUri $ElasticBaseUri -AuthHeaders $AuthHeaders `
        -Tool $Tool -SubModule $SubModule -IndexName $IndexName -Exact:$Exact `
        -SkipCertificateCheck:$SkipCertificateCheck -LogPath $LogPath

    $indexCreated = Confirm-IndexWithTimestampMapping -ElasticBaseUri $ElasticBaseUri -AuthHeaders $AuthHeaders `
        -IndexName $IndexName -TimestampField $TimestampField -TimestampFormat $TimestampFormat `
        -SkipCertificateCheck:$SkipCertificateCheck
    if ($indexCreated -and $TimestampField -and $TimestampFormat) {
        Write-EvtxRelayLog -LogPath $LogPath -Message "Created index '$IndexName' with an explicit date mapping for '$TimestampField'."
    }

    # UPLOAD THE DATA IN BATCHES

    $totalRows = $Records.Count
    $bulkErrors = New-Object System.Collections.Generic.List[object]

    for ($start = 0; $start -lt $totalRows; $start += $BatchSize) {
        $end = [Math]::Min($start + $BatchSize, $totalRows) - 1
        $batch = $Records[$start..$end]
        $sanitizedBatch = @(foreach ($r in $batch) { ConvertTo-SanitizedRecord -Record $r -HeaderMap $HeaderMap })
        $bulkBody = ConvertTo-BulkBody -IndexName $IndexName -Records $sanitizedBatch

        $response = Invoke-ElkRequest -Uri "$ElasticBaseUri/$IndexName/_bulk" -Method Post `
            -Headers $AuthHeaders -Body $bulkBody -ContentType 'application/x-ndjson' `
            -SkipCertificateCheck:$SkipCertificateCheck

        if ($response.errors) {
            for ($j = 0; $j -lt $response.items.Count; $j++) {
                $item = $response.items[$j].index
                if ($item.error) {
                    # elasticsearch's main error message is often vague (like
                    # "failed to parse"); the real, useful detail is usually
                    # buried in the nested "caused by" messages underneath it,
                    # so collect all of them
                    $detailParts = New-Object System.Collections.Generic.List[string]
                    $errNode = $item.error
                    while ($errNode) {
                        $detailParts.Add("[$($errNode.type)] $($errNode.reason)")
                        $errNode = $errNode.caused_by
                    }
                    $bulkErrors.Add([PSCustomObject]@{
                        Row    = $start + $j + 1
                        Type   = $item.error.type
                        Reason = ($detailParts -join ' <- caused by: ')
                    })
                }
            }
        }

        Write-EvtxRelayLog -LogPath $LogPath -Message "Indexed rows $($start + 1)-$($end + 1) of $totalRows into '$IndexName'."
    }

    $rowsIndexed = $totalRows - $bulkErrors.Count
    if ($bulkErrors.Count -gt 0) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "$($bulkErrors.Count) row(s) failed to index:"
        foreach ($e in $bulkErrors) {
            Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "  Row $($e.Row): $($e.Reason)"
        }
    }

    # DOUBLE CHECK NOTHING WAS LOST

    Write-EvtxRelayLog -LogPath $LogPath -Message 'Verifying column coverage against index mapping...'
    $missingColumns = Test-IndexColumnCoverage -ElasticBaseUri $ElasticBaseUri -AuthHeaders $AuthHeaders `
        -IndexName $IndexName -ExpectedFields $SanitizedFields -SkipCertificateCheck:$SkipCertificateCheck

    if ($missingColumns.Count -gt 0) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Columns missing from mapping (all values may have been null/empty): $($missingColumns -join ', ')"
    }
    else {
        Write-EvtxRelayLog -LogPath $LogPath -Message "All $($SanitizedFields.Count) columns present in the index mapping. No column loss detected."
    }

    # SET UP KIBANA

    Write-EvtxRelayLog -LogPath $LogPath -Message "Ensuring Kibana Data View for '$IndexName'..."
    $dataView = Confirm-KibanaDataView -KibanaBaseUri $KibanaBaseUri -AuthHeaders $AuthHeaders `
        -IndexName $IndexName -TimestampField $TimestampField -SkipCertificateCheck:$SkipCertificateCheck

    Write-EvtxRelayLog -LogPath $LogPath -Message "Ensuring Kibana saved search for '$IndexName'..."
    $savedSearch = Confirm-KibanaSavedSearch -KibanaBaseUri $KibanaBaseUri -AuthHeaders $AuthHeaders `
        -IndexName $IndexName -DataViewId $dataView.Id -TimestampField $TimestampField `
        -SkipCertificateCheck:$SkipCertificateCheck

    # PRINT A SUMMARY

    Write-EvtxRelayLog -LogPath $LogPath -Message '=== Summary ==='
    Write-EvtxRelayLog -LogPath $LogPath -Message "Rows indexed:        $rowsIndexed / $totalRows"
    Write-EvtxRelayLog -LogPath $LogPath -Message "Column loss:         $(if ($missingColumns.Count -gt 0) { "$($missingColumns.Count) column(s) missing" } else { 'none' })"
    Write-EvtxRelayLog -LogPath $LogPath -Message "Kibana Data View:    $(if ($dataView.Created) { 'created' } else { 'already existed' })"
    Write-EvtxRelayLog -LogPath $LogPath -Message "Kibana saved search: $(if ($savedSearch.Created) { 'created' } else { 'already existed' })"

    return [PSCustomObject]@{
        IndexName          = $IndexName
        TotalRows          = $totalRows
        RowsIndexed        = $rowsIndexed
        MissingColumns      = $missingColumns
        DataViewCreated    = $dataView.Created
        SavedSearchCreated = $savedSearch.Created
    }
}


# LOG FILE SUPPORT (-TOOL LOG)


# figures out how to turn -tool log's raw lines into dated events: sends a sample of the file to
# elasticsearch's own structure finder and, if it finds a usable per-line timestamp pattern, returns
# the ingest pipeline processors needed to extract it. throws only when the file clearly isn't
# log-shaped (e.g. it's really a csv); every other failure is soft and just means the caller indexes
# lines untimed
function Resolve-EvtxRelayLogStructure {
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][string]$ElasticBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory)][string]$LogPath
    )

    # same sampling convention as -tool auto's structure-finder fallback: up to 1000 raw lines is
    # plenty for confident detection, and keeps a huge log file from turning into a huge request
    $sampleLines = @(Get-Content -LiteralPath $File -TotalCount 1000)
    $sampleBody = $sampleLines -join "`n"

    try {
        $response = Invoke-ElkRequest -Uri "$ElasticBaseUri/_ml/find_file_structure" -Method Post `
            -Headers $AuthHeaders -Body $sampleBody -ContentType 'application/json' `
            -SkipCertificateCheck:$SkipCertificateCheck
    }
    catch {
        $detail = $_.ErrorDetails.Message
        $msg = if ($detail) { "$($_.Exception.Message): $detail" } else { $_.Exception.Message }
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Elasticsearch's structure finder could not analyze this file ($msg); every line will be indexed as a raw message with no timestamp."
        return $null
    }

    if ($response.format -ne 'semi_structured_text') {
        throw "This file doesn't look like an unstructured log to Elasticsearch (it detected '$($response.format)' instead). If it's actually delimited/tabular data, re-run with -Tool auto instead."
    }

    $timestampField = $response.timestamp_field
    if (-not $timestampField -or -not $response.ingest_pipeline) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Elasticsearch could not find a reliable per-line timestamp in this file; every line will be indexed as a raw message with no timestamp."
        return $null
    }

    $coveredCount = $response.field_stats.$timestampField.count
    if ($coveredCount -and $response.num_messages_analyzed -and $coveredCount -lt $response.num_messages_analyzed) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Elasticsearch's detected timestamp pattern only matched $coveredCount of $($response.num_messages_analyzed) sampled lines; some lines may end up indexed without a timestamp."
    }

    # field names this tool always sets itself; a real extracted field landing on one of these
    # would silently overwrite it, so field-extraction tiers below check candidate field names
    # against this list before building a pipeline, same defensive pattern as -folder mode's
    # source_file guard (resolve-evtxrelaycsvfiledetection)
    $reservedFieldNames = @('message', '@timestamp', 'source_file', 'grok_parse_failed')

    # a bare reference to one of elasticsearch's own named patterns (like %{combinedapachelog})
    # means the structure finder recognized a known format, not just guessed one from this one
    # sample. that pattern's captures are well-tested and worth trusting; anything else is a
    # pattern elasticsearch synthesized on the fly for this specific file, which (per a live test
    # during design) can produce meaningless capture names and even a wrong timestamp for
    # key=value-style text, so it's only ever trusted for the timestamp, never for other fields
    $isTrustedPattern = $response.grok_pattern -match '^%\{[A-Z_]+\}$'

    if ($isTrustedPattern) {
        # keep every processor the trusted pattern defines, including 'convert': these are the
        # pattern's own well-tested field definitions, not incidental captures, and elasticsearch's
        # own response already sets ignore_missing on every convert step, so a field that's simply
        # absent on some lines doesn't trip anything
        $keptProcessors = @($response.ingest_pipeline.processors | Where-Object {
            (@($_.PSObject.Properties.Name)[0]) -in @('grok', 'date', 'remove', 'convert')
        })

        $collisionField = @($response.mappings.properties.PSObject.Properties.Name | Where-Object { $_ -cin @('source_file', 'grok_parse_failed') })
        if ($collisionField.Count -gt 0) {
            throw "Elasticsearch's detected pattern for this file extracts a field called '$($collisionField[0])', which collides with a field EvtxRelay sets itself. Rename that field's source data before re-running, or use -Tool auto if this is really tabular data."
        }
    }
    else {
        # only keep the processors that exist to find and set the timestamp. the structure finder's
        # auto-derived grok pattern sometimes also captures an incidental field (e.g. a pid) and adds a
        # 'convert' processor for it; that processor throwing on a line where the field isn't the type it
        # expects would trip this pipeline's on_failure handler and mislabel a line whose timestamp parsed
        # just fine as a parse failure, so anything other than grok/date/remove is dropped
        $keptProcessors = @($response.ingest_pipeline.processors | Where-Object {
            # PowerShell collapses a single-property object's .Name from an array to a plain
            # scalar string, so indexing it directly with [0] would return the name's first
            # character instead of the name itself. wrapping in @(...) forces array context first
            (@($_.PSObject.Properties.Name)[0]) -in @('grok', 'date', 'remove')
        })
    }

    # elasticsearch's own date processor asks for a per-document 'event.timezone' field to resolve
    # local-time logs (visible in the raw response as timezone: "{{ event.timezone }}"), which this
    # tool's documents never set, so that reference would never resolve and every line's date parsing
    # would fail, not just the ones that genuinely don't match. most log formats here (syslog-style)
    # don't carry timezone info in the text anyway, so drop it and let the date processor fall back to
    # elasticsearch's own default (utc) instead of failing outright
    foreach ($proc in $keptProcessors) {
        $procType = @($proc.PSObject.Properties.Name)[0]
        if ($procType -eq 'date' -and $proc.date.PSObject.Properties.Name -contains 'timezone') {
            $proc.date.PSObject.Properties.Remove('timezone')
            Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Elasticsearch's detected date format needs a per-line timezone this file doesn't provide; timestamps will be parsed as UTC."
        }
    }

    # if filtering above dropped every processor that would have set the timestamp, there's nothing
    # left to write @timestamp, so fall back to the same untimed path as a structure-finder failure
    # instead of creating a pipeline and a date-mapped index that never actually get a timestamp
    $hasDate = @($keptProcessors | Where-Object { @($_.PSObject.Properties.Name)[0] -eq 'date' }).Count -gt 0
    if (-not $hasDate) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Elasticsearch's suggested pipeline has no usable timestamp step for this file; every line will be indexed as a raw message with no timestamp."
        return $null
    }

    return [PSCustomObject]@{
        Processors        = $keptProcessors
        TimestampFieldRaw = $timestampField
    }
}

# uploads a -tool log file: one bulk document per line, with a message field and, when
# resolve-evtxrelaylogstructure found a usable pattern, an elasticsearch-parsed @timestamp field
function Invoke-EvtxRelayLogUpload {
    param(
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][string]$IndexName,
        [Parameter(Mandatory)][string]$Tool,
        [switch]$Exact,
        $StructureResult,
        [Parameter(Mandatory)][string]$ElasticBaseUri,
        [Parameter(Mandatory)][string]$KibanaBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [Parameter(Mandatory)][int]$BatchSize,
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory)][string]$LogPath
    )

    $IndexName = Resolve-EvtxRelayAvailableIndexName -ElasticBaseUri $ElasticBaseUri -AuthHeaders $AuthHeaders `
        -Tool $Tool -SubModule 'events' -IndexName $IndexName -Exact:$Exact `
        -SkipCertificateCheck:$SkipCertificateCheck -LogPath $LogPath

    # pipelines hold no data, so there's no need to check for an existing one first the way index
    # creation does; a plain put always either creates it fresh or harmlessly overwrites it
    $pipelineName = $null
    if ($StructureResult) {
        $pipelineName = "$IndexName-pipeline"
        $pipelineBody = @{
            description = "EvtxRelay log pipeline for '$IndexName'"
            processors  = $StructureResult.Processors
            on_failure  = @(
                @{ set = @{ field = 'grok_parse_failed'; value = $true } }
            )
        }
        Invoke-ElkRequest -Uri "$ElasticBaseUri/_ingest/pipeline/$pipelineName" -Method Put `
            -Headers $AuthHeaders -Body ($pipelineBody | ConvertTo-Json -Depth 10) -ContentType 'application/json' `
            -SkipCertificateCheck:$SkipCertificateCheck | Out-Null
        Write-EvtxRelayLog -LogPath $LogPath -Message "Created ingest pipeline '$pipelineName' (detected via column '$($StructureResult.TimestampFieldRaw)')."
    }

    # elasticsearch's date processor always writes @timestamp in this exact shape regardless of
    # what format the original text was in, so unlike -tool auto's structure-finder fallback there's
    # no per-file format to translate here, just this one fixed constant
    $timestampField = if ($StructureResult) { '@timestamp' } else { $null }
    $timestampFormat = if ($StructureResult) { 'strict_date_optional_time||epoch_millis' } else { $null }

    $indexCreated = Confirm-IndexWithTimestampMapping -ElasticBaseUri $ElasticBaseUri -AuthHeaders $AuthHeaders `
        -IndexName $IndexName -TimestampField $timestampField -TimestampFormat $timestampFormat `
        -SkipCertificateCheck:$SkipCertificateCheck
    if ($indexCreated -and $timestampField) {
        Write-EvtxRelayLog -LogPath $LogPath -Message "Created index '$IndexName' with an explicit date mapping for '$timestampField'."
    }

    # UPLOAD THE DATA IN BATCHES

    $totalLines = $Lines.Count
    $bulkErrors = New-Object System.Collections.Generic.List[object]
    $bulkUri = "$ElasticBaseUri/$IndexName/_bulk"
    if ($pipelineName) { $bulkUri += "?pipeline=$pipelineName" }

    for ($start = 0; $start -lt $totalLines; $start += $BatchSize) {
        $end = [Math]::Min($start + $BatchSize, $totalLines) - 1
        $batch = @(foreach ($line in $Lines[$start..$end]) { [PSCustomObject]@{ message = $line } })
        $bulkBody = ConvertTo-BulkBody -IndexName $IndexName -Records $batch

        $response = Invoke-ElkRequest -Uri $bulkUri -Method Post `
            -Headers $AuthHeaders -Body $bulkBody -ContentType 'application/x-ndjson' `
            -SkipCertificateCheck:$SkipCertificateCheck

        if ($response.errors) {
            for ($j = 0; $j -lt $response.items.Count; $j++) {
                $item = $response.items[$j].index
                if ($item.error) {
                    $detailParts = New-Object System.Collections.Generic.List[string]
                    $errNode = $item.error
                    while ($errNode) {
                        $detailParts.Add("[$($errNode.type)] $($errNode.reason)")
                        $errNode = $errNode.caused_by
                    }
                    $bulkErrors.Add([PSCustomObject]@{
                        Row    = $start + $j + 1
                        Type   = $item.error.type
                        Reason = ($detailParts -join ' <- caused by: ')
                    })
                }
            }
        }

        Write-EvtxRelayLog -LogPath $LogPath -Message "Indexed lines $($start + 1)-$($end + 1) of $totalLines into '$IndexName'."
    }

    $rowsIndexed = $totalLines - $bulkErrors.Count
    if ($bulkErrors.Count -gt 0) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "$($bulkErrors.Count) line(s) failed to index:"
        foreach ($e in $bulkErrors) {
            Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "  Line $($e.Row): $($e.Reason)"
        }
    }

    # SET UP KIBANA

    Write-EvtxRelayLog -LogPath $LogPath -Message "Ensuring Kibana Data View for '$IndexName'..."
    $dataView = Confirm-KibanaDataView -KibanaBaseUri $KibanaBaseUri -AuthHeaders $AuthHeaders `
        -IndexName $IndexName -TimestampField $timestampField -SkipCertificateCheck:$SkipCertificateCheck

    Write-EvtxRelayLog -LogPath $LogPath -Message "Ensuring Kibana saved search for '$IndexName'..."
    $savedSearch = Confirm-KibanaSavedSearch -KibanaBaseUri $KibanaBaseUri -AuthHeaders $AuthHeaders `
        -IndexName $IndexName -DataViewId $dataView.Id -TimestampField $timestampField `
        -SkipCertificateCheck:$SkipCertificateCheck

    # lines the pipeline's on_failure handler tagged never get an @timestamp, so they're invisible in
    # the time-filtered saved search; surface the count here since it's the only place that shows them
    $unparsedCount = $null
    if ($pipelineName) {
        $countResponse = Invoke-ElkRequest -Uri "$ElasticBaseUri/$IndexName/_count?q=grok_parse_failed:true" -Method Get `
            -Headers $AuthHeaders -SkipCertificateCheck:$SkipCertificateCheck
        $unparsedCount = $countResponse.count
    }

    # PRINT A SUMMARY

    Write-EvtxRelayLog -LogPath $LogPath -Message '=== Summary ==='
    Write-EvtxRelayLog -LogPath $LogPath -Message "Lines indexed:       $rowsIndexed / $totalLines"
    Write-EvtxRelayLog -LogPath $LogPath -Message "Timestamp field:     $(if ($timestampField) { $timestampField } else { 'none (uploaded untimed)' })"
    if ($null -ne $unparsedCount) {
        Write-EvtxRelayLog -LogPath $LogPath -Message "Lines not parsed:    $unparsedCount / $totalLines (tagged grok_parse_failed, no timestamp)"
    }
    Write-EvtxRelayLog -LogPath $LogPath -Message "Kibana Data View:    $(if ($dataView.Created) { 'created' } else { 'already existed' })"
    Write-EvtxRelayLog -LogPath $LogPath -Message "Kibana saved search: $(if ($savedSearch.Created) { 'created' } else { 'already existed' })"

    return [PSCustomObject]@{
        IndexName          = $IndexName
        TotalLines         = $totalLines
        RowsIndexed        = $rowsIndexed
        DataViewCreated    = $dataView.Created
        SavedSearchCreated = $savedSearch.Created
    }
}


# FOLDER BATCH SUPPORT (-TOOL AUTO / -TOOL LOG)


# runs one -tool auto csv file through the same detection a single-file run would do (header
# sanitizing, field-alias concept mapping, structure-finder fallback, per-file date format
# detection), without touching the index or uploading anything. folder mode calls this once per
# file so every file can be detected independently before the shared index is created
function Resolve-EvtxRelayCsvFileDetection {
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)]$AliasMap,
        [Parameter(Mandatory)][array]$AutoTimestampFormatCandidates,
        [string]$Override,
        [Parameter(Mandatory)][string]$ElasticBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory)][string]$LogPath
    )

    $records = @(Import-Csv -LiteralPath $File -Encoding UTF8)
    if ($records.Count -eq 0) {
        throw "No data rows found in '$File'."
    }

    $originalHeaders = @($records[0].PSObject.Properties.Name)
    $headerMap = Get-SanitizedHeaderMap -Headers $originalHeaders
    $headerMap = Resolve-EvtxRelayFieldConcepts -HeaderMap $headerMap -AliasMap $AliasMap -LogPath $LogPath
    $sanitizedFields = @($headerMap.Values)
    Write-EvtxRelayLog -LogPath $LogPath -Message "Detected $($sanitizedFields.Count) columns: $($sanitizedFields -join ', ')"

    $resolvedTimestampField = Resolve-EvtxRelayTimestampField -SanitizedFields $sanitizedFields `
        -Candidates @('event_timestamp') -Override $Override

    # only worth asking elasticsearch to guess when nothing already found a timestamp column,
    # same rule the single-file -tool auto path uses
    $structureFinderResult = $null
    if (-not $resolvedTimestampField) {
        $structureFinderResult = Resolve-EvtxRelayTimestampViaFindStructure -File $File -HeaderMap $headerMap `
            -ElasticBaseUri $ElasticBaseUri -AuthHeaders $AuthHeaders -SkipCertificateCheck:$SkipCertificateCheck -LogPath $LogPath
        if ($structureFinderResult) {
            $existingOwner = @($headerMap.Keys | Where-Object { $headerMap[$_] -eq 'event_timestamp' })
            if ($existingOwner.Count -gt 0) {
                throw "Structure finder collision: '$($structureFinderResult.OriginalColumnName)' and '$($existingOwner[0])' would both end up named 'event_timestamp'. Rename one of the source columns, or edit .evtxrelay/field-aliases.json, before re-running."
            }
            $headerMap[$structureFinderResult.OriginalColumnName] = 'event_timestamp'
            $sanitizedFields = @($headerMap.Values)
            $resolvedTimestampField = 'event_timestamp'
        }
    }

    $timestampFormat = $null
    if ($resolvedTimestampField) {
        Write-EvtxRelayLog -LogPath $LogPath -Message "Using '$resolvedTimestampField' as the timestamp field for sorting."
        if ($structureFinderResult) {
            $timestampFormat = $structureFinderResult.EsFormat
            Write-EvtxRelayLog -LogPath $LogPath -Message "Elasticsearch's structure finder detected '$($structureFinderResult.OriginalColumnName)' as the timestamp column, using format $($structureFinderResult.EsFormat)."
        }
        # a format is only worth detecting from sample values for the alias table's own
        # event_timestamp concept. a manual -timestampfield override could name any column, and
        # there's no reliable way to guess a format for an arbitrary one
        elseif ($resolvedTimestampField -eq 'event_timestamp') {
            $originalTimestampColumn = @($headerMap.Keys | Where-Object { $headerMap[$_] -eq 'event_timestamp' })[0]
            $sampleValues = @($records | Select-Object -ExpandProperty $originalTimestampColumn)
            $timestampFormat = Resolve-EvtxRelayTimestampFormat -SampleValues $sampleValues -FormatCandidates $AutoTimestampFormatCandidates
            if ($timestampFormat) {
                Write-EvtxRelayLog -LogPath $LogPath -Message "Detected date format for 'event_timestamp': $timestampFormat"
            }
            else {
                Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Could not confidently detect a date format for 'event_timestamp' from this file's sample values; its rows will rely on whatever date mapping the shared index ends up with, if any."
            }
        }
    }
    else {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Could not auto-detect a timestamp column in this file; its rows will not be time-sorted."
    }

    if ($sanitizedFields -contains 'source_file') {
        throw "Column 'source_file' collides with the field folder mode adds automatically to tag each row's source file. Rename the source column before re-running with -Folder."
    }

    return [PSCustomObject]@{
        HeaderMap       = $headerMap
        SanitizedFields = $sanitizedFields
        TimestampField  = $resolvedTimestampField
        TimestampFormat = $timestampFormat
    }
}

# resolves and creates the one shared index a folder batch run uses, same as
# resolve-evtxrelayavailableindexname + confirm-indexwithtimestampmapping already do for a single
# file, just factored out so folder mode can call it once instead of once per file
function Resolve-EvtxRelayBatchIndexSetup {
    param(
        [Parameter(Mandatory)][string]$ElasticBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$IndexName,
        [switch]$Exact,
        [string]$TimestampField,
        [string]$TimestampFormat,
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory)][string]$LogPath
    )

    $resolvedIndexName = Resolve-EvtxRelayAvailableIndexName -ElasticBaseUri $ElasticBaseUri -AuthHeaders $AuthHeaders `
        -Tool $Tool -SubModule 'events' -IndexName $IndexName -Exact:$Exact `
        -SkipCertificateCheck:$SkipCertificateCheck -LogPath $LogPath

    $indexCreated = Confirm-IndexWithTimestampMapping -ElasticBaseUri $ElasticBaseUri -AuthHeaders $AuthHeaders `
        -IndexName $resolvedIndexName -TimestampField $TimestampField -TimestampFormat $TimestampFormat `
        -SkipCertificateCheck:$SkipCertificateCheck
    if ($indexCreated -and $TimestampField -and $TimestampFormat) {
        Write-EvtxRelayLog -LogPath $LogPath -Message "Created index '$resolvedIndexName' with an explicit date mapping for '$TimestampField'."
    }

    return [PSCustomObject]@{ IndexName = $resolvedIndexName; IndexCreated = $indexCreated }
}

# uploads one already-detected csv file's rows into a shared index that folder mode already
# created, tagging every row with which file it came from
function Invoke-EvtxRelayCsvBatchUpload {
    param(
        [Parameter(Mandatory)][array]$Records,
        [Parameter(Mandatory)]$HeaderMap,
        [Parameter(Mandatory)][string[]]$SanitizedFields,
        [Parameter(Mandatory)][string]$SourceFile,
        [Parameter(Mandatory)][string]$IndexName,
        [Parameter(Mandatory)][string]$ElasticBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [Parameter(Mandatory)][int]$BatchSize,
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory)][string]$LogPath
    )

    $totalRows = $Records.Count
    $bulkErrors = New-Object System.Collections.Generic.List[object]

    for ($start = 0; $start -lt $totalRows; $start += $BatchSize) {
        $end = [Math]::Min($start + $BatchSize, $totalRows) - 1
        $batch = $Records[$start..$end]
        $sanitizedBatch = @(foreach ($r in $batch) { ConvertTo-SanitizedRecord -Record $r -HeaderMap $HeaderMap -SourceFile $SourceFile })
        $bulkBody = ConvertTo-BulkBody -IndexName $IndexName -Records $sanitizedBatch

        $response = Invoke-ElkRequest -Uri "$ElasticBaseUri/$IndexName/_bulk" -Method Post `
            -Headers $AuthHeaders -Body $bulkBody -ContentType 'application/x-ndjson' `
            -SkipCertificateCheck:$SkipCertificateCheck

        if ($response.errors) {
            for ($j = 0; $j -lt $response.items.Count; $j++) {
                $item = $response.items[$j].index
                if ($item.error) {
                    $detailParts = New-Object System.Collections.Generic.List[string]
                    $errNode = $item.error
                    while ($errNode) {
                        $detailParts.Add("[$($errNode.type)] $($errNode.reason)")
                        $errNode = $errNode.caused_by
                    }
                    $bulkErrors.Add([PSCustomObject]@{
                        Row    = $start + $j + 1
                        Type   = $item.error.type
                        Reason = ($detailParts -join ' <- caused by: ')
                    })
                }
            }
        }

        Write-EvtxRelayLog -LogPath $LogPath -Message "Indexed rows $($start + 1)-$($end + 1) of $totalRows from '$SourceFile' into '$IndexName'."
    }

    $rowsIndexed = $totalRows - $bulkErrors.Count
    if ($bulkErrors.Count -gt 0) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "$($bulkErrors.Count) row(s) from '$SourceFile' failed to index:"
        foreach ($e in $bulkErrors) {
            Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "  Row $($e.Row): $($e.Reason)"
        }
    }

    Write-EvtxRelayLog -LogPath $LogPath -Message "Verifying column coverage for '$SourceFile' against the shared index mapping..."
    $missingColumns = Test-IndexColumnCoverage -ElasticBaseUri $ElasticBaseUri -AuthHeaders $AuthHeaders `
        -IndexName $IndexName -ExpectedFields $SanitizedFields -SkipCertificateCheck:$SkipCertificateCheck
    if ($missingColumns.Count -gt 0) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Columns from '$SourceFile' missing from the mapping (all its values may have been null/empty, or another file just hasn't populated them yet): $($missingColumns -join ', ')"
    }

    return [PSCustomObject]@{ TotalRows = $totalRows; RowsIndexed = $rowsIndexed; MissingColumns = $missingColumns }
}

# uploads one already-detected log file's lines into folder mode's shared index, tagging each line with its source file
function Invoke-EvtxRelayLogBatchUpload {
    param(
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][string]$SourceFile,
        [Parameter(Mandatory)][string]$IndexName,
        $StructureResult,
        [Parameter(Mandatory)][string]$ElasticBaseUri,
        [Parameter(Mandatory)][hashtable]$AuthHeaders,
        [Parameter(Mandatory)][int]$BatchSize,
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory)][string]$LogPath
    )

    # each file gets its own pipeline, since a bulk request picks its pipeline per call, not per index
    $pipelineName = $null
    if ($StructureResult) {
        # slugs the whole filename, not just its base name, so "auth.log" and "auth.log.1"
        # (get-filenamewithoutextension would strip only the last extension, turning those into
        # the ambiguous "auth" and "auth.log") get distinct, recognizable pipeline names
        $fileSlug = ($SourceFile -replace '[^a-zA-Z0-9]+', '-').ToLowerInvariant().Trim('-')
        $pipelineName = "$IndexName-$fileSlug-pipeline"
        $pipelineBody = @{
            description = "EvtxRelay log pipeline for '$IndexName' (source file '$SourceFile')"
            processors  = $StructureResult.Processors
            on_failure  = @(
                @{ set = @{ field = 'grok_parse_failed'; value = $true } }
            )
        }
        Invoke-ElkRequest -Uri "$ElasticBaseUri/_ingest/pipeline/$pipelineName" -Method Put `
            -Headers $AuthHeaders -Body ($pipelineBody | ConvertTo-Json -Depth 10) -ContentType 'application/json' `
            -SkipCertificateCheck:$SkipCertificateCheck | Out-Null
        Write-EvtxRelayLog -LogPath $LogPath -Message "Created ingest pipeline '$pipelineName' for '$SourceFile' (detected via column '$($StructureResult.TimestampFieldRaw)')."
    }

    $totalLines = $Lines.Count
    $bulkErrors = New-Object System.Collections.Generic.List[object]
    $bulkUri = "$ElasticBaseUri/$IndexName/_bulk"
    if ($pipelineName) { $bulkUri += "?pipeline=$pipelineName" }

    for ($start = 0; $start -lt $totalLines; $start += $BatchSize) {
        $end = [Math]::Min($start + $BatchSize, $totalLines) - 1
        $batch = @(foreach ($line in $Lines[$start..$end]) { [PSCustomObject]@{ message = $line; source_file = $SourceFile } })
        $bulkBody = ConvertTo-BulkBody -IndexName $IndexName -Records $batch

        $response = Invoke-ElkRequest -Uri $bulkUri -Method Post `
            -Headers $AuthHeaders -Body $bulkBody -ContentType 'application/x-ndjson' `
            -SkipCertificateCheck:$SkipCertificateCheck

        if ($response.errors) {
            for ($j = 0; $j -lt $response.items.Count; $j++) {
                $item = $response.items[$j].index
                if ($item.error) {
                    $detailParts = New-Object System.Collections.Generic.List[string]
                    $errNode = $item.error
                    while ($errNode) {
                        $detailParts.Add("[$($errNode.type)] $($errNode.reason)")
                        $errNode = $errNode.caused_by
                    }
                    $bulkErrors.Add([PSCustomObject]@{
                        Row    = $start + $j + 1
                        Type   = $item.error.type
                        Reason = ($detailParts -join ' <- caused by: ')
                    })
                }
            }
        }

        Write-EvtxRelayLog -LogPath $LogPath -Message "Indexed lines $($start + 1)-$($end + 1) of $totalLines from '$SourceFile' into '$IndexName'."
    }

    $rowsIndexed = $totalLines - $bulkErrors.Count
    if ($bulkErrors.Count -gt 0) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "$($bulkErrors.Count) line(s) from '$SourceFile' failed to index:"
        foreach ($e in $bulkErrors) {
            Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "  Line $($e.Row): $($e.Reason)"
        }
    }

    return [PSCustomObject]@{ TotalLines = $totalLines; RowsIndexed = $rowsIndexed }
}


# MAIN


Write-EvtxRelayLog -LogPath $LogPath -Message "=== EvtxRelay start: File='$File' Tool='$Tool' ==="

try {
    if ($Tool -eq 'apt-hunter') {
        if ($File) {
            throw "-File isn't used with -Tool apt-hunter; pass -Folder pointing at the APT-Hunter output directory instead."
        }
        if (-not $Folder) {
            throw '-Folder is required with -Tool apt-hunter (the directory containing the APT-Hunter CSV output).'
        }
        if (-not (Test-Path -LiteralPath $Folder -PathType Container)) {
            throw "Folder not found: '$Folder'"
        }
        if ($TimestampField) {
            throw "-TimestampField isn't supported with -Tool apt-hunter, since each category file has its own differently-named date column. Omit it and let auto-detection handle each file."
        }
    }
    elseif ($Tool -eq 'auto' -or $Tool -eq 'log') {
        if ($File -and $Folder) {
            throw '-File and -Folder cannot both be given; pass one or the other.'
        }
        if (-not $File -and -not $Folder) {
            throw '-File or -Folder is required.'
        }
        if ($File -and -not (Test-Path -LiteralPath $File -PathType Leaf)) {
            throw "File not found: '$File'"
        }
        if ($Folder -and -not (Test-Path -LiteralPath $Folder -PathType Container)) {
            throw "Folder not found: '$Folder'"
        }
        if ($Tool -eq 'log' -and $TimestampField) {
            throw "-TimestampField isn't supported with -Tool log; the timestamp always comes from Elasticsearch's structure finder as '@timestamp'."
        }
    }
    else {
        if ($Folder) {
            throw "-Folder is only used with -Tool apt-hunter, auto, or log; pass -File pointing at the CSV instead."
        }
        if (-not $File) {
            throw '-File is required.'
        }
        if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
            throw "File not found: '$File'"
        }
    }

    $sshOverrides = @{}
    if ($PSBoundParameters.ContainsKey('UseSshTunnel')) { $sshOverrides.UseSshTunnel = $UseSshTunnel.IsPresent }
    if ($SshUser) { $sshOverrides.SshUser = $SshUser }
    if ($SshKeyPath) { $sshOverrides.SshKeyPath = $SshKeyPath }
    if ($PSBoundParameters.ContainsKey('RemoteElasticPort')) { $sshOverrides.RemoteElasticPort = $RemoteElasticPort }
    if ($PSBoundParameters.ContainsKey('RemoteKibanaPort')) { $sshOverrides.RemoteKibanaPort = $RemoteKibanaPort }

    $config = Get-EvtxRelayConfig -ConfigDir $ConfigDir -ElkHostOverride $ElkHost -SshOverrides $sshOverrides -LogPath $LogPath -ElkHostPlaceholder $ElkHostPlaceholder
    $cred = Get-EvtxRelayCredential -ConfigDir $ConfigDir -Reset:$ResetCredential -LogPath $LogPath

    if ($config.UseSshTunnel) {
        Confirm-SshTunnel -ElkHost $config.ElkHost -SshUser $config.SshUser -SshKeyPath $config.SshKeyPath `
            -LocalElasticPort $ElasticPort -RemoteElasticPort $config.RemoteElasticPort `
            -LocalKibanaPort $KibanaPort -RemoteKibanaPort $config.RemoteKibanaPort -LogPath $LogPath
    }

    $pair = "$($cred.UserName):$($cred.GetNetworkCredential().Password)"
    $basicAuth = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pair))
    $authHeaders = @{ Authorization = "Basic $basicAuth" }

    # the ssh tunnel connects to this same computer instead of the server's
    # real address, so its https certificate never matches. skip that check
    # automatically in that case.
    $effectiveSkipCertCheck = [bool]($SkipCertificateCheck -or $config.UseSshTunnel)
    $connectHost = if ($config.UseSshTunnel) { '127.0.0.1' } else { $config.ElkHost }

    $elasticBaseUri = "https://${connectHost}:$ElasticPort"
    $kibanaBaseUri = "https://${connectHost}:$KibanaPort"

    if ($Tool -eq 'apt-hunter') {
        $csvPaths = @(Get-ChildItem -LiteralPath $Folder -Filter '*.csv' -File | Select-Object -ExpandProperty FullName)
        if ($csvPaths.Count -eq 0) {
            throw "No .csv files found in '$Folder'."
        }
        $categoryMap = Get-AptHunterCategoryMap -CsvPaths $csvPaths

        $fileResults = New-Object System.Collections.Generic.List[object]
        foreach ($csvPath in $csvPaths) {
            $category = $categoryMap[$csvPath]
            $fileIndexName = Get-EvtxRelayIndexName -Tool $Tool -SubModule $category -CustomName $IndexName -Exact:$ExactIndexName
            Write-EvtxRelayLog -LogPath $LogPath -Message "--- Processing '$csvPath' (category '$category', index '$fileIndexName') ---"

            try {
                $records = @(Import-Csv -Path $csvPath -Encoding UTF8)
                if ($records.Count -eq 0) {
                    Write-EvtxRelayLog -LogPath $LogPath -Message "Skipped '$csvPath': no data rows."
                    $fileResults.Add([PSCustomObject]@{ File = $csvPath; IndexName = $fileIndexName; Status = 'Skipped (empty)' })
                    continue
                }

                $originalHeaders = @($records[0].PSObject.Properties.Name)
                $headerMap = Get-SanitizedHeaderMap -Headers $originalHeaders
                $sanitizedFields = @($headerMap.Values)
                Write-EvtxRelayLog -LogPath $LogPath -Message "Detected $($sanitizedFields.Count) columns: $($sanitizedFields -join ', ')"

                $resolvedTimestampField = Resolve-EvtxRelayTimestampField -SanitizedFields $sanitizedFields `
                    -Candidates $TimestampCandidates[$Tool] -Override $null
                if (-not $resolvedTimestampField) {
                    Write-EvtxRelayLog -LogPath $LogPath -Message "Skipped '$csvPath': no recognizable timestamp column."
                    $fileResults.Add([PSCustomObject]@{ File = $csvPath; IndexName = $fileIndexName; Status = 'Skipped (no timestamp)' })
                    continue
                }
                Write-EvtxRelayLog -LogPath $LogPath -Message "Using '$resolvedTimestampField' as the timestamp field for sorting."

                $result = Invoke-EvtxRelayFileUpload -Records $records -HeaderMap $headerMap -SanitizedFields $sanitizedFields `
                    -IndexName $fileIndexName -Tool $Tool -SubModule $category -Exact:$ExactIndexName `
                    -TimestampField $resolvedTimestampField -TimestampFormat $TimestampFormats[$Tool] `
                    -ElasticBaseUri $elasticBaseUri -KibanaBaseUri $kibanaBaseUri -AuthHeaders $authHeaders `
                    -BatchSize $BatchSize -SkipCertificateCheck:$effectiveSkipCertCheck -LogPath $LogPath

                $fileResults.Add([PSCustomObject]@{ File = $csvPath; IndexName = $result.IndexName; Status = 'Uploaded'; RowsIndexed = $result.RowsIndexed; TotalRows = $result.TotalRows })
            }
            catch {
                $detail = $_.ErrorDetails.Message
                $msg = if ($detail) { "$($_.Exception.Message): $detail" } else { $_.Exception.Message }
                Write-EvtxRelayLog -LogPath $LogPath -Level ERROR -Message "Failed '$csvPath': $msg"
                $fileResults.Add([PSCustomObject]@{ File = $csvPath; IndexName = $fileIndexName; Status = 'Failed' })
            }
        }

        Write-EvtxRelayLog -LogPath $LogPath -Message '=== Batch summary ==='
        foreach ($r in $fileResults) {
            $line = "$($r.File): $($r.Status)"
            if ($r.Status -eq 'Uploaded') { $line += " ($($r.RowsIndexed)/$($r.TotalRows) rows into '$($r.IndexName)')" }
            Write-EvtxRelayLog -LogPath $LogPath -Message $line
        }
        $failedCount = @($fileResults | Where-Object { $_.Status -eq 'Failed' }).Count
        Write-EvtxRelayLog -LogPath $LogPath -Message '=== EvtxRelay done ==='
        if ($failedCount -gt 0) {
            throw "$failedCount of $($fileResults.Count) file(s) failed. See the batch summary above."
        }
    }
    elseif ($Tool -eq 'auto' -and $Folder) {
        $csvPaths = @(Get-ChildItem -LiteralPath $Folder -Filter '*.csv' -File | Select-Object -ExpandProperty FullName)
        if ($csvPaths.Count -eq 0) {
            throw "No .csv files found in '$Folder'."
        }

        $aliasMap = Get-EvtxRelayFieldAliasMap -ConfigDir $ConfigDir -LogPath $LogPath

        # detect every file up front, before creating the index, so the shared index's date
        # mapping can be built from every format actually found in the folder instead of only
        # the first file's. a file that fails detection is recorded here and skipped later,
        # rather than aborting the whole batch
        $detections = @{}
        $primaryFormats = New-Object System.Collections.Generic.List[string]
        $sharedTimestampField = $null
        foreach ($csvPath in $csvPaths) {
            Write-EvtxRelayLog -LogPath $LogPath -Message "--- Detecting '$csvPath' ---"
            try {
                $detection = Resolve-EvtxRelayCsvFileDetection -File $csvPath -AliasMap $aliasMap `
                    -AutoTimestampFormatCandidates $AutoTimestampFormatCandidates -Override $TimestampField `
                    -ElasticBaseUri $elasticBaseUri -AuthHeaders $authHeaders `
                    -SkipCertificateCheck:$effectiveSkipCertCheck -LogPath $LogPath
                $detections[$csvPath] = $detection
                if ($detection.TimestampField) { $sharedTimestampField = $detection.TimestampField }
                if ($detection.TimestampFormat) {
                    $primaryFormat = $detection.TimestampFormat -replace '\|\|strict_date_optional_time\|\|epoch_millis$', ''
                    if (-not $primaryFormats.Contains($primaryFormat)) { $primaryFormats.Add($primaryFormat) }
                }
            }
            catch {
                if ($_.Exception.Message -like "No data rows found in *") {
                    Write-EvtxRelayLog -LogPath $LogPath -Message "Skipped '$csvPath': no data rows."
                    $detections[$csvPath] = 'EMPTY'
                    continue
                }
                $detail = $_.ErrorDetails.Message
                $msg = if ($detail) { "$($_.Exception.Message): $detail" } else { $_.Exception.Message }
                Write-EvtxRelayLog -LogPath $LogPath -Level ERROR -Message "Could not detect '$csvPath': $msg"
                $detections[$csvPath] = $null
            }
        }

        $unionedFormat = $null
        if ($primaryFormats.Count -gt 0) {
            $unionedFormat = ($primaryFormats -join '||') + '||strict_date_optional_time||epoch_millis'
        }

        $indexSetup = Resolve-EvtxRelayBatchIndexSetup -ElasticBaseUri $elasticBaseUri -AuthHeaders $authHeaders `
            -Tool $Tool -IndexName $IndexName -Exact:$ExactIndexName `
            -TimestampField $sharedTimestampField -TimestampFormat $unionedFormat `
            -SkipCertificateCheck:$effectiveSkipCertCheck -LogPath $LogPath
        $IndexName = $indexSetup.IndexName

        $fileResults = New-Object System.Collections.Generic.List[object]
        foreach ($csvPath in $csvPaths) {
            $sourceFile = Split-Path -Leaf $csvPath
            $detection = $detections[$csvPath]
            if ($detection -eq 'EMPTY') {
                $fileResults.Add([PSCustomObject]@{ File = $sourceFile; Status = 'Skipped (empty)' })
                continue
            }
            if (-not $detection) {
                $fileResults.Add([PSCustomObject]@{ File = $sourceFile; Status = 'Failed' })
                continue
            }
            Write-EvtxRelayLog -LogPath $LogPath -Message "--- Uploading '$csvPath' ---"
            try {
                # re-parses the file here instead of reusing the detection pass's rows, so folder
                # mode only ever holds one file's rows in memory at a time, same as single-file mode
                $records = @(Import-Csv -LiteralPath $csvPath -Encoding UTF8)
                $uploadResult = Invoke-EvtxRelayCsvBatchUpload -Records $records -HeaderMap $detection.HeaderMap `
                    -SanitizedFields $detection.SanitizedFields -SourceFile $sourceFile -IndexName $IndexName `
                    -ElasticBaseUri $elasticBaseUri -AuthHeaders $authHeaders -BatchSize $BatchSize `
                    -SkipCertificateCheck:$effectiveSkipCertCheck -LogPath $LogPath
                $fileResults.Add([PSCustomObject]@{ File = $sourceFile; Status = 'Uploaded'; RowsIndexed = $uploadResult.RowsIndexed; TotalRows = $uploadResult.TotalRows })
            }
            catch {
                $detail = $_.ErrorDetails.Message
                $msg = if ($detail) { "$($_.Exception.Message): $detail" } else { $_.Exception.Message }
                Write-EvtxRelayLog -LogPath $LogPath -Level ERROR -Message "Failed '$csvPath': $msg"
                $fileResults.Add([PSCustomObject]@{ File = $sourceFile; Status = 'Failed' })
            }
        }

        Write-EvtxRelayLog -LogPath $LogPath -Message "Ensuring Kibana Data View for '$IndexName'..."
        $dataView = Confirm-KibanaDataView -KibanaBaseUri $kibanaBaseUri -AuthHeaders $authHeaders `
            -IndexName $IndexName -TimestampField $sharedTimestampField -SkipCertificateCheck:$effectiveSkipCertCheck

        Write-EvtxRelayLog -LogPath $LogPath -Message "Ensuring Kibana saved search for '$IndexName'..."
        $savedSearch = Confirm-KibanaSavedSearch -KibanaBaseUri $kibanaBaseUri -AuthHeaders $authHeaders `
            -IndexName $IndexName -DataViewId $dataView.Id -TimestampField $sharedTimestampField `
            -SkipCertificateCheck:$effectiveSkipCertCheck

        Write-EvtxRelayLog -LogPath $LogPath -Message '=== Batch summary ==='
        foreach ($r in $fileResults) {
            $line = "$($r.File): $($r.Status)"
            if ($r.Status -eq 'Uploaded') { $line += " ($($r.RowsIndexed)/$($r.TotalRows) rows into '$IndexName')" }
            Write-EvtxRelayLog -LogPath $LogPath -Message $line
        }
        Write-EvtxRelayLog -LogPath $LogPath -Message "Kibana Data View:    $(if ($dataView.Created) { 'created' } else { 'already existed' })"
        Write-EvtxRelayLog -LogPath $LogPath -Message "Kibana saved search: $(if ($savedSearch.Created) { 'created' } else { 'already existed' })"

        $failedCount = @($fileResults | Where-Object { $_.Status -eq 'Failed' }).Count
        Write-EvtxRelayLog -LogPath $LogPath -Message '=== EvtxRelay done ==='
        if ($failedCount -gt 0) {
            throw "$failedCount of $($fileResults.Count) file(s) failed. See the batch summary above."
        }
    }
    elseif ($Tool -eq 'log' -and $Folder) {
        $excludedExtensions = @('.gz', '.zip', '.bz2')
        $logPaths = @(Get-ChildItem -LiteralPath $Folder -File | Where-Object { $excludedExtensions -notcontains $_.Extension.ToLowerInvariant() } | Select-Object -ExpandProperty FullName)
        if ($logPaths.Count -eq 0) {
            throw "No usable files found in '$Folder' (compressed files like .gz/.zip/.bz2 are skipped, not decompressed)."
        }

        $indexSetup = Resolve-EvtxRelayBatchIndexSetup -ElasticBaseUri $elasticBaseUri -AuthHeaders $authHeaders `
            -Tool $Tool -IndexName $IndexName -Exact:$ExactIndexName `
            -TimestampField '@timestamp' -TimestampFormat 'strict_date_optional_time||epoch_millis' `
            -SkipCertificateCheck:$effectiveSkipCertCheck -LogPath $LogPath
        $IndexName = $indexSetup.IndexName

        $fileResults = New-Object System.Collections.Generic.List[object]
        foreach ($sourceLogPath in $logPaths) {
            # named $sourceLogPath, not $logPath: powershell variable names are case-insensitive,
            # so a loop variable called $logPath would be the exact same variable as the script's
            # own $LogPath (the execution log file), silently overwriting it with the current
            # source file's path on every iteration
            $sourceFile = Split-Path -Leaf $sourceLogPath
            Write-EvtxRelayLog -LogPath $LogPath -Message "--- Processing '$sourceLogPath' ---"
            try {
                $lines = @(Get-Content -LiteralPath $sourceLogPath -Encoding UTF8)
                if ($lines.Count -eq 0) {
                    Write-EvtxRelayLog -LogPath $LogPath -Message "Skipped '$sourceLogPath': no lines."
                    $fileResults.Add([PSCustomObject]@{ File = $sourceFile; Status = 'Skipped (empty)' })
                    continue
                }

                $structureResult = Resolve-EvtxRelayLogStructure -File $sourceLogPath `
                    -ElasticBaseUri $elasticBaseUri -AuthHeaders $authHeaders `
                    -SkipCertificateCheck:$effectiveSkipCertCheck -LogPath $LogPath

                if (-not $structureResult) {
                    Write-EvtxRelayLog -LogPath $LogPath -Level ERROR -Message "Failed '$sourceLogPath': no reliable per-line timestamp could be detected."
                    $fileResults.Add([PSCustomObject]@{ File = $sourceFile; Status = 'Failed' })
                    continue
                }

                $uploadResult = Invoke-EvtxRelayLogBatchUpload -Lines $lines -SourceFile $sourceFile -IndexName $IndexName `
                    -StructureResult $structureResult `
                    -ElasticBaseUri $elasticBaseUri -AuthHeaders $authHeaders -BatchSize $BatchSize `
                    -SkipCertificateCheck:$effectiveSkipCertCheck -LogPath $LogPath

                $fileResults.Add([PSCustomObject]@{ File = $sourceFile; Status = 'Uploaded'; RowsIndexed = $uploadResult.RowsIndexed; TotalRows = $uploadResult.TotalLines })
            }
            catch {
                $detail = $_.ErrorDetails.Message
                $msg = if ($detail) { "$($_.Exception.Message): $detail" } else { $_.Exception.Message }
                Write-EvtxRelayLog -LogPath $LogPath -Level ERROR -Message "Failed '$sourceLogPath': $msg"
                $fileResults.Add([PSCustomObject]@{ File = $sourceFile; Status = 'Failed' })
            }
        }

        Write-EvtxRelayLog -LogPath $LogPath -Message "Ensuring Kibana Data View for '$IndexName'..."
        $dataView = Confirm-KibanaDataView -KibanaBaseUri $kibanaBaseUri -AuthHeaders $authHeaders `
            -IndexName $IndexName -TimestampField '@timestamp' -SkipCertificateCheck:$effectiveSkipCertCheck

        Write-EvtxRelayLog -LogPath $LogPath -Message "Ensuring Kibana saved search for '$IndexName'..."
        $savedSearch = Confirm-KibanaSavedSearch -KibanaBaseUri $kibanaBaseUri -AuthHeaders $authHeaders `
            -IndexName $IndexName -DataViewId $dataView.Id -TimestampField '@timestamp' `
            -SkipCertificateCheck:$effectiveSkipCertCheck

        Write-EvtxRelayLog -LogPath $LogPath -Message '=== Batch summary ==='
        foreach ($r in $fileResults) {
            $line = "$($r.File): $($r.Status)"
            if ($r.Status -eq 'Uploaded') { $line += " ($($r.RowsIndexed)/$($r.TotalRows) lines into '$IndexName')" }
            Write-EvtxRelayLog -LogPath $LogPath -Message $line
        }
        Write-EvtxRelayLog -LogPath $LogPath -Message "Kibana Data View:    $(if ($dataView.Created) { 'created' } else { 'already existed' })"
        Write-EvtxRelayLog -LogPath $LogPath -Message "Kibana saved search: $(if ($savedSearch.Created) { 'created' } else { 'already existed' })"

        $failedCount = @($fileResults | Where-Object { $_.Status -eq 'Failed' }).Count
        Write-EvtxRelayLog -LogPath $LogPath -Message '=== EvtxRelay done ==='
        if ($failedCount -gt 0) {
            throw "$failedCount of $($fileResults.Count) file(s) failed. See the batch summary above."
        }
    }
    elseif ($Tool -eq 'log') {
        Write-EvtxRelayLog -LogPath $LogPath -Message "Reading log file: $File"
        $lines = @(Get-Content -LiteralPath $File -Encoding UTF8)
        if ($lines.Count -eq 0) {
            throw "No lines found in '$File'."
        }

        $structureResult = Resolve-EvtxRelayLogStructure -File $File `
            -ElasticBaseUri $elasticBaseUri -AuthHeaders $authHeaders `
            -SkipCertificateCheck:$effectiveSkipCertCheck -LogPath $LogPath

        Invoke-EvtxRelayLogUpload -Lines $lines -IndexName $IndexName -Tool $Tool -Exact:$ExactIndexName `
            -StructureResult $structureResult `
            -ElasticBaseUri $elasticBaseUri -KibanaBaseUri $kibanaBaseUri -AuthHeaders $authHeaders `
            -BatchSize $BatchSize -SkipCertificateCheck:$effectiveSkipCertCheck -LogPath $LogPath | Out-Null

        Write-EvtxRelayLog -LogPath $LogPath -Message '=== EvtxRelay done ==='
    }
    else {
        Write-EvtxRelayLog -LogPath $LogPath -Message "Reading CSV: $File"
        $records = @(Import-Csv -Path $File -Encoding UTF8)
        if ($records.Count -eq 0) {
            throw "No data rows found in '$File'."
        }

        $originalHeaders = @($records[0].PSObject.Properties.Name)
        $headerMap = Get-SanitizedHeaderMap -Headers $originalHeaders
        $sanitizedFields = @($headerMap.Values)
        Write-EvtxRelayLog -LogPath $LogPath -Message "Detected $($sanitizedFields.Count) columns: $($sanitizedFields -join ', ')"

        $timestampCandidatesForTool = $TimestampCandidates[$Tool]
        $timestampFormatForTool = $TimestampFormats[$Tool]

        if ($Tool -eq 'auto') {
            $aliasMap = Get-EvtxRelayFieldAliasMap -ConfigDir $ConfigDir -LogPath $LogPath
            $headerMap = Resolve-EvtxRelayFieldConcepts -HeaderMap $headerMap -AliasMap $aliasMap -LogPath $LogPath
            $sanitizedFields = @($headerMap.Values)
            Write-EvtxRelayLog -LogPath $LogPath -Message "Columns after concept mapping: $($sanitizedFields -join ', ')"
            $timestampCandidatesForTool = @('event_timestamp')
        }

        $resolvedTimestampField = Resolve-EvtxRelayTimestampField -SanitizedFields $sanitizedFields `
            -Candidates $timestampCandidatesForTool -Override $TimestampField

        # only worth asking elasticsearch to guess when the alias table found nothing at all.
        # if it already found a column, trust that pick instead of risking a second opinion
        # that names a different column, which would have no clean way to be resolved
        $structureFinderResult = $null
        if (-not $resolvedTimestampField -and $Tool -eq 'auto') {
            $structureFinderResult = Resolve-EvtxRelayTimestampViaFindStructure -File $File -HeaderMap $headerMap `
                -ElasticBaseUri $elasticBaseUri -AuthHeaders $authHeaders -SkipCertificateCheck:$effectiveSkipCertCheck -LogPath $LogPath
            if ($structureFinderResult) {
                # don't let the structure finder's pick steal 'event_timestamp' out from under
                # a column the alias table already claimed that name for
                $existingOwner = @($headerMap.Keys | Where-Object { $headerMap[$_] -eq 'event_timestamp' })
                if ($existingOwner.Count -gt 0) {
                    throw "Structure finder collision: '$($structureFinderResult.OriginalColumnName)' and '$($existingOwner[0])' would both end up named 'event_timestamp'. Rename one of the source columns, or edit .evtxrelay/field-aliases.json, before re-running."
                }
                $headerMap[$structureFinderResult.OriginalColumnName] = 'event_timestamp'
                $sanitizedFields = @($headerMap.Values)
                $resolvedTimestampField = 'event_timestamp'
                $timestampFormatForTool = $structureFinderResult.EsFormat
                Write-EvtxRelayLog -LogPath $LogPath -Message "Field alias table had no timestamp match; Elasticsearch's structure finder detected '$($structureFinderResult.OriginalColumnName)' as the timestamp column, using format $($structureFinderResult.EsFormat)."
            }
        }

        if ($resolvedTimestampField) {
            Write-EvtxRelayLog -LogPath $LogPath -Message "Using '$resolvedTimestampField' as the timestamp field for sorting."
        }
        else {
            Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Could not auto-detect a timestamp column; saved search will not be time-sorted. Pass -TimestampField to override."
        }

        if ($Tool -eq 'auto' -and $resolvedTimestampField -eq 'event_timestamp' -and -not $structureFinderResult) {
            $originalTimestampColumn = @($headerMap.Keys | Where-Object { $headerMap[$_] -eq 'event_timestamp' })[0]
            $sampleValues = @($records | Select-Object -ExpandProperty $originalTimestampColumn)
            $timestampFormatForTool = Resolve-EvtxRelayTimestampFormat -SampleValues $sampleValues -FormatCandidates $AutoTimestampFormatCandidates
            if ($timestampFormatForTool) {
                Write-EvtxRelayLog -LogPath $LogPath -Message "Detected date format for 'event_timestamp': $timestampFormatForTool"
            }
            else {
                Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Could not confidently detect a date format for 'event_timestamp' from sample values; index will be created without an explicit date mapping."
            }
        }

        Invoke-EvtxRelayFileUpload -Records $records -HeaderMap $headerMap -SanitizedFields $sanitizedFields `
            -IndexName $IndexName -Tool $Tool -SubModule 'events' -Exact:$ExactIndexName `
            -TimestampField $resolvedTimestampField -TimestampFormat $timestampFormatForTool `
            -ElasticBaseUri $elasticBaseUri -KibanaBaseUri $kibanaBaseUri -AuthHeaders $authHeaders `
            -BatchSize $BatchSize -SkipCertificateCheck:$effectiveSkipCertCheck -LogPath $LogPath | Out-Null

        Write-EvtxRelayLog -LogPath $LogPath -Message '=== EvtxRelay done ==='
    }
}
catch {
    $detail = $_.ErrorDetails.Message
    $msg = if ($detail) { "$($_.Exception.Message): $detail" } else { $_.Exception.Message }
    Write-EvtxRelayLog -LogPath $LogPath -Level ERROR -Message "EvtxRelay failed: $msg"
    throw
}
