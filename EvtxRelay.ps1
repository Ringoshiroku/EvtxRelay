#Requires -Version 5.1
<#
.SYNOPSIS
    takes a csv file (from hayabusa, chainsaw, or evtxecmd) and loads it into
    elasticsearch in batches.

.DESCRIPTION
    reads a csv made by one of the three tools, cleans up its column names
    (removes the hidden byte at the start of the file, swaps dots for
    underscores), and uploads every row into elasticsearch in batches. login
    details are cached after the first run.

.EXAMPLE
    .\EvtxRelay.ps1 -File .\crownjewel2.csv -Tool hayabusa

.EXAMPLE
    .\EvtxRelay.ps1 -File .\path.csv -Tool chainsaw -ElkHost 10.10.10.5
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$File,

    [Parameter(Mandatory)]
    [ValidateSet('hayabusa', 'chainsaw', 'evtxecmd')]
    [string]$Tool,

    [string]$IndexName,
    [string]$ElkHost,
    [int]$ElasticPort = 9200,
    [int]$BatchSize = 2000,
    [string]$TimestampField,
    [switch]$SkipCertificateCheck,
    [switch]$ResetCredential
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


# SETUP


$ConfigDir = '.evtxrelay'
if (-not (Test-Path -LiteralPath $ConfigDir)) {
    New-Item -Path $ConfigDir -ItemType Directory -Force | Out-Null
}
$LogPath = Join-Path $ConfigDir 'evtxrelay.log'
$ElkHostPlaceholder = '<ISI_IP_ATAU_HOSTNAME_ELK_DI_SINI>'
if (-not $IndexName) { $IndexName = "$Tool-events" }

# best guess at which column holds the date/time for each tool, used only if
# -timestampfield isn't given by hand.
$TimestampCandidates = @{
    hayabusa = @('Timestamp')
    chainsaw = @('timestamp', 'Timestamp', 'Event_System_TimeCreated_SystemTime')
    evtxecmd = @('TimeCreated')
}

# elasticsearch only auto-recognizes a few common date styles. hayabusa and
# evtxecmd don't match, so their exact format is spelled out here. chainsaw
# already matches on its own, so it isn't listed. without this, the date
# column would silently be stored as plain text instead of a real date.
$TimestampFormats = @{
    hayabusa = 'yyyy-MM-dd HH:mm:ss.SSS XXX||strict_date_optional_time||epoch_millis'
    evtxecmd = 'yyyy-MM-dd HH:mm:ss.SSSSSSS||strict_date_optional_time||epoch_millis'
}


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
        ElkHost = $Placeholder
    }
    $template | ConvertTo-Json | Set-Content -LiteralPath $ConfigPath
    Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "No config found. Created a template at '$ConfigPath'. Edit 'ElkHost' before running again."
}

# loads the saved settings file, mixes in any value passed on the command
# line, and makes sure an elk host is actually set before continuing
function Get-EvtxRelayConfig {
    param(
        [Parameter(Mandatory)][string]$ConfigDir,
        [string]$ElkHostOverride,
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$ElkHostPlaceholder
    )
    $configPath = Join-Path $ConfigDir 'config.json'

    if (-not (Test-Path -LiteralPath $configPath)) {
        New-EvtxRelayConfigTemplate -ConfigPath $configPath -Placeholder $ElkHostPlaceholder -LogPath $LogPath
        throw "config.json did not exist, so a template was created at '$configPath'. Fill in 'ElkHost', then run again."
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

    $configObject = [PSCustomObject]@{
        ElkHost = $elkHostValue
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

# rebuilds one row of data using the cleaned up column names
function ConvertTo-SanitizedRecord {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)]$HeaderMap
    )
    $out = [ordered]@{}
    foreach ($original in $HeaderMap.Keys) {
        $out[$HeaderMap[$original]] = $Record.$original
    }
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


# MAIN


Write-EvtxRelayLog -LogPath $LogPath -Message "=== EvtxRelay start: File='$File' Tool='$Tool' ==="

try {
    $config = Get-EvtxRelayConfig -ConfigDir $ConfigDir -ElkHostOverride $ElkHost -LogPath $LogPath -ElkHostPlaceholder $ElkHostPlaceholder
    $cred = Get-EvtxRelayCredential -ConfigDir $ConfigDir -Reset:$ResetCredential -LogPath $LogPath

    $pair = "$($cred.UserName):$($cred.GetNetworkCredential().Password)"
    $basicAuth = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pair))
    $authHeaders = @{ Authorization = "Basic $basicAuth" }

    $elasticBaseUri = "https://$($config.ElkHost):$ElasticPort"

    Write-EvtxRelayLog -LogPath $LogPath -Message "Reading CSV: $File"
    $records = @(Import-Csv -Path $File -Encoding UTF8)
    if ($records.Count -eq 0) {
        throw "No data rows found in '$File'."
    }

    $originalHeaders = @($records[0].PSObject.Properties.Name)
    $headerMap = Get-SanitizedHeaderMap -Headers $originalHeaders
    $sanitizedFields = @($headerMap.Values)
    Write-EvtxRelayLog -LogPath $LogPath -Message "Detected $($sanitizedFields.Count) columns: $($sanitizedFields -join ', ')"

    $resolvedTimestampField = $TimestampField
    if (-not $resolvedTimestampField) {
        foreach ($candidate in $TimestampCandidates[$Tool]) {
            if ($sanitizedFields -contains $candidate) {
                $resolvedTimestampField = $candidate
                break
            }
        }
    }
    if ($resolvedTimestampField) {
        Write-EvtxRelayLog -LogPath $LogPath -Message "Using '$resolvedTimestampField' as the timestamp field."
    }
    else {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Could not auto-detect a timestamp column. Pass -TimestampField to override."
    }

    $indexCreated = Confirm-IndexWithTimestampMapping -ElasticBaseUri $elasticBaseUri -AuthHeaders $authHeaders `
        -IndexName $IndexName -TimestampField $resolvedTimestampField -TimestampFormat $TimestampFormats[$Tool] `
        -SkipCertificateCheck:$SkipCertificateCheck
    if ($indexCreated -and $resolvedTimestampField -and $TimestampFormats.ContainsKey($Tool)) {
        Write-EvtxRelayLog -LogPath $LogPath -Message "Created index '$IndexName' with an explicit date mapping for '$resolvedTimestampField'."
    }

    # UPLOAD THE DATA IN BATCHES

    $totalRows = $records.Count
    $bulkErrors = New-Object System.Collections.Generic.List[object]

    for ($start = 0; $start -lt $totalRows; $start += $BatchSize) {
        $end = [Math]::Min($start + $BatchSize, $totalRows) - 1
        $batch = $records[$start..$end]
        $sanitizedBatch = @(foreach ($r in $batch) { ConvertTo-SanitizedRecord -Record $r -HeaderMap $headerMap })
        $bulkBody = ConvertTo-BulkBody -IndexName $IndexName -Records $sanitizedBatch

        $response = Invoke-ElkRequest -Uri "$elasticBaseUri/$IndexName/_bulk" -Method Post `
            -Headers $authHeaders -Body $bulkBody -ContentType 'application/x-ndjson' `
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
    $missingColumns = Test-IndexColumnCoverage -ElasticBaseUri $elasticBaseUri -AuthHeaders $authHeaders `
        -IndexName $IndexName -ExpectedFields $sanitizedFields -SkipCertificateCheck:$SkipCertificateCheck

    if ($missingColumns.Count -gt 0) {
        Write-EvtxRelayLog -LogPath $LogPath -Level WARN -Message "Columns missing from mapping (all values may have been null/empty): $($missingColumns -join ', ')"
    }
    else {
        Write-EvtxRelayLog -LogPath $LogPath -Message "All $($sanitizedFields.Count) columns present in the index mapping. No column loss detected."
    }

    # PRINT A SUMMARY

    Write-EvtxRelayLog -LogPath $LogPath -Message '=== Summary ==='
    Write-EvtxRelayLog -LogPath $LogPath -Message "Rows indexed: $rowsIndexed / $totalRows"
    Write-EvtxRelayLog -LogPath $LogPath -Message "Column loss:  $(if ($missingColumns.Count -gt 0) { "$($missingColumns.Count) column(s) missing" } else { 'none' })"
    Write-EvtxRelayLog -LogPath $LogPath -Message '=== EvtxRelay done ==='
}
catch {
    $detail = $_.ErrorDetails.Message
    $msg = if ($detail) { "$($_.Exception.Message): $detail" } else { $_.Exception.Message }
    Write-EvtxRelayLog -LogPath $LogPath -Level ERROR -Message "EvtxRelay failed: $msg"
    throw
}
