# EvtxRelay

EvtxRelay is a single PowerShell script that pushes a CSV timeline from
Hayabusa, Chainsaw, EvtxECmd, or APT-Hunter into an existing ELK
(Elasticsearch + Kibana) stack: it bulk indexes the data, checks no column
was lost, and sets up a ready-to-open Kibana Data View and saved search. It
has no server-side component and doesn't run the parser tools themselves:
you run those yourself and hand EvtxRelay the result. A CSV from any other
tool, or a plain `.log`/IIS/JSON log source, also works. See
[Basic usage](#basic-usage).

It works the same whether Elasticsearch/Kibana live on a remote VPS or a
lab machine on your local network. EvtxRelay just needs to reach the host
over HTTPS. See [Getting started](#getting-started) for both cases.

## Requirements

- Windows PowerShell 5.1, or PowerShell 7+.
- HTTPS access to Elasticsearch (9200) and Kibana (5601) from your
  workstation. If those ports are only reachable from the ELK host's own
  localhost (common on a VPS with no reverse proxy), use `-UseSshTunnel`
  instead, see [Getting started](#getting-started). Needs Windows'
  OpenSSH client (`ssh`) on your `PATH`.
- Elastic/Kibana credentials that can write indices and create saved
  objects, filled into `config.json` (see [Getting started](#getting-started)).
- Kibana 7.x or 8.x. EvtxRelay detects whether your Kibana uses Data Views
  (8.x) or the older index pattern API (7.x) and uses the right one
  automatically.

## Built-in help

```powershell
Get-Help .\EvtxRelay.ps1            # summary and syntax
Get-Help .\EvtxRelay.ps1 -Full      # every parameter and tool, in detail
Get-Help .\EvtxRelay.ps1 -Examples  # just the usage examples
```

`-Full` is the exhaustive reference for exactly how each `-Tool` value
behaves (folder mode, field extraction, timestamp fallbacks, and so on).
This README stays intentionally short. Reach for `-Full` for the fine print.

## Getting started

1. Run the script once with no arguments. It creates
   `.evtxrelay\config.json` in the current folder and stops, that run
   never touches Elasticsearch or Kibana.
2. Open `config.json` and fill in `ElkHost` (a VPS hostname/IP or a lab
   machine's LAN IP, both work the same), `ElkUsername`, and `ElkPassword`.
   Then pick one of the two paths below depending on how your ELK stack is
   reachable.
3. Run the script again against a real file. Every run after the first only
   needs `-File`/`-Folder` and `-Tool`.

Run the script from the same folder each time: `.evtxrelay\` lives wherever
you ran it from, not your home folder.

Everything you fill into `config.json`, `ElkHost`, `ElkUsername`,
`ElkPassword`, and the SSH tunnel fields if you use them, is cached and
reused automatically on every later run, whether you connect directly or
through a tunnel. The one flag that's never cached, on either path, is
`-SkipCertificateCheck`: pass it again on every run that needs it.

**Direct connection**: Elasticsearch/Kibana reachable straight from your
workstation (lab stack on the same WiFi/LAN, or a VPS with public ports):

```powershell
.\EvtxRelay.ps1 -File .\your-file.csv -Tool hayabusa -ElkHost 192.168.1.50 -SkipCertificateCheck
```

Drop `-SkipCertificateCheck` if the host uses a certificate your machine
already trusts.

**Via SSH tunnel**: use this when `Test-NetConnection -ComputerName <host>
-Port 9200` fails from your workstation. Elasticsearch may only be
listening on the VPS's own localhost even though Kibana is exposed. Your
SSH key needs no passphrase (the tunnel can't prompt for one):

```powershell
.\EvtxRelay.ps1 -File .\your-file.csv -Tool hayabusa -ElkHost 10.10.10.5 -UseSshTunnel `
    -SshUser security-engineer -SshKeyPath ~\.ssh\engineer.pem -RemoteKibanaPort 443
```

`-UseSshTunnel` skips `-SkipCertificateCheck` for you automatically, since
the tunnel connects to `localhost`, not the real host, so its certificate
never matches anyway. The tunnel is opened in the background and reused on
later runs. It keeps running after the script exits, which is fine to
leave. Close it yourself with `Get-Process ssh | Stop-Process` if you want to.

After either path, later runs are just:

```powershell
.\EvtxRelay.ps1 -File .\your-next-file.csv -Tool hayabusa
```

Add `-SkipCertificateCheck` back to that if you're on the direct-connection
path with a self-signed certificate. The SSH tunnel path never needs it.

## Basic usage

`-Tool` is optional for everything except `apt-hunter`. EvtxRelay looks at
the file itself and figures out which tool produced it. Pass it explicitly
if you'd rather be exact, or a guess turns out wrong (every detection
decision is logged to `.evtxrelay\evtxrelay.log`).

| `-Tool` | Input | What it's for |
|---|---|---|
| `hayabusa`, `chainsaw`, `evtxecmd` | `-File` (a `-Folder` of these works too, without `-Tool`, see below) | CSV timeline from that parser |
| `apt-hunter` | `-Folder`, always explicit | folder of per-category CSVs, each category gets its own index |
| `auto` | `-File` or `-Folder` | CSV from an unrecognized tool, renames common columns (timestamp, IPs, hostname, user, event ID, process) via `.evtxrelay\field-aliases.json` |
| `log` | `-File` or `-Folder` | plain `.log` files (syslog, firewall, access logs), one event per line |
| `iis` | `-File` or `-Folder` | IIS W3C Extended web server logs |
| `json` | `-File` or `-Folder` | NDJSON or single-object/array JSON sources (AWS WAF, ModSecurity, XDR exports) |

```powershell
.\EvtxRelay.ps1 -File .\crownjewel2.csv                          # tool auto-detected
.\EvtxRelay.ps1 -File .\path.csv -Tool chainsaw
.\EvtxRelay.ps1 -Folder .\apt-hunter-output -Tool apt-hunter
.\EvtxRelay.ps1 -Folder .\var-log -Tool log
```

**Folders**: for every `-Tool` except `apt-hunter`, a `-Folder` of same-kind
files lands in one shared index (tagged `source_file` per row/record)
instead of one index each. Leaving `-Tool` out entirely detects each file
in the folder independently, everything still lands in one shared index,
normalized onto a common `event_timestamp` field so Kibana can time-sort
the whole thing even if the folder turns out to be a genuine mix of
formats. If you already know a folder is one consistent kind, `-SameTool`
sniffs only the first file and applies its result to the rest:

```powershell
.\EvtxRelay.ps1 -Folder .\exports -SameTool
```

`apt-hunter` is never auto-detected (its one-index-per-category layout is
too different to guess safely), always pass `-Tool apt-hunter` by hand.
See `Get-Help -Full` for exactly how detection, field extraction, and
timestamp handling work per tool.

## Parameters

| Parameter | Required | Default | Purpose |
|---|---|---|---|
| `-File` | if not apt-hunter | none | path to the input file |
| `-Folder` | if apt-hunter | none | folder of files instead of one `-File`, see [Basic usage](#basic-usage) |
| `-Tool` | no | auto-detected | see the table above |
| `-SameTool` | no | off | with `-Folder` and no `-Tool`: sniff only the first file, apply to the rest |
| `-IndexName` | no | none | custom prefix for the index/Data View name, e.g. `case42-hayabusa-events` |
| `-ExactIndexName` | no | off | requires `-IndexName`, uses it as-is instead of adding the tool name in |
| `-ElkHost` | no | saved | Elasticsearch/Kibana host, or the SSH target if tunneling |
| `-ElasticPort` | no | `9200` | local port for Elasticsearch (tunnel's local port, if tunneling) |
| `-KibanaPort` | no | `5601`, but 443 is tried first if not tunneling | local port for Kibana (tunnel's local port, if tunneling) |
| `-BatchSize` | no | `2000` | rows per bulk request |
| `-TimestampField` | no | auto-guessed | override the timestamp column/path, not supported for apt-hunter, `log`, `iis`, or an undetected `-Folder` mix |
| `-SkipCertificateCheck` | no | off | skip TLS checks, for self-signed certs, on automatically with `-UseSshTunnel` |
| `-UseSshTunnel` | no | off (saved) | open/reuse a background SSH tunnel |
| `-SshUser` | if tunneling | saved | SSH username |
| `-SshKeyPath` | if tunneling | saved | path to a passphrase-less SSH private key |
| `-RemoteElasticPort` | no | `9200` (saved) | Elasticsearch's port on the ELK host itself |
| `-RemoteKibanaPort` | no | `443` (saved) | Kibana's port on the ELK host itself |
| `-Cleanup` | no | off | enter cleanup mode, see [Cleanup](#cleanup) below |
| `-DeleteIndex` | with `-Cleanup` | none | full index name to delete, along with its Data View and saved search |
| `-DeleteSavedSearch` | with `-Cleanup` | none | full index name whose saved search to delete |
| `-DeleteAll` | with `-Cleanup` | off | delete every index/Data View/saved search EvtxRelay has created |

## What each run does

1. Reads the file, strips a BOM if present, and replaces dots in field
   names with underscores (Elasticsearch treats `.` as a nested-object
   separator). `-Tool auto`/`iis` rename matching columns to shared names.
2. Bulk indexes into a stable index named `<tool>-events` (or
   `<IndexName>-<tool>-events`), not a date-rolling index, since the data
   belongs to one case. If the index already exists, EvtxRelay asks
   whether to delete and replace it or use a different name.
3. Compares the source's fields against the index's live mapping and
   reports any that didn't make it in.
4. Creates a Kibana Data View and saved search if they don't already exist
   (matched by title, so re-running is safe).
5. Prints and logs a summary: rows indexed, any lost columns, and whether
   the Data View/saved search were created or already existed.

With `-Tool apt-hunter`, steps 1-5 run once per CSV in `-Folder`, and a
batch summary covering every file is printed at the end.

## Cleanup

`-Cleanup`, combined with exactly one of `-DeleteIndex`, `-DeleteSavedSearch`,
or `-DeleteAll`, removes what a previous run created:

```powershell
.\EvtxRelay.ps1 -Cleanup -DeleteIndex hayabusa-events        # index + its Data View + its saved search
.\EvtxRelay.ps1 -Cleanup -DeleteSavedSearch hayabusa-events  # just the saved search
.\EvtxRelay.ps1 -Cleanup -DeleteAll                           # everything EvtxRelay has ever created
```

Every saved search EvtxRelay creates is titled `<index> (EvtxRelay)`;
`-DeleteAll` finds every saved search with that tag and, for each one,
deletes its Data View and index too, so nothing without the tag is ever
touched. Every cleanup action shows what it found and asks for
confirmation before deleting anything.

## Local files

| File | Purpose |
|---|---|
| `.evtxrelay\config.json` | `ElkHost`, `ElkUsername`/`ElkPassword`, and SSH tunnel settings, fill in before your first run |
| `.evtxrelay\evtxrelay.log` | a running log of every run, including detection decisions |
| `.evtxrelay\field-aliases.json` | `-Tool auto`'s column-name-to-concept table (created on first use, editable) |
