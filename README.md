# EvtxRelay

EvtxRelay is a single PowerShell script that takes a CSV (a plain-text
spreadsheet file, one row per event) timeline produced by Hayabusa,
Chainsaw, EvtxECmd, or APT-Hunter and pushes it into an existing ELK
(Elasticsearch and Kibana) stack. It bulk indexes the data, checks that no
column was lost along the way, and leaves you with a ready to open Kibana
saved search. It has no server side component and does not wrap the parser
tools themselves: you run Hayabusa, Chainsaw, EvtxECmd, or APT-Hunter
yourself, then hand the resulting CSV (or, for APT-Hunter, its output
folder) to EvtxRelay. A CSV from some other tool can still be uploaded with
`-Tool auto`, which renames a small set of common columns (timestamp,
source/dest IP, hostname, user name, event ID, process name) to shared
names so data from different unfamiliar sources ends up comparable in
Kibana.

This works the same way whether Elasticsearch/Kibana live on a remote VPS
or on a lab machine on your own local network (same office/lab WiFi, for
example) -- EvtxRelay just needs to be able to reach the host over HTTPS,
wherever that host actually is. See [Quick commands](#quick-commands) below
for ready-to-run examples of both.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 or newer.
- A way to reach Elasticsearch (port 9200) and Kibana (port 5601) over
  HTTPS from your workstation -- whether the ELK host is a remote VPS or a
  lab machine on the same local network. If those ports are only reachable
  from the ELK host's own localhost (common on a VPS with no reverse proxy
  set up for Elasticsearch), you can use `-UseSshTunnel` instead (see
  below), which needs Windows' OpenSSH client (`ssh`) on your `PATH`.
- Elastic and Kibana credentials that can write to indices and create saved
  objects.
- Kibana 7.x or 8.x. Kibana's concept of "which index to search" is called
  a **Data View** on 8.x; the same concept on 7.x is called an **index
  pattern** and is managed through an older API. EvtxRelay detects which
  one your Kibana has and uses the matching one automatically -- you don't
  need to do anything differently either way.

## Built-in help

The script has standard PowerShell comment based help. From the script's
directory:

```powershell
Get-Help .\EvtxRelay.ps1            # summary and syntax
Get-Help .\EvtxRelay.ps1 -Full      # full parameter detail
Get-Help .\EvtxRelay.ps1 -Examples  # just the usage examples
```

## Basic usage

Run the parser tool yourself first, then hand its CSV output to EvtxRelay
and tell it which schema to expect with `-Tool`:

```powershell
.\EvtxRelay.ps1 -File .\crownjewel2.csv -Tool hayabusa
.\EvtxRelay.ps1 -File .\path.csv -Tool chainsaw
.\EvtxRelay.ps1 -File .\htb-trojan-system.csv -Tool evtxecmd
.\EvtxRelay.ps1 -Folder .\apt-hunter-output -Tool apt-hunter
.\EvtxRelay.ps1 -File .\unknown-tool-output.csv -Tool auto
```

`-Tool` accepts `hayabusa`, `chainsaw`, `evtxecmd`, `apt-hunter`, or `auto`.
Other than `auto`, it is never guessed from the CSV headers, since each
tool's schema can change across versions and being explicit is safer than
guessing.

### `-Tool auto`: for a CSV from a tool EvtxRelay doesn't know about

`-Tool auto` works like `-Tool hayabusa`/`chainsaw`/`evtxecmd` (one CSV via
`-File`), but instead of expecting a specific schema, it renames whichever
columns match a small set of common concepts to a shared name, using the
table in `.evtxrelay\field-aliases.json`:

| Concept | Renamed to |
|---|---|
| timestamp | `event_timestamp` |
| source IP | `source_ip` |
| destination IP | `dest_ip` |
| hostname | `hostname` |
| user name | `user_name` |
| event ID | `event_id` |
| process name | `process_name` |

`source_ip` and `dest_ip` (and any other column that ends up with an
ip-like name, whether through this table or on its own) get an explicit
Elasticsearch `ip` mapping instead of plain text, the same as every other
tool's ip-like columns; see the note under `-Tool log`'s field extraction
below for exactly which names qualify and what happens to a value that
isn't actually a valid IP.

The first time `-Tool auto` runs, `field-aliases.json` is created with a
built-in default list of spellings for each concept (for example `source_ip`
matches `SourceIp`, `SourceIP`, `Source IP`, `src_ip`, `ClientIp`, and a few
more). Open the file to see or edit the full list; it's a plain JSON object
of concept name to an ordered list of candidate column spellings, and you
can add more concepts or spellings by hand. A column that doesn't match
anything keeps its own (sanitized) name, exactly like every column does for
the other four tools.

If two columns in the same file both match the same concept, or a column
name is listed under more than one concept, EvtxRelay picks one (whichever
candidate spelling appears first for that concept in `field-aliases.json`,
regardless of which column comes first in the file) and logs a warning
naming the other column so you can tighten the table if the pick was wrong.
If renaming a column to its concept's canonical name would collide with
another column that already has that exact name (for example, a file that
already has both `ClientIp` and `source_ip` columns, and `ClientIp` maps to
`source_ip`), EvtxRelay stops with an error instead of silently overwriting
one column's data with the other's; rename one of the source columns, or
edit `field-aliases.json`, and run it again. If nothing in the file matches
any concept at all, every column just passes through unmapped, same as an
unrecognized column always has.

Once a column is renamed to `event_timestamp`, EvtxRelay samples its values
and tries a curated list of common date formats against them to build a
proper Elasticsearch date mapping, the same way it already has an explicit
format hardcoded for hayabusa/evtxecmd/apt-hunter. If none of the curated
formats fit, the index is created without one, same as when no timestamp
column can be found at all: the data still uploads, it just won't be
time-sorted in the saved search.

If nothing in `field-aliases.json` matched a timestamp column (other
concepts like hostname or username can still have matched fine), EvtxRelay
makes one more attempt before giving up on time-sorting: it sends a sample
of the file to Elasticsearch's own structure finder, which tries to spot a
timestamp-looking column and its date format on its own, independent of
the alias table. If that succeeds, the column is renamed to
`event_timestamp` just like a normal alias match, and the run continues as
usual. If Elasticsearch can't find one either, or can't be reached, the
run still succeeds without one, same as it always has.

`-Tool auto` also accepts `-Folder` instead of `-File`, for a folder of
CSVs that are the same kind of data, like the same export tool run against
several hosts. Unlike APT-Hunter's folder mode, every file lands in one
shared index instead of getting its own, since splitting same-kind data
across indices would force you to flip between Kibana Data Views to
correlate events across hosts in the same time window. Each file still
gets fully independent detection (its own columns, its own timestamp
column and date format), and every uploaded row gets a `source_file` field
holding the filename, so you can still filter or group by origin file in
Kibana without losing the single unified timeline. If two files use
different date formats for their timestamp column, EvtxRelay detects every
file's format before creating the index and builds a mapping that accepts
all of them, not just the first file's. The same detect-everything-first
pass also collects every file's ip-like column names, so the shared
index's `ip` mappings cover every file's columns, not just the first
file's. A file that's genuinely unreadable
or empty, or hits a structure-finder column-naming collision, is logged
and marked Failed, and is excluded from the folder; it doesn't abort the
rest of the batch. A file where simply no timestamp column is found still
uploads into the shared index, just untimed, same as single-file
`-Tool auto`'s own behavior above. Files are discovered the same way
APT-Hunter's folder mode already does: every `*.csv` in the folder, no
recursion into subdirectories.

### `-Tool log`: for plain `.log` files (syslog, firewall, access logs)

`-Tool log` is for files that aren't tabular at all, like `auth.log`,
firewall/device logs, or web server access logs: one event per line, no
columns. Each line becomes an Elasticsearch document with a `message`
field holding the line untouched.

To find a timestamp in each line, EvtxRelay sends a sample of the file to
the same Elasticsearch structure finder `-Tool auto` uses, but asks it to
detect a per-line pattern instead of columns. If it finds one, EvtxRelay
takes Elasticsearch's own suggested parsing steps (a pattern-matching step
plus a date-parsing step) and turns them into an Elasticsearch ingest
pipeline, so the actual per-line parsing happens on the server, not in
PowerShell. Every line then gets a proper `@timestamp` field alongside its
`message`. A line that doesn't match the detected pattern still gets
indexed, just with `grok_parse_failed: true` set instead of an
`@timestamp`, so a run is never derailed by a handful of odd lines. Because
the saved search this tool creates is time-filtered on `@timestamp`, those
lines never show up in it, no matter what filter you add on top; the run's
summary reports how many lines were tagged `grok_parse_failed`, and you can
find the actual lines with a direct query against the index (for example
`grok_parse_failed:true` in Kibana's Dev Tools console, or a second data
view that isn't time-based).

If Elasticsearch can't find a reliable timestamp pattern at all, or can't
be reached, every line still gets uploaded with just its `message` field,
same as any other timestamp-detection failure elsewhere in this tool: the
run succeeds, it just won't be time-sorted. If Elasticsearch decides the
file isn't actually log-shaped (for example, it's really a CSV in
disguise), the run stops with a message suggesting `-Tool auto` instead,
since forcing structured data through this raw-message-only path would
throw away structure a different tool would have kept.

Beyond the timestamp, EvtxRelay now extracts real fields from two kinds
of log line it can detect reliably. If Elasticsearch recognizes the line
as one of its own known formats (for example, a web server's combined
access log), every field that format defines gets pulled out and
correctly typed — client IP as a real IP field, status codes and byte
counts as numbers, and so on — not just an incidental field or two.

If the line isn't a known format but looks like `key=value` text (common
for firewall and similar device logs, for example `srcip=10.1.1.5
action=deny`), EvtxRelay extracts every key as its own field, using the
log's own key names. Elasticsearch's own pattern-guessing isn't reliable
for this kind of line (an ad-hoc guess can produce meaningless field
names, and in one case tested during development, silently dropped the
time-of-day entirely when a timestamp was split across two separate keys
like `date=`/`time=`), so this path builds its own extraction instead of
trusting that guess. When a `date` and a `time` key are both present,
they're combined into one real, fully-precise timestamp; a single field
named `timestamp`, `time`, or `datetime` works too. A file whose extracted
field would collide with a field EvtxRelay sets itself (`message`,
`@timestamp`, `source_file`, `grok_parse_failed`) stops with a clear error
instead of silently overwriting it, same as `-Tool auto`'s column-collision
guards.

Fields that look like an IP address (`srcip`, `source_ip`, `clientip`, and
similar common names, matched case-insensitively) get an explicit `ip`
mapping in the index, not just plain text — this applies to `-Tool auto`'s
aliased `source_ip`/`dest_ip` columns too, and to every other CSV tool's
columns that happen to carry one of these names. A value that doesn't
actually look like a valid IP is still stored and visible in that
row/line, it's just not searchable, filterable, or sortable on that
particular field; it doesn't fail the whole upload. The run's summary
reports how many rows/lines this happened to, the same way it reports
`grok_parse_failed` lines.

Any line that doesn't fit either of those two shapes still gets just a
timestamp and `message`, exactly as before — this isn't a general-purpose
field-extraction engine for arbitrary log formats, and formats that mix
several different message layouts in one file (a firewall log with many
different message types under one general syslog structure, for example)
aren't reliably covered by either path above. It also doesn't merge
multi-line events (like a stack trace spanning several lines) into one
document; each line is always its own event.

`-Tool log` also accepts `-Folder` instead of `-File`, for a folder of log
files, like a rotated `auth.log` directory (`auth.log`, `auth.log.1`,
`auth.log.2`, `messages`, `secure`, with no consistent extension). Every
file in the folder is picked up except compressed ones (`.gz`/`.zip`/
`.bz2`, skipped rather than decompressed), no recursion into
subdirectories. As with `-Tool auto`'s folder mode, every file lands in
one shared index instead of getting its own, tagged with a `source_file`
field per row so you can filter by origin file in Kibana. Different files
can genuinely need different parsing patterns (a firewall log and a VPN
log rarely share a line format), so each file gets its own ingest
pipeline built from its own structure-finder result, even though they all
write into the same index. Unlike single-file `-Tool log`, where a file
with no reliable per-line timestamp pattern still uploads untimed with
just `message`, folder mode marks that file Failed and does not upload
its lines at all; only files where Elasticsearch finds a pattern land in
the shared index. A file that isn't log-shaped (for example, a CSV run
through `-Tool log` by mistake) is also marked Failed rather than
stopping the whole folder; either way, the rest of the folder still
uploads. Because every file's extracted fields land in that same shared
index, two files that extract a same-named field with different apparent
types (one file's `id=123` inferred as a number, another's
`id=abc-forwarded` wanting to be a string) will show per-line indexing
errors for whichever file's lines don't match the mapping the index
already settled on. Ip-like field names are the one exception: instead of
failing per-line, EvtxRelay adds each newly-seen one to the shared
index's mapping as it's discovered, so a later file introducing a `srcip`
the first file didn't have still gets it typed correctly, and a genuine
mapping conflict there degrades to a logged warning rather than per-line
errors.

### `-Tool iis`: for IIS W3C Extended web server logs

    .\EvtxRelay.ps1 -File .\u_ex220302.log -Tool iis

IIS's default W3C Extended log format isn't a CSV: it's space-delimited,
and the real column list lives on a `#Fields:` line buried after a few
other `#`-prefixed metadata lines, not on row 1. That `#Fields:` block can
even repeat partway through a file (IIS rewrites it whenever logging is
reconfigured or the log rolls while the file stays open) — `-Tool iis`
handles all of this without needing `Import-Csv` at all.

IIS's own column names are terse W3C notation, so they're translated to
this project's friendlier, consistent names using a fixed built-in table
(not `.evtxrelay\field-aliases.json` — these names are known and fixed,
not guessed):

| IIS column | Becomes |
|---|---|
| `c-ip` | `source_ip` (the client's IP, matching every other tool's `source_ip`) |
| `s-ip` | `dest_ip` (the server's own listening IP, not the client's) |
| `cs-username` | `user_name` |
| `cs-method` | `method` |
| `cs-uri-stem` | `uri_stem` |
| `cs-uri-query` | `uri_query` |
| `s-port` | `port` |
| `cs(User-Agent)` | `user_agent` |
| `cs(Referer)` | `referrer` |
| `sc-status` | `status` |
| `sc-substatus` | `substatus` |
| `sc-win32-status` | `win32_status` |
| `time-taken` | `time_taken` |

Any column not in this table keeps its own (sanitized) name. `source_ip`/
`dest_ip` get the same `ip`-type mapping every other tool's IP-named
columns already get, automatically.

IIS's `date` and `time` are separate columns; they're combined into a
single `event_timestamp` field (and mapped as the Kibana time field) at
upload time. A file whose `#Fields:` line doesn't include both `date` and
`time` still uploads, just without time-sorting.

Any value IIS writes as a literal `-` (its way of marking a blank field)
is treated as absent, not stored as the string `-`.

A data line that doesn't have the right number of fields for the active
`#Fields:` columns is skipped with a warning, not fatal to the rest of the
file. A file whose `#Fields:` block genuinely changes to a different
column list partway through (not just repeats the same one) fails with a
clear error — split it by hand before re-running. A file with no
`#Fields:` line at all isn't IIS-shaped and fails with a clear error too;
use `-Tool auto` if it's actually a CSV.

`-Folder` works the same way it does for `-Tool log`: every file in the
folder except compressed ones (`.gz`/`.zip`/`.bz2`) lands in one shared
index, tagged with `source_file` per row.

### `-Tool json`: for JSON-based log sources

    .\EvtxRelay.ps1 -File .\waf-logs.json -Tool json

For JSON-shaped event sources that aren't tabular at all: AWS WAF logs,
ModSecurity's JSON audit log, or an XDR platform export/stream like
CrowdStrike Falcon Data Replicator. The expected shape is one JSON object per
line (NDJSON) -- what every real source above actually ships as. If the whole
file turns out to have zero valid one-line JSON objects, EvtxRelay falls back
to parsing the entire file as one JSON value instead, which also covers a
pretty-printed single object (for example ModSecurity's JSON output, which
requires "concurrent" logging mode and writes one object per file) or a
genuine top-level JSON array.

Unlike every other tool here, nested objects and arrays are **not**
flattened into synthetic field names -- they're indexed close to as-received,
since Elasticsearch stores nested JSON natively and Kibana's Discover view can
expand it. The only change made to a record's own shape is the same one every
other tool already makes to column names: a key containing a literal `.` gets
it replaced with `_`, since Elasticsearch treats a dot in a field's own name
as a nested-object separator.

A timestamp field is found by checking a built-in list of common key names
(`timestamp`, `time`, `@timestamp`, `ts`, and similar) against every nesting
level of the first record that has one, not just the top level -- so AWS
WAF's top-level `timestamp` and ModSecurity's nested `transaction.time_stamp`
are both found the same way, no per-source configuration needed. A numeric
value is classified as seconds or milliseconds since epoch by its magnitude; a
string value is tried against the same curated date-format list `-Tool auto`
uses. Pass `-TimestampField` with a dotted path (e.g.
`-TimestampField transaction.time_stamp`) to override the guess -- this is the
one tool besides the four CSV-shaped ones where `-TimestampField` is
supported.

Fields that look like an IP address (matched by leaf key name, the same list
every other tool uses -- `clientIp`, `srcip`, and similar) get an explicit
`ip` mapping automatically, no matter how deeply nested they are.

A line that isn't valid JSON is skipped with a warning and a running count,
not fatal to the rest of the file. A file that's genuinely not JSON at all
(no valid line, and the whole-file fallback also fails to parse) fails with a
clear error; use `-Tool auto` or `-Tool log` instead if it's actually a CSV or
a plain-text log.

`-Folder` works the same way it does for `-Tool log`/`-Tool iis`: every file
in the folder except compressed ones (`.gz`/`.zip`/`.bz2`, skipped rather than
decompressed) lands in one shared index, tagged with `source_file` per
record. As with those tools, folder mode is for a batch of *same-kind* files
(several days of the same export, for example) -- a folder mixing genuinely
different JSON shapes will still upload, but only the first file's detected
timestamp field name is used as the shared index's time field.

### APT-Hunter is different: a folder of CSVs, not one file

APT-Hunter writes one CSV per event category into a single output folder
(logons, process execution, its combined TimeSketch timeline, and so on),
instead of one CSV like the other three tools. Point `-Folder` at that
folder instead of using `-File`, and EvtxRelay uploads every `.csv` it
finds there in one run, each into its own index named
`apt-hunter-<category>` (for example `apt-hunter-logon_events`,
`apt-hunter-timesketch`), or `<IndexName>-apt-hunter-<category>` if you
passed a custom `-IndexName`. All the CSVs in an APT-Hunter output folder share
a common filename prefix (whatever run name you gave APT-Hunter when you
ran it), and EvtxRelay strips that shared prefix off each filename to get
the category, so the category is independent of whatever you named the
run. If `-Folder` only has one CSV in it, there's no other file to compare
against to find that shared prefix, so the whole filename (run name
included) is used as the category as-is.

A couple of files get skipped automatically rather than uploaded, and this
is normal, not an error:

- A file with no data rows (APT-Hunter creates one file per category even
  when nothing matched it).
- A file with no recognizable date/time column, like the SID-to-username
  lookup table APT-Hunter also writes out. It isn't a timeline, so there's
  nothing to sort a saved search by.

Each file is independent: if one fails to upload, EvtxRelay logs it and
keeps going with the rest, then prints a summary of every file's outcome
at the end. The run only reports an overall failure if at least one file
truly failed, not for skipped files.

The APT-Hunter `.xlsx` report is not used by EvtxRelay; the `.csv` files in
the same output folder already contain the same detections in a simpler
format to parse.

### Setting up `.evtxrelay\config.json` before your first real run

EvtxRelay never prompts you for connection details. `ElkHost` (and the SSH
tunnel settings, if you need them) must be filled in in
`.evtxrelay\config.json`, or passed as flags, before it will talk to
Elasticsearch or Kibana at all. This means a run can't silently sit there
waiting on a prompt you didn't expect, and it's always obvious when the
config is incomplete.

If `.evtxrelay\config.json` doesn't exist yet, running the script once
creates a template file there and stops with an error telling you what to
fill in. That run does not contact Elasticsearch or Kibana. Open the file,
fill in at least `ElkHost` -- the address of the machine running
Elasticsearch/Kibana, whether that's a VPS hostname/IP or a lab machine's
IP on your local network, both work the same way -- and run the script
again.

Your Elastic/Kibana username and password are handled separately from
`config.json`. The first time the script needs them, you will see a plain
prompt for your username, then a masked prompt for your password (the
characters will not show as you type). These are saved in encrypted form,
tied to your Windows user and machine, and are never stored as plain text.

`.evtxrelay\` is created in whatever folder you run the script from, not
your home folder. Run the script from the same folder each time, or it
will not find the saved values.

| File             | Purpose                                       |
|------------------|-------------------------------------------------|
| `config.json`    | `ElkHost` and SSH tunnel settings -- fill this in before your first run |
| `credential.xml` | Encrypted Elastic and Kibana credential          |
| `evtxrelay.log`  | A running log of every run                       |

Once `config.json` is filled in and your credentials are cached, later
runs only need `-File` and `-Tool`.

### If Elasticsearch or Kibana only listen on the VPS's own localhost

Some setups expose Kibana to the internet (often on port 443) while keeping
Elasticsearch reachable only from the VPS itself. If
`Test-NetConnection -ComputerName <host> -Port 9200` fails from your
workstation, check what is actually listening on the VPS before assuming a
firewall is blocking you. Elasticsearch may simply not be listening on any
public interface at all.

In that case, pass `-UseSshTunnel` once with your SSH details, and EvtxRelay
will open a background SSH tunnel itself before talking to Elasticsearch or
Kibana:

```powershell
.\EvtxRelay.ps1 -File .\path.csv -Tool evtxecmd -UseSshTunnel `
    -SshUser security-engineer -SshKeyPath ~\.ssh\engineer.pem `
    -RemoteKibanaPort 443
```

Your SSH key needs to have no passphrase, since the tunnel cannot prompt you
for one. If it does need one, the connection will fail quickly with a clear
error rather than hang. `-UseSshTunnel`, `-SshUser`, `-SshKeyPath`,
`-RemoteElasticPort`, and `-RemoteKibanaPort` are all saved too, so later
runs only need `-File` and `-Tool`. Each run checks whether the tunnel is
already open and reuses it, or opens a new one if not. The tunnel keeps
running after the script finishes, which is fine to leave as is. To close
it yourself, find and stop the background `ssh` process with
`Get-Process ssh | Stop-Process`.

## Quick commands

Ready-to-run examples for both ways of reaching Elasticsearch/Kibana. Swap
in your own file path and (for the first run only) your own `-ElkHost`.

### Via SSH tunnel (remote VPS)

Use this when Elasticsearch/Kibana are only reachable from the VPS's own
localhost -- see [If Elasticsearch or Kibana only listen on the VPS's own
localhost](#if-elasticsearch-or-kibana-only-listen-on-the-vpss-own-localhost)
above for why that happens.

```powershell
.\EvtxRelay.ps1 -File .\your-file.csv -Tool hayabusa -ElkHost 10.10.10.5 -UseSshTunnel `
    -SshUser security-engineer -SshKeyPath ~\.ssh\engineer.pem `
    -RemoteKibanaPort 443
```

```powershell
.\EvtxRelay.ps1 -File .\your-file.csv -Tool chainsaw -ElkHost 10.10.10.5 -UseSshTunnel `
    -SshUser security-engineer -SshKeyPath ~\.ssh\engineer.pem `
    -RemoteKibanaPort 443
```

```powershell
.\EvtxRelay.ps1 -File .\your-file.csv -Tool evtxecmd -ElkHost 10.10.10.5 -UseSshTunnel `
    -SshUser security-engineer -SshKeyPath ~\.ssh\engineer.pem `
    -RemoteKibanaPort 443
```

```powershell
.\EvtxRelay.ps1 -Folder .\your-apt-hunter-output -Tool apt-hunter -ElkHost 10.10.10.5 -UseSshTunnel `
    -SshUser security-engineer -SshKeyPath ~\.ssh\engineer.pem `
    -RemoteKibanaPort 443
```

**After the first run**, `-ElkHost`, `-UseSshTunnel`, `-SshUser`,
`-SshKeyPath`, and `-RemoteKibanaPort` are all cached in `config.json` --
you only need `-File`/`-Folder` and `-Tool` from then on:

```powershell
.\EvtxRelay.ps1 -File .\your-next-file.csv -Tool hayabusa
```

```powershell
.\EvtxRelay.ps1 -Folder .\your-next-apt-hunter-output -Tool apt-hunter
```

### Direct connection (same-network lab)

Use this when Elasticsearch/Kibana are directly reachable from your
workstation -- for example a lab ELK stack on the same WiFi/LAN. No SSH
tunnel needed; `-SkipCertificateCheck` is for a self-signed lab
certificate (omit it if the lab uses a certificate your machine already
trusts).

```powershell
.\EvtxRelay.ps1 -File .\your-file.csv -Tool hayabusa -ElkHost 192.168.1.50 -SkipCertificateCheck
```

```powershell
.\EvtxRelay.ps1 -File .\your-file.csv -Tool chainsaw -ElkHost 192.168.1.50 -SkipCertificateCheck
```

```powershell
.\EvtxRelay.ps1 -File .\your-file.csv -Tool evtxecmd -ElkHost 192.168.1.50 -SkipCertificateCheck
```

```powershell
.\EvtxRelay.ps1 -Folder .\your-apt-hunter-output -Tool apt-hunter -ElkHost 192.168.1.50 -SkipCertificateCheck
```

**After the first run**, `-ElkHost` is cached in `config.json`. However,
`-SkipCertificateCheck` is not cached and must be passed on every run if
your lab certificate is self-signed:

```powershell
.\EvtxRelay.ps1 -File .\your-next-file.csv -Tool hayabusa -SkipCertificateCheck
```

```powershell
.\EvtxRelay.ps1 -Folder .\your-next-apt-hunter-output -Tool apt-hunter -SkipCertificateCheck
```

## Parameters

| Parameter              | Required     | Default      | Purpose |
|------------------------|---------------|--------------|---------|
| `-File`                 | If not apt-hunter | none    | Path to the CSV produced by the parser. Not used with `-Tool apt-hunter`; use `-Folder` instead. |
| `-Tool`                 | Yes           | none         | `hayabusa`, `chainsaw`, `evtxecmd`, `apt-hunter`, `auto`, `log`, `iis`, or `json`. Picks the target index and the timestamp field guess. `auto` also renames matching columns using `.evtxrelay\field-aliases.json`. `log` is for plain `.log` files instead of CSVs. `iis` is for IIS W3C Extended web server logs. `json` is for JSON-based log sources (NDJSON, one JSON object per line); nested objects/arrays are kept nested, not flattened. |
| `-Folder`               | No            | none         | Path to a folder of files to upload instead of a single `-File`. Required with `-Tool apt-hunter` (every `.csv` in the folder gets its own index). Optional with `-Tool auto` (every `.csv`), `-Tool log`, `-Tool iis`, or `-Tool json` (every file except `.gz`/`.zip`/`.bz2` for the latter three); for those four, every file in the folder lands in one shared index instead of its own, tagged with a `source_file` field per row. Not supported with `-Tool hayabusa`/`chainsaw`/`evtxecmd`. |
| `-IndexName`            | No            | none         | Adds a custom prefix to the Elasticsearch index (and matching Kibana Data View/saved search) name, in front of the default `hayabusa-events`/`chainsaw-events`/`evtxecmd-events` naming, e.g. `case42-hayabusa-events`. With `-Tool apt-hunter`, it prefixes each category's index the same way: `<IndexName>-apt-hunter-<category>` (for example `case42-apt-hunter-logon_events`), instead of the default `apt-hunter-<category>`. |
| `-ExactIndexName`       | No            | off          | Requires `-IndexName`. Uses that name as-is for the index instead of adding the tool name in, e.g. `-IndexName case42` becomes just `case42` rather than `case42-hayabusa-events`. With `-Tool apt-hunter`, the category is still appended (`case42-logon_events`), since categories can't share one index. |
| `-ElkHost`              | No            | saved value  | Elasticsearch and Kibana host, or the SSH target host if using `-UseSshTunnel`. Works the same whether it's a remote VPS or a lab machine on your local network. Also updates the saved value. |
| `-ElasticPort`          | No            | `9200`       | Local port EvtxRelay connects to for Elasticsearch. This is the tunnel's local port if using `-UseSshTunnel`. |
| `-KibanaPort`           | No            | `5601`       | Local port EvtxRelay connects to for Kibana. This is the tunnel's local port if using `-UseSshTunnel`. |
| `-BatchSize`            | No            | `2000`       | Rows sent per bulk request. |
| `-TimestampField`       | No            | auto-guessed | Overrides the column used to sort the Kibana saved search, if the guess is wrong or missing. With `-Tool json`, pass a dotted path (e.g. `transaction.time_stamp`) to point at a nested field. Not supported with `-Tool apt-hunter` (each category file has its own differently-named date column), `-Tool log` (the timestamp field is always `@timestamp`, found by Elasticsearch itself), or `-Tool iis` (always the combined `date`+`time` columns). |
| `-SkipCertificateCheck` | No            | off          | Skips TLS certificate checks, for self-signed VPS or lab certificates. Turned on automatically when `-UseSshTunnel` is used. |
| `-ResetCredential`      | No            | off          | Asks for your credentials again, for example after a password change. |
| `-UseSshTunnel`         | No            | off (saved)  | Opens or reuses a background SSH tunnel to reach an Elasticsearch or Kibana that only listens on the VPS's own localhost. |
| `-SshUser`              | If tunneling  | saved value  | SSH username for the tunnel. |
| `-SshKeyPath`           | If tunneling  | saved value  | Path to the SSH private key. Must have no passphrase. |
| `-RemoteElasticPort`    | No            | `9200` (saved) | The port Elasticsearch listens on, on the VPS itself. |
| `-RemoteKibanaPort`     | No            | `443` (saved)  | The port Kibana listens on, on the VPS itself. Often `443` directly rather than the usual `5601`. |

## What each run does

1. Reads the CSV, strips a BOM if one is present (a BOM, or byte order
   mark, is a few invisible bytes some tools put at the very start of a
   file to mark its text encoding -- harmless to the file itself, but it
   corrupts the first column's name if left in), and replaces any dots in
   column names with underscores, since Elasticsearch treats dots as
   nested-object separators. With `-Tool auto`, columns matching a known
   concept are then renamed to their shared name, as described above.
2. Bulk indexes every row into a stable index named `<tool>-events` by
   default (`hayabusa-events`, `chainsaw-events`, or `evtxecmd-events`), or
   `<IndexName>-<tool>-events` if you passed a custom `-IndexName`. This is
   not a date-rolling index, since the data belongs to one forensic case.
   If that index already exists, EvtxRelay warns and asks whether to delete
   and replace it or type a different custom index name instead.
3. Compares the CSV's columns against the index's live field mapping and
   reports, by name, any column that did not make it in.
4. Creates a Kibana Data View and saved search for that index if they do not
   already exist. Both are matched by title first, so running the script
   again is safe and will not create duplicates.
5. Prints a summary: rows indexed, whether any columns were lost, and
   whether the Data View and saved search were created or already existed.
   The same summary is added to `evtxrelay.log`.

With `-Tool apt-hunter`, steps 1-5 happen once for each CSV in `-Folder`
(skipping any file with no data rows or no recognizable timestamp column,
as described above), and a batch summary listing every file's outcome is
printed and logged at the end.
