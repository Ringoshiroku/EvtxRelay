# EvtxRelay

EvtxRelay is a single PowerShell script that takes a CSV timeline produced by
Hayabusa, Chainsaw, or EvtxECmd and pushes it into an existing ELK
(Elasticsearch and Kibana) stack. It bulk indexes the data, checks that no
column was lost along the way, and leaves you with a ready to open Kibana
saved search. It has no server side component and does not wrap the parser
tools themselves: you run Hayabusa, Chainsaw, or EvtxECmd yourself, then hand
the resulting CSV to EvtxRelay.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 or newer.
- A way to reach the VPS's Elasticsearch (port 9200) and Kibana (port 5601)
  over HTTPS from your workstation. If those ports are only open on the
  VPS's own localhost, you can use `-UseSshTunnel` instead (see below), which
  needs Windows' OpenSSH client (`ssh`) on your `PATH`.
- Elastic and Kibana credentials that can write to indices and create saved
  objects.
- Kibana 7.x or 8.x. On 8.x the script uses Kibana's Data Views API. On 7.x,
  where that API does not exist, it falls back automatically to the older
  Saved Objects API for the same underlying index pattern object.

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
```

`-Tool` only accepts `hayabusa`, `chainsaw`, or `evtxecmd`. It is never
guessed from the CSV headers, since each tool's schema can change across
versions and being explicit is safer than guessing.

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

## Parameters

| Parameter              | Required     | Default      | Purpose |
|------------------------|---------------|--------------|---------|
| `-File`                 | Yes           | none         | Path to the CSV produced by the parser. |
| `-Tool`                 | Yes           | none         | `hayabusa`, `chainsaw`, or `evtxecmd`. Picks the target index and the timestamp field guess. |
| `-IndexName`            | No            | `<tool>-events` | Overrides the Elasticsearch index (and matching Kibana Data View/saved search) name, if you don't want the default `hayabusa-events`/`chainsaw-events`/`evtxecmd-events` naming. |
| `-ElkHost`              | No            | saved value  | Elasticsearch and Kibana host, or the SSH target host if using `-UseSshTunnel`. Works the same whether it's a remote VPS or a lab machine on your local network. Also updates the saved value. |
| `-ElasticPort`          | No            | `9200`       | Local port EvtxRelay connects to for Elasticsearch. This is the tunnel's local port if using `-UseSshTunnel`. |
| `-KibanaPort`           | No            | `5601`       | Local port EvtxRelay connects to for Kibana. This is the tunnel's local port if using `-UseSshTunnel`. |
| `-BatchSize`            | No            | `2000`       | Rows sent per bulk request. |
| `-TimestampField`       | No            | auto-guessed | Overrides the column used to sort the Kibana saved search, if the guess is wrong or missing. |
| `-SkipCertificateCheck` | No            | off          | Skips TLS certificate checks, for self-signed VPS certificates. Turned on automatically when `-UseSshTunnel` is used. |
| `-ResetCredential`      | No            | off          | Asks for your credentials again, for example after a password change. |
| `-UseSshTunnel`         | No            | off (saved)  | Opens or reuses a background SSH tunnel to reach an Elasticsearch or Kibana that only listens on the VPS's own localhost. |
| `-SshUser`              | If tunneling  | saved value  | SSH username for the tunnel. |
| `-SshKeyPath`           | If tunneling  | saved value  | Path to the SSH private key. Must have no passphrase. |
| `-RemoteElasticPort`    | No            | `9200` (saved) | The port Elasticsearch listens on, on the VPS itself. |
| `-RemoteKibanaPort`     | No            | `443` (saved)  | The port Kibana listens on, on the VPS itself. Often `443` directly rather than the usual `5601`. |

## What each run does

1. Reads the CSV, strips a BOM if one is present, and replaces any dots in
   column names with underscores, since Elasticsearch treats dots as
   nested-object separators.
2. Bulk indexes every row into a stable index named `<tool>-events` by
   default (`hayabusa-events`, `chainsaw-events`, or `evtxecmd-events`), or
   whatever name you passed via `-IndexName`. This is not a date-rolling
   index, since the data belongs to one forensic case.
3. Compares the CSV's columns against the index's live field mapping and
   reports, by name, any column that did not make it in.
4. Creates a Kibana Data View and saved search for that index if they do not
   already exist. Both are matched by title first, so running the script
   again is safe and will not create duplicates.
5. Prints a summary: rows indexed, whether any columns were lost, and
   whether the Data View and saved search were created or already existed.
   The same summary is added to `evtxrelay.log`.
