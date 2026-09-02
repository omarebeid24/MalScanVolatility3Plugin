# MalScan — indicator scanner with false-positive suppression

`windows.malscan.MalScan` scans a Windows memory image for malware, ransomware and
attacker-tooling indicators in a single pass, then spends most of its effort deciding
which of those hits are worth an analyst's time.

The scanning part is not the interesting part. Any string scanner will find
`vssadmin delete shadows /all` and a dozen ransomware family names in a typical
Windows image. The problem is that almost all of those hits are noise, and the noise
looks exactly like a serious finding. On the two images used to develop this plugin,
**13,201 of 13,401 raw hits were Microsoft Defender's own signature database** sitting
resident in memory — every ransomware family name, every ransom-note phrase and every
malicious command line it detects, present on a perfectly healthy machine.

MalScan exists to separate those.

## What it filters, and why

**Antivirus signature data (content).** Defender's detection-name database is
recognised three ways: literal taxonomy markers near a hit (`Trojan:`, `Win32/`,
`!MTB`, `#HSTR`), detection-name punctuation (`!Emotet`, `:Koadic`), and family-name
density — four different family names inside one 64 KiB block is a signature database,
not an infection. Contiguous regions are gap-closed up to 2 MiB, because much of the
VDM is compressed and carries no literal marker.

**Ownership (process).** With `--processes`, who owns the page outranks every content
heuristic:

| Owner | Treatment |
|---|---|
| `MsMpEng.exe`, `MpDefenderCoreService.exe`, `NisSrv.exe`, third-party AV engines | Never scored — a ransom note inside the AV engine is the signature database doing its job |
| `MemCompression` | Never scored — holds pages compressed out of *some other* process; this mapping cannot say which |
| No owning process | Never scored — nothing to attribute the hit to |
| Any ordinary process | Scored, and the owner is shown inline |

**Command coherence.** A command indicator only counts inside a readable run of at
least 24 characters. A real command line sits in long printable text; a fragment of a
compressed signature blob is surrounded by control bytes and truncated tokens
(`powersh0f.exe -ep bypass`).

**Word boundaries, per side.** `Conti` no longer matches inside *continue*,
`sdelete` inside *IsDeleted*, `transfer.sh` inside *DataTransfer.Shared*, or
`_readme.txt` inside *HEARTBEAT_README.TXT*. Sides that begin on punctuation stay
open, so `.onion` still matches `abcdef.onion`.

**Family names never score.** `RANSOMWARE_FAMILY` and `MALWARE_TOOLING` are
informational only. A name is a label, not a behaviour: during testing `CryptoLocker`
turned up inside an advertising keyword list and `WannaCry` inside a URL.

## What it will not tell you

The plugin never reports that a host is compromised, because a string scan cannot
establish that. Verdicts describe indicator strength only — `NO ACTIONABLE
INDICATORS`, `WEAK`, `INDICATORS PRESENT`, `STRONG INDICATORS - TRIAGE` — and
`STRONG` additionally requires process attribution to be available. Every run emits
`== SCAN BASIS ==` rows stating whether a translation layer was built, whether
attribution is on, and how many hits were retired by ownership. They are rows rather
than log lines so the caveats survive into CSV and JSON output.

Confirming that a command actually ran needs process command lines, console history,
script-block logs, prefetch or Amcache. This plugin points at where to look.

## Requirements

Volatility 3 (developed against 2.26.1). No third-party Python packages — the
indicator engine, the Base58Check/bech32 address validation and the attribution map
all use the standard library and the framework's own APIs.

Kernel symbols must resolve for `MalScan`, as for any Windows plugin.

## Usage

Either drop `malscan.py` into `volatility3/framework/plugins/windows/`, or point
Volatility at a plugin directory with `-p`. The two give different plugin paths:

```
# installed in the windows plugin directory
python3 vol.py -f image.raw windows.malscan.MalScan

# loaded from a plugin directory
python3 vol.py -p /path/to/plugins -f image.raw malscan.MalScan
```

```
# full run with process attribution
python3 vol.py -f image.raw windows.malscan.MalScan --min-severity HIGH --processes

# truncated / partial / non-Windows images, where no translation layer can be built
python3 vol.py -f image.raw windows.malscan.RawScan
```

| Option | Effect |
|---|---|
| `--min-severity` | `INFO`/`LOW`/`MEDIUM`/`HIGH`. `LOW` and above hides the context-only family names |
| `--categories` | Restrict reporting to named categories. Name categories are always *scanned* regardless, because the AV-database detector needs them |
| `--processes` | Build the physical-page → process map and apply ownership rules |
| `--show-hits` / `--show-context` | Every hit under each indicator / surrounding bytes for demoted hits too (scored hits always carry context) |
| `--wallets` | Extra pass for checksum-validated BTC and XMR addresses |
| `--no-av-filter` | Disable AV-signature suppression, to see what the filtering is doing |
| `--virtual` | Scan the translated address space instead of the physical layer |
| `--max-hits` | Stop after N raw matches |

Two entry points: `MalScan` requires the kernel module, so it always has a real
virtual address space and can attribute hits. `RawScan` takes an unconstrained layer
requirement and scans the image flat, reporting itself as `LIMITED` throughout.

## Performance

One pass. A 2 GB image scans in roughly 40 seconds with the full indicator set;
`--processes` adds about 30 seconds to map ~200,000 physical pages.

## Known limitations

- AV-process suppression matches on **image name only**. Malware named `MsMpEng.exe`
  would inherit the exemption, so demoted hits stay visible rather than being dropped.
- The indicator database is embedded in the source. Threat-intel ages; family names
  and note filenames will need periodic updating.
- The suppression thresholds (24-character command run, 64 KiB blocks, 2 MiB gap
  closing, four names per block) are empirical, derived from the development images.
- Validation to date is limited — see below.

## Validation status

Developed and tested against two 2 GB Windows images. On both, the honest answer
after filtering is that nothing survives as evidence owned by an ordinary process:
`memdump1.raw` scores 0, and `imagery.raw` scores 0 once ownership is applied, with
all seven previously-scored indicators traced to `MsMpEng.exe` (PID 1988) or
`MemCompression` (PID 1332). The false-positive suppression is therefore well
exercised; **true-positive behaviour on a confirmed infection is not yet
demonstrated.**

## Author and licence

Omar Ebeid — originally built for CSE5800 (Advanced Topics in Computer Science),
Florida Institute of Technology.

Licensed under the Volatility Software License 1.0, matching the framework:
<https://www.volatilityfoundation.org/license/vsl-v1.0>
