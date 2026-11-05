# REWIND — Windows Activity Timeline

Standalone Windows desktop forensic artifact collector.

## Run
1. Extract the ZIP.
2. Windows 10/11 + Python 3.10+.
3. Run `python main.py` from Command Prompt.
4. Run as Administrator for best access.

No third-party dependencies.

## Sources
- Recent Items folder metadata
- Prefetch file metadata (filesystem modified time, not guaranteed execution time)
- Automatic and Custom Jump List file metadata
- Startup folder entries
- Downloads folder metadata
- USBSTOR registry device entries
- Selected Security, System, and PowerShell event IDs via `wevtutil`

## Exports
JSON, CSV, and HTML.

## Limitations
Not a full forensic suite. Does not yet parse LNK targets, Jump List internals, Prefetch binary execution history, Amcache, Shimcache, or USN Journal. Event log access depends on permissions and audit configuration. Timestamps may represent filesystem modification rather than the underlying activity. Missing artifacts do not prove an event did not occur. Use only on systems you own or are authorized to examine.
