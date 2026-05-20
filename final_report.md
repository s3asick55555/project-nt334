# Verdict
- Classification: MALWARE
- Confidence: high

# Summary
The script implements a clipboard hijacker that detects Bitcoin addresses in the clipboard, replaces the clipboard content with a hard‑coded BTC address, and persists itself by copying to %APPDATA% and creating a Run key entry. It also contains a self‑destruct routine. The code demonstrates self‑replication, persistence, data manipulation, and collection of clipboard data, all characteristic of malicious activity.

## Key IOCs
- GetClipboardData
- OpenClipboard
- APPDATA
- LOCALAPPDATA
- \Programs\Python\Launcher\py.exe
- HKEY_CURRENT_USER
- SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- BTC CLIPPER
- Starting BTC Clipper

## Interesting Strings
- Clipboard init
- ctypes
- GetClipboardData
- OpenClipboard
- IsClipboardFormatAvailable
- CloseClipboard
- APPDATA
- LOCALAPPDATA
- \Programs\Python\Launcher\py.exe
- winreg
- HKEY_CURRENT_USER
- SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- CreateKeyEx
- SetValueEx
- BTC CLIPPER
- clipboard
- target_clipboard
- Clipboard
- Text found in clipboard: %s
- Probably a btc address.
- Original clipboard: %s
- Setting clipboard to %s
- BTC_ADDRESS
- set_clipboard
- Not a btc address?

## Dangerous Indicators
- persistence: Creates or writes to a Windows startup registry key. Evidence: code_objects[4].name='add_to_registry'; code_objects[4].name='add_to_registry' offset=88 opname=LOAD_CONST argval='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
- self_replication: Copies the sample into a user profile location. Evidence: code_objects[5].name='replicate'; code_objects[5].name='replicate' offset=68 opname=LOAD_CONST argval='APPDATA'
- self_modification: Overwrites the original script after replication. Evidence: code_objects[6].name='self_destruct'; code_objects[6].name='self_destruct' offset=36 opname=LOAD_GLOBAL argval='SELF_DESTRUCT_MESSAGE'
- clipboard_hijacking: Reads clipboard content and replaces cryptocurrency-like text. Evidence: code_objects[1].name='__enter__'; code_objects[7].name='start'; code_objects[1].name='__enter__' offset=4 opname=LOAD_METHOD argval='OpenClipboard'; code_objects[7].name='start' offset=92 opname=LOAD_GLOBAL argval='BTC_ADDRESS'

## Behavioral Analysis
- Reads its own script and writes a copy into the APPDATA profile path. Where: code_objects[5].name='replicate'; code_objects[5].name='replicate' offset=68 opname=LOAD_CONST argval='APPDATA'.
- Creates or updates HKCU Run persistence so the copied script starts with Windows. Where: code_objects[4].name='add_to_registry'; code_objects[4].name='add_to_registry' offset=88 opname=LOAD_CONST argval='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'.
- Overwrites the original file with a removal message after installing the copied version. Where: code_objects[6].name='self_destruct'; code_objects[6].name='self_destruct' offset=36 opname=LOAD_GLOBAL argval='SELF_DESTRUCT_MESSAGE'.
- Loops over clipboard content, detects Bitcoin-address-like strings, and replaces them. Where: code_objects[7].name='start'; code_objects[7].name='start' offset=92 opname=LOAD_GLOBAL argval='BTC_ADDRESS'.

## MITRE ATT&CK Mapping
- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
- T1115 - Clipboard Data
- T1105/T1036 - Local payload staging and masquerading-like copy behavior

## Rationale
- Artifact Inspector Agent extracted 9 IOC-like values, 26 interesting strings, and 4 dangerous indicators.
- Final verdict normalized to classification=malware with confidence=high.
- Bytecode Reverser Agent findings were compiled into a final report with exact code object locations.
- Reads its own script and writes a copy into the APPDATA profile path. Where: code_objects[5].name='replicate'; code_objects[5].name='replicate' offset=68 opname=LOAD_CONST argval='APPDATA'.
- Creates or updates HKCU Run persistence so the copied script starts with Windows. Where: code_objects[4].name='add_to_registry'; code_objects[4].name='add_to_registry' offset=88 opname=LOAD_CONST argval='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'.

## Overall Capability
Reads its own script and writes a copy into the APPDATA profile path. Where: code_objects[5].name='replicate'; code_objects[5].name='replicate' offset=68 opname=LOAD_CONST argval='APPDATA'. Creates or updates HKCU Run persistence so the copied script starts with Windows. Where: code_objects[4].name='add_to_registry'; code_objects[4].name='add_to_registry' offset=88 opname=LOAD_CONST argval='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'. Overwrites the original file with a removal message after installing the copied version. Where: code_objects[6].name='self_destruct'; code_objects[6].name='self_destruct' offset=36 opname=LOAD_GLOBAL argval='SELF_DESTRUCT_MESSAGE'. Loops over clipboard content, detects Bitcoin-address-like strings, and replaces them. Where: code_objects[7].name='start'; code_objects[7].name='start' offset=92 opname=LOAD_GLOBAL argval='BTC_ADDRESS'.
