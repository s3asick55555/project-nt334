# Verdict
- Classification: MALWARE
- Confidence: high

# Summary
The report is consistent with malware: Reads its own script and writes a copy into the APPDATA profile path. Where: code_objects[5].name='replicate'; code_objects[5].name='replicate' offset=68 opname=LOAD_CONST argval='APPDATA'. Key signals include suspicious_import, suspicious_import, suspicious_import, persistence.

## Key IOCs
- you have been infected by btc clipper malware
- File contents have been deleted. 
 To remove the btc clipper, Delete it from %APPDATA% and delete it from Startup in the Registry Editor
- ^(bc1|[13])[a-zA-HJ-NP-Z0-9]+
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
- btcClip.py
- subprocess
- ctypes
- winreg
- BTC_ADDRESS
- you have been infected by btc clipper malware
- File contents have been deleted. 
 To remove the btc clipper, Delete it from %APPDATA% and delete it from Startup in the Registry Editor
- Clipboard
- ^(bc1|[13])[a-zA-HJ-NP-Z0-9]+
- set_clipboard
- Clipboard init
- GetClipboardData
- OpenClipboard
- IsClipboardFormatAvailable
- CloseClipboard
- APPDATA
- LOCALAPPDATA
- \Programs\Python\Launcher\py.exe
- HKEY_CURRENT_USER
- SOFTWARE\Microsoft\Windows\CurrentVersion\Run

## Dangerous Indicators
- suspicious_import: Can spawn external commands or child processes. Evidence: modules[2].name='subprocess', path='C:\\Users\\Sherry\\AppData\\Local\\Programs\\Python\\Python38\\lib\\subprocess.py'
- suspicious_import: Windows API access and clipboard manipulation are possible through ctypes. Evidence: modules[3].name='ctypes', path='C:\\Users\\Sherry\\AppData\\Local\\Programs\\Python\\Python38\\lib\\ctypes\\__init__.py'
- suspicious_import: Can create or modify Windows registry persistence keys. Evidence: modules[5].name='winreg'
- persistence: Creates or writes to a Windows startup registry key. Evidence: code_objects[4].name='add_to_registry'; code_objects[4].name='add_to_registry' offset=88 opname=LOAD_CONST argval='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
- self_replication: Copies the sample into a user profile location. Evidence: code_objects[5].name='replicate'; code_objects[5].name='replicate' offset=68 opname=LOAD_CONST argval='APPDATA'
- self_modification: Overwrites the original script after replication. Evidence: code_objects[6].name='self_destruct'; code_objects[6].name='self_destruct' offset=36 opname=LOAD_GLOBAL argval='SELF_DESTRUCT_MESSAGE'
- clipboard_hijacking: Reads clipboard content and replaces cryptocurrency-like text. Evidence: code_objects[1].name='__enter__'; code_objects[7].name='start'; code_objects[1].name='__enter__' offset=4 opname=LOAD_METHOD argval='OpenClipboard'; code_objects[7].name='start' offset=92 opname=LOAD_GLOBAL argval='BTC_ADDRESS'

## Behavioral Analysis
- Reads its own script and writes a copy into the APPDATA profile path. Where: code_objects[5].name='replicate'; code_objects[5].name='replicate' offset=68 opname=LOAD_CONST argval='APPDATA'.
- Creates or updates HKCU Run persistence so the copied script starts with Windows. Where: code_objects[4].name='add_to_registry'; code_objects[4].name='add_to_registry' offset=88 opname=LOAD_CONST argval='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'.
- Overwrites the original file with a removal message after installing the copied version. Where: code_objects[6].name='self_destruct'; code_objects[6].name='self_destruct' offset=36 opname=LOAD_GLOBAL argval='SELF_DESTRUCT_MESSAGE'.
- Loops over clipboard content, detects Bitcoin-address-like strings, and replaces them. Where: code_objects[7].name='start'; code_objects[7].name='start' offset=92 opname=LOAD_GLOBAL argval='BTC_ADDRESS'.
- Uses ctypes to call Windows user32/kernel32 clipboard APIs directly. Where: code_objects[0].name='__init__'; code_objects[0].name='__init__' offset=12 opname=LOAD_ATTR argval='windll'.

## MITRE ATT&CK Mapping
- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
- T1115 - Clipboard Data
- T1105/T1036 - Local payload staging and masquerading-like copy behavior

## Rationale
- 7 dangerous indicators were extracted from concrete report evidence.
- 12 IOC-like values were extracted.
- Bytecode-level function names and constants support the reconstructed behavior.

## Overall Capability
Reads its own script and writes a copy into the APPDATA profile path. Where: code_objects[5].name='replicate'; code_objects[5].name='replicate' offset=68 opname=LOAD_CONST argval='APPDATA'. Creates or updates HKCU Run persistence so the copied script starts with Windows. Where: code_objects[4].name='add_to_registry'; code_objects[4].name='add_to_registry' offset=88 opname=LOAD_CONST argval='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'. Overwrites the original file with a removal message after installing the copied version. Where: code_objects[6].name='self_destruct'; code_objects[6].name='self_destruct' offset=36 opname=LOAD_GLOBAL argval='SELF_DESTRUCT_MESSAGE'. Loops over clipboard content, detects Bitcoin-address-like strings, and replaces them. Where: code_objects[7].name='start'; code_objects[7].name='start' offset=92 opname=LOAD_GLOBAL argval='BTC_ADDRESS'. Uses ctypes to call Windows user32/kernel32 clipboard APIs directly. Where: code_objects[0].name='__init__'; code_objects[0].name='__init__' offset=12 opname=LOAD_ATTR argval='windll'.
