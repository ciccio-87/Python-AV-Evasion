# Python-AV-Evasion
Execute shellcode and evade AV detection with python.

Some old and unmantained (but still working, it seems) python scripts
to execute a shellcode (shell.py and winshell.py) and evade AVs.

1. shell and winshell do straightforward shellcode execution 
on Linux and Windows respectively.
2. generate.py does instead generate python scripts (similar to the former ones)
from a given shellcode (read from a file or piped in by msfpayload/msfvenom),
optionally adding an Hyperion/Veil/[SympleCrypter](https://github.com/ciccio-87/SimpleCrypter) like AV evasion.
The generated script could be very well used with PyInstaller or similar,
automation for this is not implemented though.

<s>For real world usage DES is probably totally outdated, it should be replaced
with AES (or 3DES at least).</s> Don't mind it, it's already using AES, I was confusing it with SimpleCrypter
