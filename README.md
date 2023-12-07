# Xerox Decryptor

Here's a little tool that extracts hardcoded encryption keys from the Xerox WorkCentre firmware using Binary Ninja's API.

It will try and recursively find a binary in the firmware; this is probably not efficient and I cannot guarantee it will work all the time. Luckily the resources I used to write this up cover that entire process. 

I want to automatically decrypt encrypted strings, but it's time consuming

## Usage
```
usage: xeroxDecrypter.py [-h] -f FILE -o OUTPUT [-s STRING] [-b BINARY]

Xerox WorkCentre Encryption Key Extractor

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to the firmware *.zip file that will be parsed.
  -o OUTPUT, --output OUTPUT
                        Directory to save the createClone file to.
  -s STRING, --string STRING
                        String to be decrypted.
  -b BINARY, --binary BINARY
                        createClone binary file
```

Example usage might look like this...

```
$ ./xeroxDecrypter.py -f /tmp/cloning/WorkCentre_7970-system-sw075.200.013.29000.zip -o /tmp/test/
[+] Converting .DLM file to .tar: /tmp/WorkCentre_7970-system-sw075.200.013.29000/WorkCentre_7970-system-sw075.200.013.29000/WorkCentre_7970-system-sw07520001329000/dlms/WorkCentre7970/WorkCentre_7970-system-sw#07520001329000#ENG_MOD.DLM
[+] 'createClone' copied to: /tmp/test/createClone
[*] Parsing /tmp/cloning/test/createClone
[*] This will take a while...
[+] Function sub_10040418 calls esscrypto_encryptString
[+] Encryption Key: 6RBWptBGmbPDbm34
[+] Encryption Key (Hex): 36524257707442476d625044626d3334
```

## References
- https://blog.compass-security.com/2021/05/printer-tricks-episode-ii-attack-of-the-clones/
- https://zolder.io/decrypt-passwords-from-xerox-workcentre-config-backups/
- https://airbus-seclab.github.io/xerox/INFILTRATE2020-RIGO-Xerox-final.pdf
