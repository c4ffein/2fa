# fv
KISS Python 2fa cli
- Interoperable with [rsc/2fa](https://github.com/rsc/2fa), you can see this project as a Python rewrite

## WARNING
**I don't recommand using this as-is.** This a PoC, usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
- **Probably doesn't work for now with Windows paths**

## Help
```
2fa - 2 factor auth
===================
~/.2fa => will contain the unencrypted secrets, compatible with https://github.com/rsc/2fa
===================
- 2fa -add [-7] [-8] [-hotp] keyname  ==> add a key to the keychain, reads key from input
- 2fa -list                           ==> list keys without showing all generated OTPs
- 2fa [-clip] keyname                 ==> show a specific key with its generated OTP
===================
[-hotp] setup the key to generate counter-based (HOTP) instead of time-based (TOTP) auth codes
[-7]    setup the key to generate 7-digits instead of 6-digits auth codes
[-8]    setup the key to generate 8-digits instead of 6-digits auth codes
[-clip] also copies the code to the system clipboard
===================
2fa keys are case-insensitive [A-Z][2-7]
With no arguments, 2fa show codes for all time-based keys
TOTP auth codes are derived from a hash of the key and the current time
One-minute accuracy from the system clock is expected
===================
WARNING: The HOTP mechanism should be improved by editing a copy of the .2fa file
         The current implementation is similar to the original one from rsc/2fa but should be improved
```
