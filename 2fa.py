#!/usr/bin/env python

"""
2fa - Pure Python Two-Factor Authentication agent based on github.com/rsc/2fa
MIT License - Copyright (c) 2024 c4ffein
Interoperable with github.com/rsc/2fa but fully reimplemented in pure Python
"""

from base64 import b32decode
from datetime import datetime
from hashlib import sha1
from hmac import new as new_hmac
from pathlib import Path
from platform import system as platform_system
from string import ascii_letters, digits
from subprocess import run as subprocess_run
from sys import argv, stderr
from typing import Dict, Optional

PLATFORM = platform_system()
COUNTER_LEN = 20


def clip(s: str):
    command = {"Darwin": "pbcopy", "Linux": "wl-copy"}.get(PLATFORM)
    if command is None:
        raise NotImplementedError(f"Clipboard not available for platform {PLATFORM}")
    try:
        subprocess_run(command, text=True, input=s)
    except FileNotFoundError:
        raise NotImplementedError(f"Clipboard command {command} not found for platform {PLATFORM}") from None


class TwoFAException(Exception):
    pass


usage_block = """
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
"""


def usage():
    print(usage_block, file=stderr)
    exit(-2)


def decode_key(key: str) -> bytes:
    return b32decode(key.upper())


class Key:
    def __init__(self):
        self.raw, self.digits, self.offset = b"", 0, 0  # offset is offset of counter


class Keychain:
    def __init__(self, file: str, data=b"", keys: Optional[Dict[str, Key]] = None):
        self.file, self.data, self.keys = file, data, {} if keys is None else keys

    def list(self):
        print("\n".join(sorted(self.keys)))

    def add(self, name: str, digits_7=False, digits_8=False, hotp_mode=False):
        if digits_7 and digits_8:
            raise TwoFAException("cannot use -7 and -8 together")
        size = 8 if digits_8 else 7 if digits_7 else 6

        try:
            text = input(f"2fa key for {name}: ")
        except Exception as e:
            raise TwoFAException(f"error reading key: {e}") from e
        key = "".join(c for c in text.upper() if not c.isspace())
        try:
            decode_key(key)
        except Exception as e:
            raise TwoFAException(f"invalid key: {e}") from e
        try:
            Path(self.file).touch(0o600)
            Path(self.file).chmod(0o600)  # in case file already exists with wrong rights
            with Path(self.file).open("a") as f:
                try:
                    f.write(f"{name} {size} {key}" + (f" {'0' * 20}" if hotp_mode else "") + "\n")
                except Exception as e:
                    raise TwoFAException(f"adding key: {e}") from e
        except TwoFAException as e:
            raise e
        except Exception as e:
            raise TwoFAException(f"opening keychain: {e}") from e

    def code(self, name: str) -> str:
        k = self.keys.get(name)
        if not k:
            raise TwoFAException(f"no such key {name}")
        if k.offset != 0:
            try:
                n = int(self.data[k.offset : k.offset + COUNTER_LEN]) + 1
            except Exception as e:
                raise TwoFAException(
                    f"malformed key counter for {name} {self.data[k.offset:k.offset+COUNTER_LEN]}"
                ) from e
            code_value = hotp(k.raw, n, k.digits)
            try:
                with Path(self.file).open("r+b") as f:
                    try:
                        f.seek(k.offset)
                        f.write(str(n).zfill(COUNTER_LEN).encode("ascii"))
                    except Exception as e:
                        raise TwoFAException(f"updating keychain: {e}") from e
            except TwoFAException as e:
                raise e
            except Exception as e:
                raise TwoFAException(f"opening/writing keychain: {e}") from e
        else:
            code_value = totp(k.raw, datetime.now(), k.digits)  # Time-based key.
        return str(code_value).zfill(k.digits)

    def show(self, name: str, do_clip=False):
        code = self.code(name)
        if do_clip:
            clip(code)
        print(f"{code}")

    def show_all(self):
        computed_max = max([0, *(k.digits for k in self.keys.values())])
        for name, k in sorted(self.keys.items()):
            print(f"{(self.code(name) if k.offset == 0 else '-' * k.digits).ljust(computed_max)} {name}")


def read_keychain(file: str) -> Keychain:
    keychain = Keychain(file=file)
    try:
        with Path(file).open("rb") as f:
            keychain.data = f.read()
    except FileNotFoundError:
        return keychain
    except Exception as e:
        raise TwoFAException(f"opening/reading keychain: {e}") from e
    lines = keychain.data.split(b"\n")
    offset = 0
    for lineno, line in enumerate(lines):
        offset += len(line) + 1  # Account for non-registered "\n"
        f = line.split(b" ")
        if len(f) == 1 and len(f[0]) == 0:
            continue
        if len(f) >= 3 and len(f[1]) == 1 and 6 <= int(f[1]) <= 8:
            key = Key()
            name = f[0].decode("ascii")
            key.digits = int(f[1])
            try:
                raw = decode_key(f[2])
            except Exception:
                print(f"{file}:{lineno + 1}: malformed key", file=stderr)
                continue
            key.raw = raw
            if len(f) == 3:
                keychain.keys[name] = key
            elif len(f) == 4 and len(f[3]) == COUNTER_LEN:
                try:
                    int(f[3])
                except Exception:
                    continue  # Invalid counter
                key.offset = offset - COUNTER_LEN - 1  # Account for non-registered "\n"
                keychain.keys[name] = key
    return keychain


def hotp(key: bytes, counter: int, digits: int) -> int:
    digest = new_hmac(key, counter.to_bytes(8, "big"), sha1).digest()
    v = int.from_bytes(digest[digest[-1] & 0x0F :][:4], "big", signed=False) & 0x7FFFFFFF
    return v % pow(10, min(digits, 8))


def totp(key: bytes, t: datetime, digits: int):
    return hotp(key, int(t.timestamp()) // 30, digits)


def main():
    flags_values = {k: False for k in ["add", "list", "hotp", "7", "8", "clip"]}
    for flag in (n for n in argv[1:] if n.startswith("-")):
        if flag[1:] not in flags_values:
            usage()  # TODO : raise TwoFAException(f"unknown option: {flag}") and catch globally as separate, handle it
        flags_values[flag[1:]] = True
    flags_count = sum(1 for v in flags_values.values() if v)
    args = [n for n in argv[1:] if not n.startswith("-")]
    if len(args) > 1:
        usage()
    keyname = args[0] if len(args) == 1 else None
    if keyname is not None and any(c not in ascii_letters + digits + "-/=" for c in keyname):
        raise TwoFAException("name must only be composed of [A-Z][a-z][0-9]-/=")
    k = read_keychain(Path.home() / ".2fa")
    if keyname is None:
        (usage if flags_count > 1 else k.list if flags_values["list"] else usage if flags_count == 1 else k.show_all)()
    elif flags_count == 0:
        k.show(keyname)
    elif flags_values["clip"]:
        (usage if flags_count != 1 else lambda: k.show(keyname, do_clip=True))()
    elif not flags_values["add"]:
        usage()
    else:
        k.add(keyname, digits_7=flags_values["7"], digits_8=flags_values["8"], hotp_mode=flags_values["hotp"])


if __name__ == "__main__":
    main()
