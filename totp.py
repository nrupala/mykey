# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""TOTP (RFC 6238) generation for entries that store a TOTP secret."""

import base64
import hashlib
import hmac
import struct
import time
import urllib.parse


def _decode_secret(secret: str) -> bytes:
    text = secret.strip()
    if text.lower().startswith("otpauth://"):
        parsed = urllib.parse.urlparse(text)
        params = urllib.parse.parse_qs(parsed.query)
        text = params.get("secret", [""])[0]
    text = text.replace(" ", "").upper()
    padding = "=" * (-len(text) % 8)
    return base64.b32decode(text + padding)


def totp_now(secret: str, at=None, period: int = 30, digits: int = 6) -> str:
    if at is None:
        at = time.time()
    counter = int(at // period)
    key = _decode_secret(secret)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)
