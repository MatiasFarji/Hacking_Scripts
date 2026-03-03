#!/usr/bin/env python3

"""
Burp Collaborator - Unified Key Derivation & Payload Generation
===============================================================
Reverse engineered from version 2025.12.5: burp.Zp8g, net.portswigger.{Zvkj, Zk7, Zbg, Zyb, Zp7, Zwh, Z_3}

TWO MODES:
  1. generate  — generate random 32-byte project key, derive everything
  2. from-biid — receive a captured base64 biid, derive everything from it

DERIVATION CHAIN (both modes share the same root):
  Zpwv (32 bytes, project key)
    ├── biid   = Base64(zpwv)                    [Zwn.Zf → new String → Z_3.Zw]
    └── secret = SHA-1(zpwv) → base36 → 22 chars [Zvkj.ZH]
                     └── subdomain = ZC + sep + stream_encrypt(secret+counter+clientPart)
"""

import hashlib
import base64
import os
import sys
import argparse

# ── Constants ──────────────────────────────────────────────────────────────────

CHARSET = 'abcdefghijklmnopqrstuvwxyz0123456789'   # Zvkj charset, ZU=36

# ASCII → charset position lookup (Zyb stream cipher)
_CHARSET_POS = [-1] * 256
for _i, _c in enumerate(CHARSET):
    _CHARSET_POS[ord(_c)] = _i

SERVER = "oastify.com"
POLLING_SERVER = "polling.oastify.com"


# ── Zp7 — checksum & separator ────────────────────────────────────────────────

def _zp7_checksum(s: str) -> str:
    """Zp7.ZU(String): CHARSET[sum(ord(c) for c in s) % 36]"""
    return CHARSET[sum(ord(c) for c in s) % 36]

def _zp7_separator(b0: int, b1: int) -> str:
    """Zp7.ZK: separator char from two key bytes (signed addition mod 36)"""
    b0s = b0 if b0 < 128 else b0 - 256
    b1s = b1 if b1 < 128 else b1 - 256
    return CHARSET[(b0s + b1s) % 36]


# ── Zvkj — secret derivation ──────────────────────────────────────────────────

def _zvkj_base36(data: bytes) -> str:
    """Zvkj.Zq: treat bytes as big-endian BigInteger, encode base-36."""
    n = int.from_bytes(data, 'big')
    if n == 0:
        return CHARSET[0]
    digits = []
    while n > 0:
        digits.append(CHARSET[n % 36])
        n //= 36
    return ''.join(reversed(digits))

def derive_secret(zpwv: bytes) -> str:
    """
    Zvkj.ZH(byte[]):
      SHA-1(zpwv) → base-36 BigInt → first 20 chars
      → split 10+10 → append checksum to each half → 22-char secret
    """
    digest  = hashlib.sha1(zpwv).digest()
    enc     = _zvkj_base36(digest)
    first20 = enc[:20]
    h1, h2  = first20[:10], first20[10:20]
    return h1 + _zp7_checksum(h1) + h2 + _zp7_checksum(h2)


# ── Z_3.Zw — URL encoder ──────────────────────────────────────────────────────

def _z3_url_encode(s: str) -> str:
    """
    Z_3.Zw(String): URL-encode.
    Unreserved (pass-through): 0-9, @A-Z, a-z, * - . _
    Space → '+', everything else → %xx (lowercase hex)
    """
    out = []
    for ch in s:
        c = ord(ch)
        if c == 32:
            out.append('+')
        elif (48 <= c <= 57) or (64 <= c <= 90) or (97 <= c <= 122) or c in (42, 45, 46, 95):
            out.append(ch)
        else:
            out.append('%' + ('00' + format(c, 'x'))[-2:])
    return ''.join(out)


# ── biid derivation ───────────────────────────────────────────────────────────

def derive_biid_raw(zpwv: bytes) -> str:
    """Zwn.Zf → new String: Base64(zpwv) as Latin-1 string."""
    return base64.b64encode(zpwv).decode('latin-1')

def derive_biid_url(zpwv: bytes) -> str:
    """Z_3.Zw(Base64(zpwv)): URL-encoded form used in polling path."""
    return _z3_url_encode(derive_biid_raw(zpwv))


# ── Zyb — stream cipher ───────────────────────────────────────────────────────

def _zyb_encrypt(key_bytes: bytes, plain: str) -> str:
    """
    Zyb.ZY: 2-byte rotating stream cipher.
    enc_pos = (pos(plain_char) + pos(key[i%2])) % 36
    key updated with ENCRYPTED byte after each step (CBC-style feedback).
    """
    key = [key_bytes[0] & 0xff, key_bytes[1] & 0xff]
    kt  = 0
    out = []
    for ch in plain:
        cb    = ord(ch) & 0xff
        p_p   = _CHARSET_POS[cb]   if cb < 256 else -1
        p_k   = _CHARSET_POS[key[kt]] if key[kt] < 256 else -1
        if p_p == -1 or p_k == -1:
            enc_ch = ch
            enc_b  = cb
        else:
            enc_ch = CHARSET[(p_p + p_k) % 36]
            enc_b  = ord(enc_ch)
        out.append(enc_ch)
        key[kt] = enc_b
        kt ^= 1
    return ''.join(out)


# ── Subdomain generation ──────────────────────────────────────────────────────

def derive_subdomain(secret: str, client_part: str,
                     zc_bytes: bytes = None, counter: int = 1) -> tuple:
    """
    Zk7.toString():
      plain     = secret + hex(counter) + 'g' + client_part + 'z'
      encrypted = zyb_encrypt(ZC, plain)        [29 chars]
      separator = zp7_separator(ZC[0], ZC[1])   [1 char]
      subdomain = chr(ZC[0]) + chr(ZC[1]) + separator + encrypted  [32 chars]

    Returns (subdomain, zc_bytes_used).
    ZC bytes are two random charset chars if not supplied.
    """
    if zc_bytes is None:
        zc_bytes = bytes([
            ord(CHARSET[int.from_bytes(os.urandom(1), 'big') % 36]),
            ord(CHARSET[int.from_bytes(os.urandom(1), 'big') % 36]),
        ])
    plain     = secret + format(counter, 'x') + 'g' + client_part + 'z'
    encrypted = _zyb_encrypt(zc_bytes, plain)
    separator = _zp7_separator(zc_bytes[0], zc_bytes[1])
    subdomain = chr(zc_bytes[0]) + chr(zc_bytes[1]) + separator + encrypted
    return subdomain, zc_bytes


# ── Core output printer ───────────────────────────────────────────────────────

def print_all(zpwv: bytes, client_part: str = "1y0y",
              zc_bytes: bytes = None, counter: int = 1):
    """Derive and echo every value from zpwv."""
    secret    = derive_secret(zpwv)
    biid_raw  = derive_biid_raw(zpwv)
    biid_url  = derive_biid_url(zpwv)
    subdomain, zc_used = derive_subdomain(secret, client_part, zc_bytes, counter)
    full_domain = f"{subdomain}.{SERVER}"

    print()
    print("━" * 62)
    print("  BURP COLLABORATOR — DERIVED VALUES")
    print("━" * 62)

    print("\n── Project Key (Zpwv) ──────────────────────────────────────")
    print(f"  hex     : {zpwv.hex()}")
    print(f"  bytes   : {list(zpwv)}")
    print(f"  b64     : {base64.b64encode(zpwv).decode()}")

    print("\n── Secret (Zvkj.ZN, 22 chars) ──────────────────────────────")
    print(f"  value   : {secret}")

    print("\n── BIID ────────────────────────────────────────────────────")
    print(f"  raw     : {biid_raw}")
    print(f"  url-enc : {biid_url}")
    print(f"  path    : /burpresults?biid={biid_url}")

    print("\n── Subdomain ───────────────────────────────────────────────")
    print(f"  ZC bytes    : {list(zc_used)}  ('{chr(zc_used[0])}{chr(zc_used[1])}')")
    print(f"  client_part : {client_part}")
    print(f"  counter     : {counter}")
    print(f"  subdomain   : {subdomain}")
    print(f"  full domain : {full_domain}")

    print("\n── Polling Request ─────────────────────────────────────────")
    print(f"  HEAD /burpresults?biid={biid_url} HTTP/1.1")
    print(f"  Host: {POLLING_SERVER}")

    print("\n── DNS Interaction Hostname ────────────────────────────────")
    print(f"  {full_domain}")
    print()
    print("━" * 62)
    print()


# ── Mode 1: generate ──────────────────────────────────────────────────────────

def mode_generate(client_part: str = "1y0y"):
    """Generate a fresh random 32-byte project key and derive everything."""
    print(f"\n[MODE] generate — fresh random project key")
    zpwv = os.urandom(32)
    print_all(zpwv, client_part=client_part)


# ── Mode 2: from-biid ─────────────────────────────────────────────────────────

def mode_from_biid(biid_b64: str, client_part: str = "1y0y"):
    """
    Receive a captured base64 biid, recover zpwv = Base64.decode(biid),
    then derive everything.
    """
    print(f"\n[MODE] from-biid — recovering from captured biid")

    # normalise URL-encoded form
    normalised = biid_b64 \
        .replace('%3d', '=').replace('%3D', '=') \
        .replace('%2f', '/').replace('%2F', '/') \
        .replace('%2b', '+').replace('%2B', '+')

    try:
        zpwv = base64.b64decode(normalised)
    except Exception as e:
        print(f"\n[ERROR] cannot base64-decode biid: {e}")
        sys.exit(1)

    if len(zpwv) != 32:
        print(f"\n[WARNING] decoded zpwv is {len(zpwv)} bytes (expected 32)")

    print_all(zpwv, client_part=client_part)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Burp Collaborator key derivation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Mode 1 – generate fresh key, derive everything
  python burp_collab_biid_subdomain_generator.py generate

  # Mode 1 – with custom client_part
  python burp_collab_biid_subdomain_generator.py generate --client-part ab1c

  # Mode 2 – recover from captured biid
  python burp_collab_biid_subdomain_generator.py from-biid "9ItYtH79/QoijmN+PHKVo0NtbMqOo+SnhCazlHVWbLQ="

  # Mode 2 – URL-encoded biid also accepted
  python burp_collab_biid_subdomain_generator.py from-biid "9ItYtH79%2fQoijmN%2bPHKVo0NtbMqOo%2bSnhCazlHVWbLQ%3d"
        """
    )
    sub = parser.add_subparsers(dest='mode', required=True)

    # generate
    p_gen = sub.add_parser('generate', help='generate fresh random project key')
    p_gen.add_argument('--client-part', default='1y0y',
                       help='client_part string (default: 1y0y)')

    # from-biid
    p_biid = sub.add_parser('from-biid', help='derive from captured base64 biid')
    p_biid.add_argument('biid', help='base64 biid (raw or URL-encoded)')
    p_biid.add_argument('--client-part', default='1y0y',
                        help='client_part string (default: 1y0y)')

    args = parser.parse_args()

    if args.mode == 'generate':
        mode_generate(client_part=args.client_part)
    elif args.mode == 'from-biid':
        mode_from_biid(args.biid, client_part=args.client_part)


if __name__ == '__main__':
    main()