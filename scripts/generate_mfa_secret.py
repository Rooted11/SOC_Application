#!/usr/bin/env python3
"""
Generate a TOTP secret and otpauth URI for authenticator apps.
"""

from __future__ import annotations

import argparse
import base64
import secrets
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description="Generate an Ataraxia TOTP MFA secret")
    parser.add_argument("--account", default="soc_operator", help="Account label shown in the authenticator app")
    parser.add_argument("--issuer", default="Ataraxia", help="Issuer label shown in the authenticator app")
    args = parser.parse_args()

    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    label = urllib.parse.quote(f"{args.issuer}:{args.account}")
    issuer = urllib.parse.quote(args.issuer)
    otp_uri = (
        f"otpauth://totp/{label}?secret={secret}&issuer={issuer}"
        "&algorithm=SHA1&digits=6&period=30"
    )

    print(f"AUTH_TOTP_SECRET={secret}")
    print(f"otpauth_uri={otp_uri}")


if __name__ == "__main__":
    main()
