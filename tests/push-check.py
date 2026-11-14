# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Checks the relay's Web Push encryption (RFC 8291) against an independent
implementation, the http_ece library used by pywebpush:
  PUSH_VECTOR=/tmp/v.json go test ./cmd/lullwire-relay -run PushVectorFile
  python3 tests/push-check.py /tmp/v.json          (pip install http_ece)"""
import base64, json, sys
import http_ece
from cryptography.hazmat.primitives.asymmetric import ec

d = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
v = json.load(open(sys.argv[1]))
priv = ec.derive_private_key(int.from_bytes(d(v['priv']), 'big'), ec.SECP256R1())
plain = http_ece.decrypt(d(v['body']), private_key=priv, dh=None, auth_secret=d(v['auth']), version='aes128gcm')
assert plain == b'When I grow up, I want to be a watermelon', plain
print('  ok   push encryption decrypts with http_ece (RFC 8291):', plain.decode())
