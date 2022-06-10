#!/usr/bin/env python

import sys

SLOT_ID = 2
NEW_ACC = '000000000000' # Set this to what you want, but don't lose it. You'll need this to change a slot's configuration.
OLD_ACC = ''
APP_ID = 'A0000005272001' # Don't change this if you want Yubikey compatibility...

if len(NEW_ACC) != 12:
    print('Invalid new access code: should be 6 bytes')
    sys.exit(1)

if len(OLD_ACC) not in [0, 12]:
    print('Invalid old access code: should be either six or zero bytes')
    sys.exit(1)

with open(0, 'rb') as f:
    raw_key = f.read(20)

if len(raw_key) < 20:
    print('Failed to read 20 bytes of key material from standard input')
    sys.exit(1)

hex_key = raw_key.hex().upper()
key = hex_key[:32] # 16 bytes of key first
uid = hex_key[32:] + '0000' # ... and then four bytes of UID, padded out to a six-byte UID string

assert len(key) == 32
assert len(uid) == 12

s = '00' * 16 # Fixed bytes, not used
s += uid # Four bytes of the key, remaining two unused
s += key # Sixteen bytes of key
s += NEW_ACC # Access code
s += '00' # Fixed byte, not used
s += '00' # Extflags, not used
s += '40' # Tktflags, contains magic setting for challenge-response mode
s += '260000' # Cfgflags, contains magic settings for HMAC
s += '00' * 2 # CRC, not used
s += OLD_ACC # Access code previously set

if len(s) != 104 + len(OLD_ACC):
    print('Invalid overall ADPU length')
    sys.exit(1)

len_encoded = '34'
if OLD_ACC != '':
    len_encoded = '3A'

slot_encoding = '01'
if SLOT_ID == 2:
    slot_encoding = '03'

print('opensc-tool -s %s -s %s' % ('00A4040007' + APP_ID + '00', '0001' + slot_encoding + '00' + len_encoded + s))
