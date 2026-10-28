"""
Legacy compatibility wrapper for dschuetz_oplib.
Functions here redirect to modern Python 3 implementations in recover_op.crypto.
"""
import base64
import binascii
from recover_op.crypto import (
    b64url_decode as opb64d,
    b64url_encode as opb64e,
    compute_2skd,
    dec_aes_gcm,
)

DEBUG = 0


def p_debug(out):
    if DEBUG:
        print(out)


def p_str(title, data):
    dat_str = f"{data}"
    lines = dat_str.split("\n")
    p_debug(f"{title:<20} {lines[0]}")
    for l in lines[1:]:
        p_debug(f"{'':20} {l}")


def dump_line(dat):
    l_raw = binascii.a2b_hex(dat.replace(" ", ""))
    asc = "".join(chr(c) if 32 <= c <= 126 else "." for c in l_raw)
    return f"{dat:<40} {asc}"
