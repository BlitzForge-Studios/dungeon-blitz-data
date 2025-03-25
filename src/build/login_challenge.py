import struct
from ..classes.bit_buffer import BitBuffer

def build_login_challenge(challenge_str):
    buf = BitBuffer()
    buf.write_utf_string(challenge_str)
    payload = buf.to_bytes()
    return struct.pack(">HH", 0x13, len(payload)) + payload
