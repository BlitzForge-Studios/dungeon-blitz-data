from ..config import characters
from ..classes.bit_buffer import BitBuffer
import struct

def build_login_character_list_bitpacked():
    buf = BitBuffer()
    buf.write_bits(len(characters), 8)  # Karakter sayısı
    for char in characters:
        buf.write_utf_string(char[0])  # İsim
        buf.write_utf_string(char[1])  # Sınıf
        buf.write_bits(char[2], 32)    # Seviye
    payload = buf.to_bytes()
    return struct.pack(">HH", 0x15, len(payload)) + payload