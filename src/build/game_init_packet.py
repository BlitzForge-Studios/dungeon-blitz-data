import struct
from ..config import characters

def build_game_init_packet(character):
    map_id = 1
    char_id = characters.index(character) + 1  # Karakterin ID'si
    start_x, start_y = 100, 200  # Pozisyon
    payload = struct.pack(">HHII", map_id, char_id, start_x, start_y)
    header = struct.pack(">HH", 0x1B, len(payload))
    return header + payload