import struct

def build_enter_game_packet(character):
    world_id = 1  # Harita ID'si
    x, y, z = 100, 200, 0  # Başlangıç pozisyonu
    instance_id = 1
    payload = struct.pack(">HiiiH", world_id, x, y, z, instance_id)
    header = struct.pack(">HH", 0x1A, len(payload))
    return header + payload