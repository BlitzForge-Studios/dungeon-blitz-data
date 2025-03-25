from ..classes.bit_buffer import BitBuffer
import struct

def send_map_data(conn):
    map_data = "<MapData><Tiles>TileDataHere</Tiles><NPCs>NPCDataHere</NPCs></MapData>"
    buf = BitBuffer()
    buf.write_utf_string(map_data)
    payload = buf.to_bytes()
    header = struct.pack(">HH", 0x1C, len(payload))
    conn.sendall(header + payload)
    print("Sent map data (0x1C):", (header + payload).hex())