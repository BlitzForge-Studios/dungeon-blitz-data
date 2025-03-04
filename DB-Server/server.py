#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import hashlib
import time

HOST = '127.0.0.1'
PORT = 443

# Global karakter listesi
# Her kayıt: (name, class_name, level, computed, extra1, extra2, extra3, extra4, hair_color, skin_color, shirt_color, pant_color)
characters = []

# Flash policy dosyası
policy_response = b"""<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM="http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
  <allow-access-from domain="*" to-ports="443"/>
</cross-domain-policy>\x00"""

def send_packet(conn, packet, label):
    try:
        conn.sendall(packet)
        print(f"Sent {label}:", packet.hex())
    except Exception as e:
        print(f"Error sending {label}:", e)

def build_handshake_response(session_id):
    session_id_bytes = session_id.to_bytes(2, 'big')
    key = b"815bfb010cd7b1b4e6aa90abc7679028"
    challenge_hash = hashlib.md5(session_id_bytes + key).hexdigest()
    dummy_bytes = bytes.fromhex(challenge_hash[:12])  # ilk 6 byte
    payload = session_id_bytes + dummy_bytes
    header = struct.pack(">HH", 0x12, len(payload))
    return header + payload

def build_login_challenge(challenge_str):
    cbytes = challenge_str.encode('utf-8')
    payload = struct.pack(">H", len(cbytes)) + cbytes
    header = struct.pack(">HH", 0x13, len(payload))
    return header + payload

#
# ----------------------- BIT-PACKED OKUMA -----------------------
#

class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.bit_index = 0

    def read_bits(self, count: int) -> int:
        result = 0
        for _ in range(count):
            byte_index = self.bit_index // 8
            bit_offset = 7 - (self.bit_index % 8)
            if byte_index >= len(self.data):
                raise ValueError("Okunacak yeterli veri yok")
            bit = (self.data[byte_index] >> bit_offset) & 1
            result = (result << 1) | bit
            self.bit_index += 1
        return result

    def align_to_byte(self):
        remainder = self.bit_index % 8
        if remainder != 0:
            self.bit_index += (8 - remainder)

    def read_string(self) -> str:
        self.align_to_byte()
        length = self.read_bits(16)
        result_bytes = bytearray()
        for _ in range(length):
            result_bytes.append(self.read_bits(8))
        try:
            return result_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return result_bytes.decode('latin1')

    def read_method_4(self) -> int:
        n = self.read_bits(4)
        n = (n + 1) << 1
        return self.read_bits(n)

    def read_method_393(self) -> int:
        return self.read_bits(8)

    def read_method_6(self, bit_count: int) -> int:
        return self.read_bits(bit_count)

#
# ----------------------- BIT-PACKED YAZMA (karakter listesi 0x15 için) -----------------------
#

class BitBuffer:
    def __init__(self):
        self.bits = []

    def _append_bits(self, value, bit_count):
        for i in reversed(range(bit_count)):
            bit = (value >> i) & 1
            self.bits.append(bit)

    def write_utf_string(self, text):
        if text is None:
            text = ""
        length = len(text)
        self._append_bits((length >> 8) & 0xFF, 8)
        self._append_bits(length & 0xFF, 8)
        for ch in text:
            self._append_bits(ord(ch) & 0xFF, 8)

    def write_method_4(self, val):
        # Küçük değerler için minimum 4 bitlik alan kullanılıyor.
        n = val.bit_length()
        if n < 4:
            n = 4
        if n % 2 != 0:
            n += 1
        prefix = (n >> 1) - 1
        self._append_bits(prefix, 4)
        self._append_bits(val, n)

    def write_method_393(self, val):
        self._append_bits(val & 0xFF, 8)

    def write_method_6(self, val, bit_count):
        self._append_bits(val, bit_count)

    def write_method_13_string(self, text):
        length = len(text)
        self.write_method_4(length)
        for ch in text:
            self._append_bits(ord(ch) & 0xFF, 8)

    def to_bytes(self):
        while len(self.bits) % 8 != 0:
            self.bits.append(0)
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            b = 0
            for bit in self.bits[i:i+8]:
                b = (b << 1) | bit
            out.append(b)
        return bytes(out)

def build_login_character_list_bitpacked():
    buf = BitBuffer()
    user_id = 1
    max_chars = 9
    char_count = len(characters)
    buf.write_method_4(user_id)   # user_id=1, 8 bit olarak kodlanacak
    buf.write_method_393(max_chars)
    buf.write_method_393(char_count)
    for char in characters:
        name, class_name, level, *_ = char
        buf.write_utf_string(name)
        buf.write_utf_string(class_name)
        buf.write_method_6(level, 6)
    payload = buf.to_bytes()
    header = struct.pack(">HH", 0x15, len(payload))
    return header + payload

#
# ----------------------- OYUN İÇİ PAKETLER -----------------------
#

def build_enter_game_packet():
    # world_id, x, y, z, instance_id
    world_id = 1
    x = 100
    y = 200
    z = 0
    instance_id = 1
    payload = struct.pack(">HiiiH", world_id, x, y, z, instance_id)
    header = struct.pack(">HH", 0x1A, len(payload))
    return header + payload

def build_game_init_packet():
    # Daha fazla dummy veri ekleyerek world init paketini genişletiyoruz.
    map_id = 1
    char_id = 1
    start_x = 100
    start_y = 200
    dummy = 0  # Ekstra alan
    payload = struct.pack(">HHIII", map_id, char_id, start_x, start_y, dummy)
    header = struct.pack(">HH", 0x1B, len(payload))
    return header + payload

#
# ----------------------- SUNUCU ANA İŞLEMLERİ -----------------------
#

def handle_client(conn, addr):
    print("Connection from", addr)
    game_started = False
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            # Flash policy isteği kontrolü
            if b"<policy-file-request/>" in data:
                print("Flash policy request received. Sending policy XML.")
                send_packet(conn, policy_response, "policy response")
                continue

            hex_data = data.hex()
            print("Received raw data:", hex_data)

            if len(hex_data) < 4:
                continue

            try:
                pkt_type = int(hex_data[:4], 16)
            except ValueError:
                print("Error parsing packet type.")
                continue

            if pkt_type == 0x11:
                session_id = 0
                if len(hex_data) >= 12:
                    session_id = int(hex_data[8:12], 16)
                print(f"Got handshake packet (0x11), session ID = {session_id}")
                handshake = build_handshake_response(session_id)
                send_packet(conn, handshake, "handshake response (0x12)")
                time.sleep(0.1)
                challenge_packet = build_login_challenge("CHALLENGE")
                send_packet(conn, challenge_packet, "login challenge (0x13)")
                time.sleep(0.1)

            elif pkt_type == 0x13 or pkt_type == 0x14:
                print("Got authentication packet (0x13/0x14). Sending login character list (0x15).")
                pkt = build_login_character_list_bitpacked()
                send_packet(conn, pkt, "login character list (0x15)")
                time.sleep(0.1)

            elif pkt_type == 0x17:
                print("Got character creation packet (0x17). Parsing creation data...")
                payload = data[4:]
                try:
                    br = BitReader(payload)
                    name = br.read_string()
                    class_name = br.read_string()
                    computed = br.read_string()
                    extra1 = br.read_string()
                    extra2 = br.read_string()
                    extra3 = br.read_string()
                    extra4 = br.read_string()
                    hair_color = br.read_bits(24)
                    skin_color = br.read_bits(24)
                    shirt_color = br.read_bits(24)
                    pant_color = br.read_bits(24)
                except Exception as e:
                    print("Error parsing create character packet:", e)
                    continue

                print("Parsed Character Creation Packet:")
                print("  Name:     ", name)
                print("  ClassName:", class_name)
                print("  Extras:   ", [computed, extra1, extra2, extra3, extra4])
                print("  Colors:   ", [hair_color, skin_color, shirt_color, pant_color])
                new_char = (name, class_name, 1, computed, extra1, extra2, extra3, extra4,
                            hair_color, skin_color, shirt_color, pant_color)
                characters.append(new_char)
                print(f"Created new char: userID=1, name='{name}', class='{class_name}'")
                # Güncellenmiş karakter listesini gönderiyoruz.
                pkt = build_login_character_list_bitpacked()
                send_packet(conn, pkt, "updated login character list (0x15)")
                time.sleep(0.3)
                # Eğer oyun henüz başlamadıysa otomatik karakter seçimi ve oyun başlangıcı simülasyonu:
                if not game_started:
                    ack_pkt = struct.pack(">HH", 0x16, 0)
                    send_packet(conn, ack_pkt, "character select acknowledgment (0x16)")
                    time.sleep(0.5)
                    enter_packet = build_enter_game_packet()
                    send_packet(conn, enter_packet, "enter game packet (0x1A)")
                    time.sleep(0.5)
                    init_pkt = build_game_init_packet()
                    send_packet(conn, init_pkt, "game init packet (0x1B)")
                    time.sleep(0.3)
                    game_started = True

            elif pkt_type == 0x16:
                print("Got character select packet (0x16). Processing selection...")
                if not game_started:
                    ack_pkt = struct.pack(">HH", 0x16, 0)
                    send_packet(conn, ack_pkt, "character select acknowledgment (0x16)")
                    time.sleep(0.5)
                    enter_packet = build_enter_game_packet()
                    send_packet(conn, enter_packet, "enter game packet (0x1A)")
                    time.sleep(0.5)
                    init_pkt = build_game_init_packet()
                    send_packet(conn, init_pkt, "game init packet (0x1B)")
                    time.sleep(0.3)
                    game_started = True
                else:
                    print("Game already started, ignoring extra character select packet.")

            elif pkt_type == 0x19:
                print("Got packet type 0x19. Acknowledging...")
                pkt = struct.pack(">HH", 0x19, 0)
                send_packet(conn, pkt, "0x19 acknowledgment")
                time.sleep(0.1)

            elif pkt_type == 0x7C:
                print("Received packet type 0x7C (Appearance/cue update). Sending empty response.")
                pkt = struct.pack(">HH", 0x7C, 0)
                send_packet(conn, pkt, "0x7C response")
                time.sleep(0.1)

            else:
                print(f"Unhandled packet type: 0x{pkt_type:02X}")

    except Exception as e:
        print("Error:", e)
    finally:
        conn.close()
        print("Client disconnected.")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"Listening on {HOST}:{PORT} (NO SSL)...")
        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)

if __name__ == "__main__":
    start_server()
