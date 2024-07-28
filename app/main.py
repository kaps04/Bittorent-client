import hashlib
import json
import math
import sys
import socket
import bencodepy
import requests
Expand 136 lines
            raw_peers = decoded_response[b"peers"]
            peers = [parse_ip(i, raw_peers) for i in range(len(raw_peers) // 6)]
            print("\n".join(peers))
    elif command == "handshake":
        file_name = sys.argv[2]
        (ip, port) = sys.argv[3].split(":")
        with open(file_name, "rb") as file:
            parsed = decode_bencode(file.read())
            info = parsed[b"info"]
            bencoded_info = bencodepy.encode(info)
            info_hash = hashlib.sha1(bencoded_info).digest()
            handshake = (
                b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
                + info_hash
                + b"00112233445566778899"
            )
            # make request to peer
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, int(port)))
                s.send(handshake)
                print(f"Peer ID: {s.recv(68)[48:].hex()}")
    else:
        raise NotImplementedError(f"Unknown command {command}")
def parse_ip(i, raw_peers):
    peer = raw_peers[i * 6 : 6 * i + 6]
    ip = ".".join([str(ba) for ba in bytearray(peer[0:4])])
    port = int.from_bytes(peer[4:])
    return f"{ip}:{port}"
if __name__ == "__main__":
    main()


