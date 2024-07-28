import json
import sys
from bencodepy import Bencode  # - available if you need it!
import hashlib
import textwrap
import requests  # - available if you need it!
import socket
# Examples:
#
Expand 88 lines
            peers_list = peers_list[6:]
    elif command == "handshake":
        content_decoded = metafile(sys.argv[2])
        info_hash = hashlib.sha1(Bencode().encode(content_decoded[b"info"])).digest()
        addr = sys.argv[3].split(":")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((addr[0], int(addr[1])))
            client.send(
                chr(19).encode()
                + b"BitTorrent protocol00000000"
                + info_hash
                + "40440440440404404040".encode()
            )
            reply = client.recv(70)
        print("Peer ID:", reply[48:].hex())
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()