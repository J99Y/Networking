#!/usr/bin/python3

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip = "127.0.0.1"
port = 6777
address = (ip, port)
size = 1024
s.sendto("example1.mp4".encode(), address)
with open ('example1.mp4', 'rb') as f:
    data = f.read(1024)
    while data:
        print(f"sending bytes {size}")
        s.sendto(data, address)
        data = f.read(1024)
        size += 1024

print("complete")