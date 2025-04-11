import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('127.0.0.1', 16068))
sock.listen(1)
print("Now manually listening on port 16068")

conn, addr = sock.accept()
print("Got connection from", addr)

