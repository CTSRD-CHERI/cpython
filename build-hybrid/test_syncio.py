import socket

try:
    s = socket.create_connection(('127.0.0.1', 16068), timeout=5)
    print("Synchronous connection succeeded!")
    s.close()
except Exception as e:
    print("Synchronous connection failed:", e)

