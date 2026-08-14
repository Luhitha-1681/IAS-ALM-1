import socket
from encryption import decrypt

HOST = '127.0.0.1'
PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Server is running...")
print("Waiting for client...")

conn, addr = server.accept()

print("Connected by:", addr)

while True:
    data = conn.recv(1024)

    if not data:
        break

    encrypted = data.decode()

    print("\nEncrypted Message :", encrypted)
    print("Decrypted Message :", decrypt(encrypted))

conn.close()
server.close()