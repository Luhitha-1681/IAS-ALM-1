import socket
from encryption import encrypt

HOST = '127.0.0.1'
PORT = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

print("Connected to Server")

while True:

    message = input("\nEnter Message (type exit to quit): ")

    if message.lower() == "exit":
        break

    encrypted = encrypt(message)

    print("Encrypted:", encrypted)

    client.send(encrypted.encode())

client.close()