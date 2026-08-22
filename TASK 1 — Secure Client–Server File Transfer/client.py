import socket
import os
import struct
import threading
import zipfile
import xml.etree.ElementTree as ET

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


SERVER_IP = "127.0.0.1"
PORT = 5000

# Same DES key
KEY = b"8bytekey"


# ============================================================
# DES ENCRYPTION
# ============================================================

def encrypt_data(data):

    cipher = DES.new(
        KEY,
        DES.MODE_ECB
    )

    ciphertext = cipher.encrypt(
        pad(
            data,
            DES.block_size
        )
    )

    return ciphertext


# ============================================================
# DES DECRYPTION
# ============================================================

def decrypt_data(data):

    cipher = DES.new(
        KEY,
        DES.MODE_ECB
    )

    plaintext = cipher.decrypt(
        data
    )

    return unpad(
        plaintext,
        DES.block_size
    )


# ============================================================
# RECEIVE EXACT NUMBER OF BYTES
# ============================================================

def receive_all(sock, size):

    data = b""

    while len(data) < size:

        packet = sock.recv(
            min(
                4096,
                size - len(data)
            )
        )

        if not packet:

            raise ConnectionError(
                "Connection closed."
            )

        data += packet

    return data


# ============================================================
# DISPLAY FILE INFORMATION
# ============================================================

def display_file_info(filename, data):

    print("\n---------- FILE INFORMATION ----------")

    print(
        "Filename:",
        filename
    )

    print(
        "File size:",
        len(data),
        "bytes"
    )

    extension = os.path.splitext(
        filename
    )[1].lower()

    # --------------------------------------------------------
    # DOCX
    # --------------------------------------------------------

    if extension == ".docx":

        try:

            with zipfile.ZipFile(
                __import__("io").BytesIO(data)
            ) as docx:

                xml_data = docx.read(
                    "word/document.xml"
                )

                root = ET.fromstring(
                    xml_data
                )

                namespace = {
                    "w":
                    "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
                }

                texts = []

                for element in root.findall(
                    ".//w:t",
                    namespace
                ):

                    if element.text:
                        texts.append(
                            element.text
                        )

                text = " ".join(
                    texts
                )

                print(
                    "\n---------- DOCX CONTENT ----------"
                )

                if text.strip():

                    print(
                        text[:3000]
                    )

                    if len(text) > 3000:

                        print(
                            "\n...[content truncated]"
                        )

                else:

                    print(
                        "[No readable text found]"
                    )

        except Exception as e:

            print(
                "Could not read DOCX:",
                e
            )

    # --------------------------------------------------------
    # TEXT
    # --------------------------------------------------------

    elif extension in [
        ".txt",
        ".csv"
    ]:

        try:

            text = data.decode(
                "utf-8",
                errors="replace"
            )

            print(
                "\n---------- FILE CONTENT ----------"
            )

            print(
                text[:3000]
            )

        except:

            print(
                "[Unable to display content]"
            )

    # --------------------------------------------------------
    # BINARY
    # --------------------------------------------------------

    else:

        print(
            "Binary file detected."
        )

        print(
            "First 100 bytes:"
        )

        print(
            data[:100]
        )


# ============================================================
# SEND FILE
# ============================================================

def send_file(sock):

    filepath = input(
        "\nEnter the complete path of the file to send: "
    ).strip().strip('"')

    if not os.path.isfile(filepath):

        print(
            "\nFile not found!"
        )

        return

    filename = os.path.basename(
        filepath
    )

    with open(
        filepath,
        "rb"
    ) as file:

        plaintext = file.read()

    print(
        "\nEncrypting using DES..."
    )

    ciphertext = encrypt_data(
        plaintext
    )

    filename_bytes = filename.encode(
        "utf-8"
    )

    # Command
    sock.sendall(
        b"FILE"
    )

    # Filename length
    sock.sendall(
        struct.pack(
            "!I",
            len(filename_bytes)
        )
    )

    # Filename
    sock.sendall(
        filename_bytes
    )

    # Ciphertext length
    sock.sendall(
        struct.pack(
            "!Q",
            len(ciphertext)
        )
    )

    # Ciphertext
    sock.sendall(
        ciphertext
    )

    print("\n======================================")
    print("          FILE SENT USING DES")
    print("======================================")

    display_file_info(
        filename,
        plaintext
    )

    print(
        "\n---------- ENCRYPTION INFO ----------"
    )

    print(
        "Plaintext size:",
        len(plaintext),
        "bytes"
    )

    print(
        "Ciphertext size:",
        len(ciphertext),
        "bytes"
    )

    print(
        "\n---------- CIPHERTEXT ----------"
    )

    print(
        ciphertext[:256].hex()
    )

    if len(ciphertext) > 256:

        print(
            "...[ciphertext truncated]"
        )

    print(
        "\nDES encryption and transmission completed."
    )


# ============================================================
# RECEIVE FILE
# ============================================================

def receive_file(sock):

    filename_length = struct.unpack(
        "!I",
        receive_all(
            sock,
            4
        )
    )[0]

    filename = receive_all(
        sock,
        filename_length
    ).decode(
        "utf-8"
    )

    ciphertext_length = struct.unpack(
        "!Q",
        receive_all(
            sock,
            8
        )
    )[0]

    print(
        "\nReceiving encrypted file..."
    )

    ciphertext = receive_all(
        sock,
        ciphertext_length
    )

    plaintext = decrypt_data(
        ciphertext
    )

    os.makedirs(
        "client_received",
        exist_ok=True
    )

    output_path = os.path.join(
        "client_received",
        "decrypted_" + filename
    )

    with open(
        output_path,
        "wb"
    ) as file:

        file.write(
            plaintext
        )

    print("\n======================================")
    print("        FILE RECEIVED USING DES")
    print("======================================")

    print(
        "Filename:",
        filename
    )

    print(
        "Ciphertext size:",
        len(ciphertext),
        "bytes"
    )

    print(
        "Decrypted size:",
        len(plaintext),
        "bytes"
    )

    print(
        "\n---------- CIPHERTEXT ----------"
    )

    print(
        ciphertext[:256].hex()
    )

    if len(ciphertext) > 256:

        print(
            "...[ciphertext truncated]"
        )

    display_file_info(
        filename,
        plaintext
    )

    print(
        "\nDecrypted file saved at:"
    )

    print(
        output_path
    )


# ============================================================
# RECEIVE THREAD
# ============================================================

def receive_loop(sock):

    while True:

        try:

            command = receive_all(
                sock,
                4
            )

            if command == b"FILE":

                receive_file(
                    sock
                )

                print(
                    "\nClient is ready."
                )

            elif command == b"EXIT":

                print(
                    "\nServer closed the connection."
                )

                break

        except Exception as e:

            print(
                "\nConnection closed:",
                e
            )

            break


# ============================================================
# CLIENT
# ============================================================

client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

print("======================================")
print("          SECURE DES CLIENT")
print("======================================")

print(
    "\nConnecting to server..."
)

client.connect(
    (
        SERVER_IP,
        PORT
    )
)

print(
    "Connected to server!"
)

print(
    "Server:",
    SERVER_IP
)

print(
    "Port:",
    PORT
)


# ============================================================
# START RECEIVING THREAD
# ============================================================

thread = threading.Thread(
    target=receive_loop,
    args=(client,),
    daemon=True
)

thread.start()


# ============================================================
# CLIENT MENU
# ============================================================

while True:

    print("\n======================================")
    print("             CLIENT MENU")
    print("======================================")

    print("1. Send file to server")
    print("2. Receive file from server")
    print("3. Exit")

    choice = input(
        "\nEnter your choice: "
    ).strip()

    # --------------------------------------------------------
    # SEND
    # --------------------------------------------------------

    if choice == "1":

        try:

            send_file(
                client
            )

        except Exception as e:

            print(
                "\nError sending file:",
                e
            )

    # --------------------------------------------------------
    # RECEIVE
    # --------------------------------------------------------

    elif choice == "2":

        print(
            "\nThe client is already listening for files."
        )

        print(
            "Ask the server to choose:"
        )

        print(
            "1. Send file to client"
        )

    # --------------------------------------------------------
    # EXIT
    # --------------------------------------------------------

    elif choice == "3":

        try:

            client.close()

        except:
            pass

        break

    else:

        print(
            "\nInvalid choice."
        )


print(
    "\nClient closed."
)