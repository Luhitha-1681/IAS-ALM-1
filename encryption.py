# Caesar Cipher Encryption & Decryption

SHIFT = 3

def encrypt(text):
    result = ""

    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr((ord(char) - 65 + SHIFT) % 26 + 65)
            else:
                result += chr((ord(char) - 97 + SHIFT) % 26 + 97)
        else:
            result += char

    return result


def decrypt(text):
    result = ""

    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr((ord(char) - 65 - SHIFT) % 26 + 65)
            else:
                result += chr((ord(char) - 97 - SHIFT) % 26 + 97)
        else:
            result += char

    return result