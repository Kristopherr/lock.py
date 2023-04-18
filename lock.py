import os
import sys
import shutil
import signal
import readchar
from getpass import getpass
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from os import urandom
from argon2 import PasswordHasher
from argon2.low_level import Type
from argon2.low_level import hash_secret_raw, Type

backend = default_backend()
buffer_size = 64 * 1024
tag_size = 16
salt_size = 16
nonce_size = 12

def secure_delete(file_path, passes=1):
    try:
        with open(file_path, "ba+") as f:
            length = f.tell()
        
        for _ in range(passes):
            with open(file_path, "br+") as f:
                f.seek(0)
                f.write(os.urandom(length))

        os.remove(file_path)
    except FileNotFoundError:
        print(f"File not found. Unable to securely delete the file: {file_path}")
    except PermissionError:
        print(f"Permission denied. Unable to securely delete the file: {file_path}")
    except Exception as e:
        print(f"An unexpected error occurred during the secure deletion process: {str(e)}")

def derive_key(password, salt):
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=16,
        memory_cost=2**14,
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )

def encrypt_data(password, input_path, output_path):
    try:
        print(f"Encrypting {input_path}")
        salt = urandom(salt_size)
        nonce = urandom(nonce_size)
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
        encryptor = cipher.encryptor()

        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            outfile.write(salt)
            outfile.write(nonce)

            while True:
                chunk = infile.read(buffer_size)
                if len(chunk) == 0:
                    break
                outfile.write(encryptor.update(chunk))
            outfile.write(encryptor.finalize())
            outfile.write(encryptor.tag)
    except KeyboardInterrupt:
        if os.path.exists(output_path):
            os.remove(output_path)
        print(f"\nEncryption process interrupted. The incomplete encrypted file {input_path} has been removed.")
        sys.exit(1)
    except FileNotFoundError:
        print(f"File not found. Unable to encrypt the file: {input_path}")
    except PermissionError:
        print(f"Permission denied. Unable to encrypt the file: {input_path}")
    except Exception as e:
        print(f"An unexpected error occurred during the encryption process: {str(e)}")

def decrypt_data(password, input_path, output_path):
    try:
        print(f"Decrypting {input_path}")
        with open(input_path, 'rb') as infile:
            salt = infile.read(salt_size)
            nonce = infile.read(nonce_size)
            encrypted_data = infile.read()
            ciphertext, tag = encrypted_data[:-tag_size], encrypted_data[-tag_size:]

        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        with open(output_path, 'wb') as outfile:
            outfile.write(decrypted_data)
    except KeyboardInterrupt:
        if os.path.exists(output_path):
            os.remove(output_path)
        print(f"\nDecryption process interrupted. The incomplete decrypted file {input_path} has been removed.")
        sys.exit(1)
    except FileNotFoundError:
        print(f"File not found. Unable to decrypt the file: {input_path}")
    except PermissionError:
        print(f"Permission denied. Unable to decrypt the file: {input_path}")
    except InvalidTag:
        print(f"Incorrect password. Unable to decrypt the file: {input_path}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during the decryption process: {str(e)}")

def get_password_with_asterisks(prompt):
    print(prompt, end='', flush=True)
    password = []
    while True:
        key = readchar.readchar()
        if key == '\r' or key == '\n':
            break
        elif key == '\x08' or key == '\x7f':
            if len(password) > 0:
                password.pop()
                print('\x08 \x08', end='', flush=True)
        else:
            password.append(key)
            print('*', end='', flush=True)
    print()
    return ''.join(password)
    
def get_password():
    while True:
        password1 = get_password_with_asterisks("Enter password: ")
        password2 = get_password_with_asterisks("Confirm password: ")

        if password1 == password2:
            return password1
        else:
            print("Passwords don't match, please try again.")

def lock_folder():
    password = get_password()

    for root, dirs, files in os.walk('.'):
        for file in files:
            if file != 'lock.py':
                input_path = os.path.join(root, file)
                output_path = input_path + '.enc'
                encrypt_data(password, input_path, output_path)
                secure_delete(input_path)

def unlock_folder():
    password = get_password_with_asterisks("Enter password: ")

    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.enc'):
                input_path = os.path.join(root, file)
                output_path = input_path[:-4]
                try:
                    decrypt_data(password, input_path, output_path)
                    secure_delete(input_path)
                except InvalidTag:
                    print("Incorrect password. Unable to decrypt the file:", file)
                    sys.exit(1)

def main():
    encrypted_files = [file for file in os.listdir('.') if file.endswith('.enc')]
    if encrypted_files:
        print("Unlocking folder...")
        unlock_folder()
        print("Folder unlocked.")
    else:
        print("Locking folder...")
        lock_folder()
        print("Folder locked.")

if __name__ == "__main__":
    main()
