import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import getpass

def generate_key(password: bytes, salt: bytes) -> bytes:
    """Generate an AES key from a password using Scrypt KDF."""
    kdf = Scrypt(
        salt=salt,
        length=32,        # 32 bytes = 256 bits
        n=2**14,          # CPU cost
        r=8,              # Block size
        p=1,              # Parallelization factor
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_epub_file(file_path: str, password: str) -> str:
    with open(file_path, 'rb') as file:
        epub_data = file.read()

    iv = os.urandom(16)
    salt = os.urandom(16)

    key = generate_key(password.encode(), salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(epub_data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    output_file = file_path + '.enc'

    with open(output_file, 'wb') as file:
        file.write(salt + iv + encrypted_data)

    print(f'Encrypted file saved as {output_file}')
    return output_file

def encrypt_all_epubs_in_folder(folder_path: str, password: str):
    for filename in os.listdir(folder_path):
        if filename.endswith('.epub'):
            file_path = os.path.join(folder_path, filename)
            encrypt_epub_file(file_path, password)

# Usage
folder_path = r"C:\Users\Arshitha\Desktop\epub\epub input"  # Use the `r` prefix to treat backslashes as literal
 # Replace with the path to your folder containing EPUB files
password = getpass.getpass("Enter encryption password: ")
encrypt_all_epubs_in_folder(folder_path, password)
