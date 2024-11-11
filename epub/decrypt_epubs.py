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

def decrypt_epub_file(file_path: str, password: str) -> str:
    # Read encrypted data
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    
    # Extract the salt, IV, and encrypted content
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    # Generate the key using the salt
    key = generate_key(password.encode(), salt)
    
    # Set up the AES cipher for decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt and remove padding
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
    
    # Save the decrypted file
    output_file = file_path.replace('.enc', '_decrypted.epub')
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)
    
    print(f'Decrypted file saved as {output_file}')
    return output_file

def decrypt_all_epubs_in_folder(folder_path: str, password: str):
    for filename in os.listdir(folder_path):
        if filename.endswith('.enc'):
            file_path = os.path.join(folder_path, filename)
            decrypt_epub_file(file_path, password)

# Usage
folder_path = r"C:\Users\Arshitha\Desktop\epub\epub input"  # Path to folder containing encrypted EPUB files
password = getpass.getpass("Enter decryption password: ")
decrypt_all_epubs_in_folder(folder_path, password)
