import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

BLOCK_SIZE = 65536

class FileCryptor:
    def __init__(self):
        self.backend = default_backend()
        self.algorithms = {
            'aes': {
                'id': b'AES',
                'key_size': 32,  # 256 bits
                'nonce_size': 16, # 128 bits
                'cipher_func': lambda key, nonce: Cipher(algorithms.AES(key), modes.CBC(nonce), backend=self.backend)
            },
            'chacha20': {
                'id': b'CHACHA20',
                'key_size': 32,
                'nonce_size': 12,
                'cipher_func': lambda key, nonce: Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=self.backend)
            }
        }

    def encrypt_file(self, input_filename, output_filename, algorithm_name):
        if algorithm_name not in self.algorithms:
            print(f"❌ Error: Algorithm '{algorithm_name}' is not supported.")
            return

        params = self.algorithms[algorithm_name]
        key = os.urandom(params['key_size'])
        nonce = os.urandom(params['nonce_size'])
        
        try:
            with open(input_filename, 'rb') as infile, open(output_filename, 'wb') as outfile:
                outfile.write(params['id'])
                outfile.write(nonce)
                outfile.write(key)
                
                cipher = params['cipher_func'](key, nonce)
                encryptor = cipher.encryptor()

                if algorithm_name == 'aes':
                    padder = padding.PKCS7(algorithms.AES.block_size).padder()
                    while True:
                        chunk = infile.read(BLOCK_SIZE)
                        if not chunk:
                            break
                        padded_chunk = padder.update(chunk)
                        outfile.write(encryptor.update(padded_chunk))
                    outfile.write(encryptor.update(padder.finalize()))

                else:
                    while True:
                        chunk = infile.read(BLOCK_SIZE)
                        if not chunk:
                            break
                        outfile.write(encryptor.update(chunk))
                
                outfile.write(encryptor.finalize())
            print(f"✅ Encryption successful! Your file has been saved as: '{output_filename}'")
        except FileNotFoundError:
            print(f"❌ Error: The file '{input_filename}' was not found. Please make sure the file is in the correct sub-folder.")
        except Exception as e:
            print(f"❌ An unexpected error occurred during encryption: {e}")

    def decrypt_file(self, input_filename, output_filename):

        try:
            with open(input_filename, 'rb') as infile, open(output_filename, 'wb') as outfile:
                alg_id_raw = infile.read(10)
                found_alg = None
                for name, params in self.algorithms.items():
                    if alg_id_raw.startswith(params['id']):
                        found_alg = params
                        # Seek back to the beginning of the nonce
                        infile.seek(len(params['id']), 0)
                        break
                
                if not found_alg:
                    print("❌ Error: Could not determine encryption algorithm from the file header. This file may be corrupt or not created by this program.")
                    return

                # Read the nonce and key from the file
                nonce = infile.read(found_alg['nonce_size'])
                key = infile.read(found_alg['key_size'])

                # Create the cipher and decryptor
                cipher = found_alg['cipher_func'](key, nonce)
                decryptor = cipher.decryptor()
                
                if found_alg['id'] == b'AES':
                    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                    while True:
                        chunk = infile.read(BLOCK_SIZE)
                        if not chunk:
                            break
                        unpadded_chunk = unpadder.update(decryptor.update(chunk))
                        if unpadded_chunk:
                            outfile.write(unpadded_chunk)
                    
                    unpadded_chunk = unpadder.finalize()
                    if unpadded_chunk:
                        outfile.write(unpadded_chunk)

                else:
                    while True:
                        chunk = infile.read(BLOCK_SIZE)
                        if not chunk:
                            break
                        outfile.write(decryptor.update(chunk))

                outfile.write(decryptor.finalize())
            print(f"✅ Decryption successful! Your file has been saved as: '{output_filename}'")
        except FileNotFoundError:
            print(f"❌ Error: The encrypted file '{input_filename}' was not found. Please double-check the file path.")
        except Exception as e:
            print(f"❌ An unexpected error occurred during decryption: {e}")

def main():
    cryptor = FileCryptor()
    
    PHOTOS_FOLDER = 'photos'
    ENCRYPTED_FOLDER = 'encrypted_photos'

    if not os.path.exists(PHOTOS_FOLDER):
        os.makedirs(PHOTOS_FOLDER)
        print(f"Created a new subfolder named '{PHOTOS_FOLDER}'. Please place your photos inside it.")
    
    if not os.path.exists(ENCRYPTED_FOLDER):
        os.makedirs(ENCRYPTED_FOLDER)
        print(f"Created a new subfolder named '{ENCRYPTED_FOLDER}' for encrypted files.")

    print("\n🔐 Welcome to the Universal File Cryptor!")
    print("This tool can encrypt and decrypt your files securely.")

    while True:
        print("\n--- Main Menu ---")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")

        choice = input("\nWhat would you like to do? (1/2/3): ").strip()
        
        if choice == "1":
            input_file = input(f"Enter the filename to encrypt (from '{PHOTOS_FOLDER}'): ").strip()
            
            input_path = os.path.join(PHOTOS_FOLDER, input_file)
            name, ext = os.path.splitext(input_file)
            output_file = f"{name}_encrypted{ext}"
            output_path = os.path.join(ENCRYPTED_FOLDER, output_file)
            
            print("\nAvailable Algorithms:")
            for i, alg in enumerate(cryptor.algorithms.keys(), 1):
                print(f"{i}. {alg.upper()}")
            
            try:
                alg_choice = int(input("Select an algorithm to use (1 or 2): "))
                if 1 <= alg_choice <= len(cryptor.algorithms):
                    selected_alg = list(cryptor.algorithms.keys())[alg_choice - 1]
                    cryptor.encrypt_file(input_path, output_path, selected_alg)
                else:
                    print("❌ Invalid algorithm choice. Please enter a number from the list.")
            except ValueError:
                print("❌ Invalid input. Please enter a number.")

        elif choice == "2":
            input_file = input(f"Enter the filename to decrypt (from '{ENCRYPTED_FOLDER}'): ").strip()
            
            # Construct full paths for input and output
            input_path = os.path.join(ENCRYPTED_FOLDER, input_file)
            name, ext = os.path.splitext(input_file)
            output_file = f"{name}_decrypted{ext}"
            output_path = os.path.join(PHOTOS_FOLDER, output_file)
            
            cryptor.decrypt_file(input_path, output_path)

        elif choice == "3":
            print("\nThank you for using the tool. Goodbye!")
            sys.exit(0)
        
        else:
            print("❌ Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
