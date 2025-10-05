
import sys
from pathlib import Path

# Constants
ALPHABET_LOWER = "abcdefghijklmnopqrstuvwxyz"
ALPHABET_UPPER = ALPHABET_LOWER.upper()
ENCRYPTED_FOLDER_NAME = "encrypted_messages"

class CaesarCipherApp:
    """
    Manages the encryption, decryption, and file I/O for the Caesar Cipher.

    Uses highly optimized str.maketrans/str.translate methods for speed
    and pathlib for modern file system management.
    """
    def __init__(self):
        """Initialize the application and define the base path for files."""
        # Use pathlib for clean, OS-agnostic path management
        self.base_path = Path.cwd() / ENCRYPTED_FOLDER_NAME

    def _get_shift_input(self, prompt="Enter shift value: ") -> int | None:
        """
        Prompts the user for a shift value and ensures valid integer input.
        Returns the integer shift or None on exit.
        """
        while True:
            try:
                # Stripping input is good practice
                shift_input = input(prompt).strip()
                return int(shift_input)
            except ValueError:
                print("❌ Invalid shift value. Please enter an integer.")

    def _encrypt(self, text: str, shift: int) -> str:
        """Core encryption logic using highly optimized string translation."""
        # Normalize the shift to prevent excessively large numbers from failing string slicing
        normalized_shift = shift % 26

        # Create the shifted alphabet by slicing and concatenating
        shifted_lower = ALPHABET_LOWER[normalized_shift:] + ALPHABET_LOWER[:normalized_shift]
        shifted_upper = ALPHABET_UPPER[normalized_shift:] + ALPHABET_UPPER[:normalized_shift]

        # str.maketrans creates the mapping table (very fast C implementation)
        table = str.maketrans(ALPHABET_LOWER + ALPHABET_UPPER, shifted_lower + shifted_upper)

        # str.translate performs the substitution
        return text.translate(table)

    def _decrypt(self, cipher_text: str, shift: int) -> str:
        """Core decryption logic (just reverses the shift)."""
        return self._encrypt(cipher_text, -shift)

    def _save_to_file(self, filename: str, content: str):
        """Saves content to a file inside the encrypted messages folder."""
        try:
            # Create the folder if it does not exist (equivalent to os.makedirs)
            self.base_path.mkdir(exist_ok=True)
            
            filepath = self.base_path / filename
            filepath.write_text(content)
            
            print(f"✅ File saved successfully to: {filepath.resolve()}")
        except Exception as e:
            print(f"❌ Error saving file: {e}")

    def _load_from_file(self, filename: str) -> str | None:
        """Loads content from a file inside the encrypted messages folder."""
        filepath = self.base_path / filename
        try:
            if filepath.exists():
                return filepath.read_text()
            else:
                print(f"❌ Error: File not found at {filepath.resolve()}")
                return None
        except Exception as e:
            print(f"❌ Error loading file: {e}")
            return None

    def encrypt_and_save(self):
        """Handler for encryption menu option."""
        message = input("Enter your message to encrypt: ")
        filename = input("Enter a filename to save the encrypted message (e.g., secret.txt): ")

        shift = self._get_shift_input("Enter shift value: ")
        if shift is not None:
            encrypted = self._encrypt(message, shift)
            print(f"\n🔐 Encrypted Text: {encrypted}")
            self._save_to_file(filename, encrypted)

    def decrypt_from_file(self):
        """Handler for decryption menu option."""
        filename = input(f"Enter the filename to decrypt (must be in the '{ENCRYPTED_FOLDER_NAME}' folder): ")
        cipher_text = self._load_from_file(filename)

        if cipher_text:
            shift = self._get_shift_input("Enter original shift value: ")
            if shift is not None:
                decrypted = self._decrypt(cipher_text, shift)
                print(f"\n🔓 Decrypted Text: {decrypted}")

    def bruteforce_from_file(self):
        """Handler for brute-force menu option."""
        filename = input(f"Enter the filename to brute-force (must be in the '{ENCRYPTED_FOLDER_NAME}' folder): ")
        cipher_text = self._load_from_file(filename)

        if cipher_text:
            print("\nAttempting brute-force decryption for all 25 possible shifts...")
            # We only need to shift from 1 to 25. Shift 26 is the same as Shift 0 (original text).
            for shift in range(1, 26):
                decrypted_text = self._decrypt(cipher_text, shift)
                print(f"Shift {shift:2d}: {decrypted_text}")

    def run(self):
        """Main application loop."""
        while True:
            print("\n--- Caesar Cipher Application Menu ---")
            print("1. Encrypt a message and save to a file")
            print("2. Decrypt a message from a file (known shift)")
            print("3. Brute-force decrypt a message from a file")
            print("4. Exit")

            choice = input("Enter your choice (1-4): ").strip()

            if choice == '1':
                self.encrypt_and_save()
            elif choice == '2':
                self.decrypt_from_file()
            elif choice == '3':
                self.bruteforce_from_file()
            elif choice == '4':
                print("Exiting...")
                sys.exit(0)
            else:
                print("❌ Invalid choice. Please enter a number from 1 to 4.")

# Entry point
if __name__ == "__main__":
    app = CaesarCipherApp()
    app.run()
