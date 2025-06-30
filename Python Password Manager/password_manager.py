from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import getpass
import hashlib

class SecurePasswordManager:
    def __init__(self):
        self.salt_file = "salt.key"
        self.master_hash_file = "master.hash"
        self.passwords_file = "passwords.txt"
    
    def generate_salt(self):
        """Generate a random salt for key derivation"""
        return os.urandom(16)
    
    def save_salt(self, salt):
        """Save salt to file"""
        with open(self.salt_file, "wb") as f:
            f.write(salt)

    def load_salt(self):
        """Load salst from file, create if it does not exist"""
        try:
            with open(self.salt_file, "rb") as f:
                return f.read()
        except FileNotFoundError:
            salt = self.generate_salt()
            self.save_salt(salt)
            return salt
            
    def derive_key_from_password(self, password, salt):
        """Derive encryption key from master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def hash_master_password(self, password, salt):
        '''Create a hash of the master password for verification'''
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    
    def save_master_hash(self, password_hash):
        '''Save master password hash to file'''
        with open(self.master_hash_file, "wb") as f:
            f.write(password_hash)

    def load_master_hash(self):
        '''Load master password hash from file'''
        try:
            with open(self.master_hash_file, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None
        
    def setup_master_password(self):
        '''Set up master password for first time'''
        print("Setting up master password for first time...")
        while True:
            password = getpass.getpass("Enter new master password: ")
            confirm = getpass.getpass("Confirm master password: ")

            if password == confirm:
                if len(password) < 8:
                    print("Password must be 8 (eight) charaters long!")
                    continue

                salt = self.load_salt()
                password_hash = self.hash_master_password(password, salt)
                self.save_master_hash(password_hash)
                print("Master password set successfully!")
                return password
            else:
                print("Passwords don't match! Try again.")

    def verify_master_password(self):
        """Verify master password"""
        stored_hash = self.load_master_hash()

        if stored_hash is None:
            return self.setup_master_password()
        
        max_attempts = 3
        for attempt in range(max_attempts):
            password = getpass.getpass("Enter master password: ")
            salt = self.load_salt()
            password_hash = self.hash_master_password(password, salt)

            if password_hash == stored_hash:
                return password
            else:
                remaining = max_attempts - attempt - 1
                if remaining > 0:
                    print(f"Incorrect password! {remaining} attempts remaining.")
                else:
                    print("Too many failed attempts. Exiting for security.")
                    exit(1)

    def get_cipher(self, master_password):
        """Get Fernet cipher from master password"""
        salt = self.load_salt()
        key = self.derive_key_from_password(master_password, salt)
        return Fernet(key)
    
    def view_passwords(self, cipher):
        """View all stored passwords"""
        try:
            with open(self.passwords_file, 'r') as f:
                passwords_found = False
                for line_num, line in enumerate(f.readlines(), 1):
                    data = line.rstrip()

                    # Skip empty lines
                    if not data:
                        continue

                    # Check if line contains the separator
                    if " | " not in data:
                        print(f"Warning: Skipping malformed line {line_num}: '{data}'")
                        continue

                    try:
                        user, encrypted_password = data.split(" | ", 1)
                        decrypted_password = cipher.decrypt(encrypted_password.encode()).decode()
                        print(f"Account: {user} | Password: {decrypted_password}")
                        passwords_found = True
                    except ValueError as e:
                        print(f"Error processing line {line_num}: {e}")
                    except Exception as e:
                        print(f"Error decrypting password on line {line_num}: {e}")

                if not passwords_found:
                    print("No passwords stored yet!")
            
        except FileNotFoundError:
            print("No password file found.  Add some passwords first!")
    
    def add_password(self, cipher):
        """Add a new password"""
        account = input('Account Name: ').strip()
        if not account:
            print("Account name cannot be empty!")
            return
        
        password = getpass.getpass("Password: ")
        if not password:
            print("Password cannot be empty!")
            return
        
        encrypted_password = cipher.encrypt(password.encode()).decode()

        with open(self.passwords_file, 'a') as f:
            f.write(f"{account} | {encrypted_password}\n")

        print(f"Password for '{account}' added successfully!")

    def change_master_password(self):
        """Change the master password"""
        print("Changing the master password...")

        # Verify current password
        current_password = self.verify_master_password()
        current_cipher = self.get_cipher(current_password)

        # Read and decrypt all existing passwords
        existing_passwords = []
        try:
            with open(self.passwords_file, 'r') as f:
                for line in f.readlines():
                    data = line.rstrip()
                    if data and " | " in data:
                        account, encrypted_password = data.split (" | ", 1)
                        try:
                            decrypted_password = current_cipher.decrypt(encrypted_password.encode()).decode()
                            existing_passwords.append((account, decrypted_password))
                        except:
                            print(f"Warning: Could not decrypt password for {account}")
        except FileNotFoundError:
            pass

        # Set new master password
        new_password = self.setup_master_password()
        new_cipher = self.get_cipher(new_password)

        # Re-encrypt all passwords with new key
        if existing_passwords:
            with open(self.passwords_file, 'w') as f:
                for account, password in existing_passwords:
                    encrypted_password = new_cipher.encrypt(password.encode()).decode()
                    f.write(f"{account} | {encrypted_password}\n")

            print(f"Successfully re-encrypted {len(existing_passwords)} passwords with new master password!")
    
    def run(self):
        """Main program loop"""
        print("=== Secure Password Manager ===")

        # Verify master password
        master_password = self.verify_master_password()
        cipher = self.get_cipher(master_password)

        while True:
            print("\nOptions:")
            print("1. View passwords (view)")
            print("2. Add password (add)")
            print("3. Change master password (change)")
            print("4. Quit (q)")

            choice = input("\nWhat would you like to do? ").lower().strip()

            if choice in ['q', 'quit', '4']:
                print("Goodbye!")
                break
            elif choice in ['view', '1']:
                self.view_passwords(cipher)
            elif choice in ['add', '2']:
                self.add_password(cipher)
            elif choice in ['change', '3']:
                self.change_master_password()
                # Get new cipher after password change
                master_password = self.verify_master_password()
                cipher = self.get_cipher(master_password)
            else:
                print("Invalid option. Please try again.")

if __name__ == "__main__":
    manager = SecurePasswordManager()
    manager.run()
