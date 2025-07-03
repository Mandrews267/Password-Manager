
 # Secure Password Manager

**A command-line password manager built with Python that provides secure encryption and storage of passwords using industry-standard cryptographic practices.**

## Features 

- :closed_lock_with_key: **Strong Encryption:** Uses Fernet symmetric encryption with PBKDF2 key derivation.
- :salt: **Salt-based Security:** Each installation generates a unique salt to prevent rainbow table attacks.
- :key: **Master Password Protection:** Secure master password verification with a maximum of three attempts.
- :eye: **Hidden Input:** Password input is hidden from the terminal (no echo).
- :repeat: **Master Password Changes:** Safely change your master password and re-encrypt all stored data.
- :warning: **Error Handling:** Graceful handling of corrupted data and malformed entries.
- :shield: **Brute Force Protection:** Limits login attempts of the master password to three attempts.

## How It Works

### Security Architecture

1. **Key Derivation:** Your master password is processed through PBKDF2 with 100,000 iterations and a random salt to create a strong encryption key.
2. **Password Verification:** The master password is hashed and stored 
3.  **Encryption:** All stored passwords are encrypted using Fernet (AES 128 in CBC mode with HMAC)
4.  **File Structure:** Uses separate files for salt, master password hash, and encrypted passwords.

### File Structure
**The application creates three files**
- `salt.key` - Random 16-byte salt for key derivation
- `master.hash` - Hashed master password for verification
- `passwords.txt` - Encrypted password entries in format: `Account | EncryptedPassword`

### Workflow
1. **First Run:** Set up master password with confirmation and minimum 8-charracteer requirement.
2. **Subsequent Runs:** Verify master password within three attempt or application closes.
3. **Operations:** View, add, or change passwords through and interactive menu.
4. **Security:** All password inputs are hidden and encryption keys are derived securely.

## Installation
### Prerequisites
`pip install cryptography`
### Usage
1. Clone the repository:
`git clone https://github.com/mandrews267/secure-password-manager.git`
`cd secure-password-manager`
2. Run the script:
`python password_manager.py`
3. Follow the prompts to set up your master password *(first time only)*

## Menu Options
- **View passwords (1/view):** Display all stored account credentials
- **Add password (2/add):** Store a new account and password
- **Change master password (3/change):** Update master password and re-encrypt all data
- **Quit (4/q):** Exit the application

## Security Features
### Cryptographic Implementation
- **Algorithm:** AES-128 encryption via Fernet
- **Key Derivation:** PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Salt:** 16-byte random salt generated per installation
- **Password Hashing:** PBKDF2-HMAC-SHA256 for master password verification

### Protection Mechanisms
- **Attempt Limiting:** Maximum 3 failed login attempts before program exits
- **Hidden Input:** Uses `getpass` module to hide password entry
- **Data Validation:** Checks for empty passwords and malformed data
- **Error Recovery:** Skips corrupted entries instead of crashing

### Best Practices Implemented
- No plaintext password storage
- Unique salt per installation
- High iteration count for key derivation
- Secure random number generation
- Proper error handling and user feedback

## Security Considerations

:warning: **Important Security Notes:**
- Keep your master password secure and memorable
- The security of all stored passwords depends on your master password strength
- Back up your `salt.key` file - without it, your passwords cannot be decrypted
- This tool stores data locally - ensure your device is secure
- Consider using a strong, unique master password with mixed case, numbers, and symbols

## Technical Details

### Dependencies
- `cryptography` - Modern cryptographic library for Python
- `hashlib` - Built-in Python hashing functions
- `getpass` - Operating system interface for secure random generation
- `base64` - Binary data encoding

### Encryption Process
1. Master password + salt &#8594; PBKDF2 &#8594; 256-bit key
2. Key &#8594; Fernet cipher object
3. Account password &#8594; Fernet encryption &#8594; Base64 encoded string
4. Encrypted string stored in file with account name

### Decryption Process
1. Master password verification stored via a stored hash
2. Key derivation from verified password
3. Fernet cipher creation
4. Base64 decode &#8594; Fernet decryption &#8594; Original password

## Disclaimer
This password manager is provided as-is for educational and personal use.  While it implements security best practices, users should evaluate their own security requirements and consider professional security audits for critical applications.
