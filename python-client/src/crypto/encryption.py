def encrypt_file(file_path, key):
    from cryptography.fernet import Fernet

    # Read the file
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Encrypt the file data
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file_data)

    # Write the encrypted file
    with open(file_path + '.encrypted', 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(encrypted_file_path, key):
    from cryptography.fernet import Fernet

    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()

    # Decrypt the file data
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    # Write the decrypted file
    original_file_path = encrypted_file_path.replace('.encrypted', '')
    with open(original_file_path, 'wb') as file:
        file.write(decrypted_data)

def generate_key():
    from cryptography.fernet import Fernet

    # Generate a key
    key = Fernet.generate_key()
    return key

def save_key(key, key_file):
    # Save the key to a file
    with open(key_file, 'wb') as file:
        file.write(key)

def load_key(key_file):
    # Load the key from a file
    with open(key_file, 'rb') as file:
        key = file.read()
    return key