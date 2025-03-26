def test_key_generation():
    from src.crypto.keys import generate_key
    key = generate_key()
    assert key is not None
    assert len(key) == 32  # Assuming a 256-bit key

def test_encryption_decryption():
    from src.crypto.encryption import encrypt, decrypt
    data = b"Test data"
    key = b"thisisaverysecretkey12345678"  # Example key
    encrypted_data = encrypt(data, key)
    decrypted_data = decrypt(encrypted_data, key)
    assert decrypted_data == data

def test_file_encryption_decryption():
    from src.crypto.encryption import encrypt_file, decrypt_file
    test_file_path = "test_file.txt"
    key = b"thisisaverysecretkey12345678"  # Example key
    
    # Create a test file
    with open(test_file_path, "wb") as f:
        f.write(b"Test file content")
    
    # Encrypt the file
    encrypt_file(test_file_path, key)
    
    # Decrypt the file
    decrypted_file_path = "decrypted_test_file.txt"
    decrypt_file(test_file_path + ".enc", key, decrypted_file_path)
    
    # Verify the content
    with open(decrypted_file_path, "rb") as f:
        decrypted_content = f.read()
    
    assert decrypted_content == b"Test file content"