import os

def generate_and_save_key(file_path):
    # Generate a random 16-byte key
    key = os.urandom(16)

    # Save the key to a file
    with open(file_path, 'wb') as key_file:
        key_file.write(key)

    # Print the key in a readable format for use
    print(f"Encryption key (hex): {key.hex()}")

if __name__ == "__main__":
    key_file_path = 'encryption_key.key'
    generate_and_save_key(key_file_path)
