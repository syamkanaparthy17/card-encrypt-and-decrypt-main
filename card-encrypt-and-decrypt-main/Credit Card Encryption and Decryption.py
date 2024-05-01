from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_credit_card(card_number, key):
    # Convert card number to bytes
    card_bytes = card_number.encode()

    # Pad the card bytes
    padded_data = pad(card_bytes, AES.block_size)

    # Generate a random initialization vector (IV)
    iv = get_random_bytes(AES.block_size)

    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt the card number
    encrypted_data = cipher.encrypt(padded_data)

    # Return the IV and encrypted data
    return iv + encrypted_data

def decrypt_credit_card(encrypted_data, key):
    # Extract IV
    iv = encrypted_data[:AES.block_size]
    encrypted_data = encrypted_data[AES.block_size:]

    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the encrypted data
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    # Convert decrypted data to string
    decrypted_card_number = decrypted_data.decode()

    # Return decrypted card number
    return decrypted_card_number

# Example usage
key = get_random_bytes(16)  # 128-bit key for AES
card_number = "1234567890123456"
encrypted_card = encrypt_credit_card(card_number, key)
print("Encrypted credit card:", encrypted_card)

decrypted_card = decrypt_credit_card(encrypted_card, key)
print("Decrypted credit card:", decrypted_card)
