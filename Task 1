def caesar_cipher_encrypt(text, shift):
    """Encrypts the given text using the Caesar Cipher algorithm."""
    encrypted_text = ""

    for char in text:
        # Check if character is an uppercase letter
        if char.isupper():
            encrypted_text += chr((ord(char) + shift - 65) % 26 + 65)
        # Check if character is a lowercase letter
        elif char.islower():
            encrypted_text += chr((ord(char) + shift - 97) % 26 + 97)
        # If it's not a letter, leave it unchanged
        else:
            encrypted_text += char

    return encrypted_text

def caesar_cipher_decrypt(text, shift):
    """Decrypts the given text using the Caesar Cipher algorithm."""
    return caesar_cipher_encrypt(text, -shift)

def main():
    while True:
        choice = input("Do you want to (E)ncrypt or (D)ecrypt a message or (Q)uit? ").upper()

        if choice == 'Q':
            print("Goodbye!")
            break
        elif choice not in ['E', 'D']:
            print("Invalid choice. Please enter E, D, or Q.")
            continue

        message = input("Enter the message: ")
        shift = int(input("Enter the shift value: "))

        if choice == 'E':
            encrypted_message = caesar_cipher_encrypt(message, shift)
            print(f"Encrypted message: {encrypted_message}")
        elif choice == 'D':
            decrypted_message = caesar_cipher_decrypt(message, shift)
            print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()
