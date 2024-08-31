import socket
from secrets import token_hex

import AES
import server_utils
import utils


# client
def start_Alice(host, port, p, g):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    # Key for the AES encryption must be 16 bytes long
    shared_secret_key_vectorAlice = ""
    for i in range(16):
        # Alice combines her secret key a with the shared key and sends the result to Bob
        a = int(token_hex(2), 16)

        # Receive the result from Bob
        B = int(client_socket.recv(1024).decode())

        # g ^ a mod p
        A = pow(g, a, p)

        # Send the result to Bob
        client_socket.sendall(str(A).encode())

        # Alice combines B with her secret key a
        # B ^ a mod p
        shared_secret_key = pow(B, a, p)

        # Build the shared secret key
        shared_secret_key_vectorAlice += str(shared_secret_key)

    key = bytes.fromhex(utils.text_to_hex(shared_secret_key_vectorAlice))

    print(f"Alice: Shared secret key is: {key}")

    # Start the message exchange
    while True:
        # Alice sends a message to Bob
        message_to_send = input("You: ")

        # Verify if the message is not empty
        if message_to_send.strip():
            # Encrypt the message to send
            encrypted_message_to_send = AES.encrypt(message_to_send, key)
            client_socket.sendall(encrypted_message_to_send)
        else:
            print("Meessage is empty.")

        # Alice wait to receive a message from Bob
        encrypted_message = client_socket.recv(1024)

        # Verify if no message was received
        if not encrypted_message:
            break

        # Decrypt the message received from Bob
        decrypted_message = AES.decrypt(encrypted_message, key)
        print(f"[Bob]: {decrypted_message}")

    client_socket.close()


if __name__ == "__main__":
    p, g = server_utils.generate_p_g("127.0.0.1", 12346)
    print("Alice a inchis conexiunea cu serverul Diffie-Hellman.")
    print(f"p: {p}, g: {g}")
    start_Alice("127.0.0.1", 12345, p, g)
