import socket
from secrets import token_hex


from aeslibrarysi.AES import encrypt, decrypt
from aeslibrarysi.diffie_server_utils import generate_p_g
from aeslibrarysi.utils import text_to_hex

DIFFIE_HELLMAN_IP = "10.177.186.2"
DIFFIE_HELLMAN_PORT = 12346

BOB_IP = "10.177.186.1"
BOB_PORT = 12345


# server
def start_Bob(host, port, p, g):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Serverul asculta la adresa {host}:{port}...")

    client_socket, client_address = server_socket.accept()
    print(f"Conexiune acceptata de la {client_address}")

    # Key for the AES encryption must be 16 bytes long
    shared_secret_key_vectorBob = ""
    for i in range(16):
        # Bob combines his secret key b with the shared key and sends the result to Alice
        b = int(token_hex(2), 16)

        # g ^ b mod p
        B = pow(g, b, p)

        # Send the result to Alice
        client_socket.sendall(str(B).encode())

        # Receive the result from Alice
        A = int(client_socket.recv(1024).decode())

        # Bob combines A with his secret key b
        # A ^ b mod p
        shared_secret_key = pow(A, b, p)

        # Build the shared secret key
        shared_secret_key_vectorBob += str(shared_secret_key)

    key = bytes.fromhex(text_to_hex(shared_secret_key_vectorBob))

    print(f"Bob: Shared secret key is: {key}")

    # Start the message exchange
    while True:
        # Bob wait to receive a message from Alice
        encrypted_message = client_socket.recv(1024)

        # Verify if no message was received
        if not encrypted_message:
            break

        # Decrypt the message received from Alice
        decrypted_message = decrypt(encrypted_message, key)
        print(f"[Alice]: {decrypted_message}")

        # Bob sends a message to Alice
        message_to_send = input("You: ")

        # Verify if the message is not empty
        if message_to_send.strip():
            # Encrypt the message to send to Alice
            encrypted_message_to_send = encrypt(message_to_send, key)
            # Send the encrypted message to Alice
            client_socket.sendall(encrypted_message_to_send)
        else:
            print("The message is empty.")

    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    # p, g = server_utils.generate_p_g("127.0.0.1", 12346)
    p, g = generate_p_g(DIFFIE_HELLMAN_IP, DIFFIE_HELLMAN_PORT)

    print("Bob a inchis conexiunea cu serverul Diffie-Hellman.")
    print(f"p = {p}, g = {g}")
    # start_Bob("127.0.0.1", 12345, p, g)
    start_Bob(BOB_IP, BOB_PORT, p, g)

