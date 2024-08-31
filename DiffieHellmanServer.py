import socket
from secrets import token_hex
import server_utils


def start_DH_Server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(2)

    print(f"Diffie-Hellman Server is listening on {host}:{port}...")

    # Generate p and g for the Diffie-Hellman key exchange
    p = server_utils.generate_prime_number()
    g = int(token_hex(2), 16)

    clients = []

    # Accept connections from Alice and Bob
    for _ in range(2):
        client_socket, client_address = server_socket.accept()
        print(f"Conexiune acceptata de la {client_address}")
        clients.append(client_socket)

    for i in range(2):
        # Send p and g to the client
        clients[i].sendall(f"{p},{g}".encode())

        # close the connection with the client
        clients[i].close()


if __name__ == "__main__":
    start_DH_Server("127.0.0.1", 12346)
