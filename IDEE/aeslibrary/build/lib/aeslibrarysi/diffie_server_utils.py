import socket
from math import sqrt
from random import randrange


def is_prime(number):
    """
    Verify if a number is prime.

    Arguments:
    number -- The number to verify

    Returns:
    True if the number is prime, False otherwise
    """
    if number < 2:
        return False
    if number == 2:
        return True
    if number % 2 == 0:
        return False
    for i in range(3, int(sqrt(number)) + 1, 2):
        if number % i == 0:
            return False
    return True


def generate_prime_number(min_value=10, max_value=100):
    """
    Generate a prime number in the given interval.

    Arguments:
    min_value -- The minimum value of the interval
    max_value -- The maximum value of the interval

    Returns:
    A prime number
    """
    prime = randrange(min_value, max_value)
    while not is_prime(prime):
        prime = randrange(min_value, max_value)
    return prime


def generate_p_g(host, port):
    """
    Generate p and g for the Diffie-Hellman key exchange
    with the help of the Diffie-Hellman Server.

    Arguments:
    host -- The host of the Diffie-Hellman Server
    port -- The port of the Diffie-Hellman Server

    Returns:
    p -- The prime number
    g -- The base
    """
    # Bob and Alice agree on a prime number p and a base g (publicly known)
    # Connect to Diffie-Hellman Server
    dh_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dh_client_socket.connect((host, port))

    # Receive p and g from Diffie-Hellman Server
    p, g = map(int, dh_client_socket.recv(1024).decode().split(','))

    # Close connection with Diffie-Hellman Server
    dh_client_socket.close()

    return p, g
