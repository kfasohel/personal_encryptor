import base64
import os
import sys
import re
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tabulate import tabulate


def main():
    print(display_options())

    while True:
        choice = input("Enter your choice, 1, 2, 3 or 4: ").strip()
        matches = re.search(r"^[1-3]{1}$", choice)

        if matches:
            u_password = getpass.getpass("Your password: ")
            b_password = u_password.encode("UTF-8")
            execute_option(choice, b_password)
        else:
            execute_option(choice)


def execute_option(option="", e_password=b""):
    if option == "1":
        token, salt = set_password(e_password)
        with open("salted.bin", "wb") as file:
            file.write(salt)

        with open("ciphered.bin", "wb") as file:
            file.write(token)
        print("Added!")

    elif option == "2":
        token = add_secret(e_password)
        with open("ciphered.bin", "ab+") as file:
            file.write(token)
            print("Added!")

    elif option == "3":
        clear_text = decrypt_secret(e_password)
        for text in clear_text:
            print(text)

    else:
        sys.exit("This program is exiting. Thank you")


def display_options():
    print(
        "Welcome to your own secret text manager!"
    )
    disp = [
        [
            1,
            "Set or Reset Password",
            "It will delete all the stored text and start new",
        ],
        [
            2,
            "Add Secret",
            "It will encrypt your text and save it.",
        ],
        [
            3,
            "Show Secret",
            "It will decrypt and show your saved text.",
        ],
        [4, "exit_program", "To exit or quit the program."],
    ]

    return tabulate(
        disp,
        headers=["Choice", "Action", "Description"],
        tablefmt="grid",
        numalign="center",
    )


def get_fernet(password, state=""):
    if state == "new":
        salt = os.urandom(16)
    else:
        try:
            with open("salted.bin", "rb") as file:
                salt = file.readline()
        except FileNotFoundError:
            sys.exit("First choose option 1, then you can add more to it.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    if state == "new":
        return Fernet(key), salt
    else:
        return Fernet(key)


def set_password(password):
    f, salt = get_fernet(password, "new")

    user_secret = input("Your secret message here: ")
    user_secret_b = user_secret.encode("UTF-8")

    e_token = f.encrypt(user_secret_b) + b"\n"
    return e_token, salt


def decrypt_secret(password):
    f = get_fernet(password)

    with open("ciphered.bin", "rb") as file:
        data = file.read()
        tokens = data.splitlines()

        try:
            d_tokens = []
            for token in tokens:
                d_token = f.decrypt(token)
                d_token = d_token.decode("UTF-8")
                d_tokens.append(d_token)
            return d_tokens
        except Exception as e:
            sys.exit("Your password doesn't match")


def add_secret(password):
    f = get_fernet(password)

    token = decrypt_secret(password)

    user_secret = input("Your secret message here: ")
    user_secret_b = user_secret.encode("UTF-8")
    token = f.encrypt(user_secret_b)
    token = token + b"\n"

    return token


if __name__ == "__main__":
    main()
 