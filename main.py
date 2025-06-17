import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import os
from pgpy import PGPKey, PGPMessage

from fraza.core import generate_password


def load_public_key(pubkey_path: str) -> PGPKey:
    with open(pubkey_path, "r") as f:
        key, _ = PGPKey.from_blob(f.read())
    return key


def load_private_key(privkey_path: str, passphrase: str = None) -> PGPKey:
    with open(privkey_path, "r") as f:
        key, _ = PGPKey.from_blob(f.read())
    if key.is_protected and passphrase is None:
        raise ValueError("Ключ защищён паролем, но пароль не передан!")
    return key


def encrypt_file(input_path: str, output_path: str, pubkey: PGPKey) -> None:
    with open(input_path, "rb") as f:
        data = f.read()

    message = PGPMessage.new(data, file=True)
    encrypted_message = pubkey.encrypt(message)

    with open(output_path, "w") as f:
        f.write(str(encrypted_message))


def decrypt_file(input_path: str, output_path: str, privkey: PGPKey) -> None:
    with open(input_path, "r") as f:
        encrypted_message = PGPMessage.from_blob(f.read())

    decrypted_message = privkey.decrypt(encrypted_message)

    with open(output_path, "wb") as f:
        f.write(decrypted_message.message)


def decrypt_and_print(input_path: str, privkey: PGPKey) -> None:
    with open(input_path, "r") as f:
        encrypted_message = PGPMessage.from_blob(f.read())

    decrypted_message = privkey.decrypt(encrypted_message)

    msg = decrypted_message.message
    if isinstance(msg, bytes):
        msg = msg.decode("utf-8")
    print(msg)


def write_encrypted_string(
    text: str, filename: str, output_dir: str, pubkey: PGPKey
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"{filename}.asc")

    message = PGPMessage.new(text)
    encrypted_message = pubkey.encrypt(message)

    with open(output_path, "w") as f:
        f.write(str(encrypted_message))

    return output_path


if __name__ == "__main__":
    pubkey_path = r"D:\Code\Python\passtty\key\passty_public.asc"
    privkey_path = r"D:\Code\Python\passtty\key\passty_secret.asc"
    privkey_passphrase = "test"

    pubkey = load_public_key(pubkey_path)
    privkey = load_private_key(privkey_path, privkey_passphrase)

    phrase, password = generate_password().values()
    phrase_str = " ".join(phrase)

    path = write_encrypted_string(f"{phrase_str}\n{password}", "gmail", "mail", pubkey)
    print(path)

    with privkey.unlock(privkey_passphrase):
        decrypt_and_print(path, privkey)
