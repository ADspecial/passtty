import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from fraza.core import generate_password


AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
AES_TAG_SIZE = 16


def generate_aes_key() -> bytes:
    return os.urandom(32)


def encrypt(input_path: str, output_path: str, key: bytes) -> None:
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Неверная длиан AES-ключа")

    nonce = os.urandom(AES_NONCE_SIZE)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    with open(output_path, "wb") as f:
        f.write(nonce + ciphertext + tag)


def decrypt(input_path: str, output_path: str, key: bytes) -> None:
    with open(input_path, "rb") as f:
        data = f.read()

    nonce = data[:AES_NONCE_SIZE]
    tag = data[-AES_TAG_SIZE:]
    ciphertext = data[AES_NONCE_SIZE:-AES_TAG_SIZE]

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(output_path, "wb") as f:
        f.write(plaintext)


def decrypt_and_print(input_path: str, key: bytes) -> None:
    with open(input_path, "rb") as f:
        data = f.read()

    nonce = data[:AES_NONCE_SIZE]
    tag = data[-AES_TAG_SIZE:]
    ciphertext = data[AES_NONCE_SIZE:-AES_TAG_SIZE]

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    print(plaintext.decode("utf-8"))


def create_file(text: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def write_encrypted_string(
    text: str, filename: str, output_dir: str, key: bytes
) -> str:
    """Шифрует строку и сохраняет в файл с указанным именем. Возвращает путь к файлу."""
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Неверная длина AES-ключа")

    # Убедимся, что директория существует
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, f"{filename}.enc")

    nonce = os.urandom(AES_NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode("utf-8")) + encryptor.finalize()
    tag = encryptor.tag

    with open(output_path, "wb") as f:
        f.write(nonce + ciphertext + tag)

    return output_path


if __name__ == "__main__":
    key = generate_aes_key()
    print(f"AES-ключ {key.hex()}")
    phrase, password = generate_password().values()
    phrase_str = " ".join(phrase)
    path = write_encrypted_string(f"{phrase_str}\n{password}", "gmail", "mail", key)
    print(path)
    decrypt_and_print(path, key)
