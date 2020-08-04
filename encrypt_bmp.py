from cryptography.hazmat.primitives.ciphers.modes import CTR
from aes_cbc_manager import EncryptionManager as CBCEncryptionManager
from aes_ctr_manager import EncryptionManager as CTREncryptionManager
import sys
import os
import argparse


def encryption_manager(mode):
    if mode == "cbc":
        return CBCEncryptionManager()
    elif mode == "ctr":
        return CTREncryptionManager()
    else:
        sys.stderr.write("Modes supported: ctr/cbc")
        exit(1)


def encrypt_image(manager, plaintext_path, ciphertext_path):
    with open(plaintext_path, "rb") as handle:
        with open(ciphertext_path, "wb") as dest:
            header = handle.read(58)
            dest.write(header)
            dest.write(manager.update_encryptor(handle.read()))
            dest.write(manager.finalize_encryptor())


def decrypt_image(manager, ciphertext_path, recovered_path):
    with open(ciphertext_path, "rb") as handle:
        with open(recovered_path, "wb") as dest:
            header = handle.read(58)
            dest.write(header)
            dest.write(manager.update_decryptor(handle.read()))
            dest.write(manager.finalize_decryptor())


def decrypt_image_with_corruption(
    manager, ciphertext_path, recovered_path, disort_bytes
):
    with open(ciphertext_path, "rb") as handle:
        with open(recovered_path, "wb") as dest:
            header = handle.read(58)
            dest.write(header)
            dest.write(
                manager.update_decryptor(
                    handle.read(number_of_bytes // 2 - disort_bytes)
                )
            )
            handle.read(disort_bytes)
            dest.write(manager.update_decryptor(b"\0" * disort_bytes))
            dest.write(manager.update_decryptor(handle.read()))
            dest.write(manager.finalize_decryptor())


if __name__ == "__main__":
    cli = argparse.ArgumentParser(usage="Encrypt/decrypt/play with bmp images")
    cli.add_argument(
        "--mode",
        type=str,
        required=True,
        choices=["ctr", "cbc"],
        help="AES encryption mode",
    )
    cli.add_argument("--source", type=str, required=True, help="Path for the bmp file")
    cli.add_argument("--dest", default=".", help="Ouput directory for the images")
    cli.add_argument(
        "--disort-n-bytes",
        type=int,
        help="Number of bytes to disort in the middle of the cyphertext",
    )
    args = cli.parse_args()
    mode: str = args.mode
    path: str = args.source
    dest_path = args.dest

    if not os.path.isfile(path) or not path.endswith(".bmp"):
        raise SystemExit(f"{path} is not an existing bmp image")

    number_of_bytes = os.stat(path).st_size - 58
    manager = encryption_manager(mode)
    basepath = os.path.basename(path)
    encrypted_path = os.path.join(dest_path, f"{mode}-encrypted-{basepath}")
    decrypted_path = os.path.join(dest_path, f"{mode}-decrypted-{basepath}")

    if os.path.isfile(encrypted_path):
        os.unlink(encrypted_path)
    if os.path.isfile(decrypted_path):
        os.unlink(decrypted_path)

    encrypt_image(manager, path, encrypted_path)
    if args.disort_n_bytes:
        decrypt_image_with_corruption(
            manager, encrypted_path, decrypted_path, args.disort_n_bytes
        )
    else:
        decrypt_image(manager, encrypted_path, decrypted_path)
    print("Encrypted path:", encrypted_path)
    print("Decryped path:", decrypted_path)
