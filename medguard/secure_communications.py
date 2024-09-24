import base64
import hashlib
import hmac
import json
import os
from typing import Dict, List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from loguru import logger


class SecureCommunicationAES:
    """
    A HIPAA-compliant class for encrypting and decrypting sensitive data using AES encryption.

    This class includes key management, audit logging, access control, HMAC for data integrity,
    and secure encryption to meet HIPAA standards.
    """

    def __init__(
        self, key: bytes = None, roles: List[str] = None
    ) -> None:
        """
        Initialize the SecureCommunicationAES class with an AES encryption key and access control roles.

        :param key: A byte string representing the AES encryption key.
                    If None, a new 256-bit (32-byte) key is generated.
        :param roles: A list of roles that are authorized to access sensitive data.
        """
        if key is None:
            self.key = os.urandom(32)  # AES-256 key (32 bytes)
            logger.info("Generated new AES encryption key.")
        else:
            self.key = key
        self.block_size = 128  # Block size for AES
        self.hmac_key = os.urandom(
            32
        )  # Key for HMAC for data integrity

        # Access control
        if roles is None:
            self.allowed_roles = ["admin", "doctor", "nurse"]
        else:
            self.allowed_roles = roles
        logger.info(
            "SecureCommunicationAES initialized with access control roles: {}",
            self.allowed_roles,
        )

    def _pad(self, data: bytes) -> bytes:
        """
        Apply padding to data to make it a multiple of the block size.

        :param data: The plaintext data to be padded.
        :return: Padded data as bytes.
        """
        padder = padding.PKCS7(self.block_size).padder()
        return padder.update(data) + padder.finalize()

    def _unpad(self, padded_data: bytes) -> bytes:
        """
        Remove padding from the data.

        :param padded_data: Padded data to be unpadded.
        :return: Unpadded data as bytes.
        """
        unpadder = padding.PKCS7(self.block_size).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def _generate_hmac(self, data: bytes) -> str:
        """
        Generate HMAC for the given data to ensure integrity.

        :param data: The data to generate HMAC for.
        :return: The HMAC value as a hex string.
        """
        return hmac.new(
            self.hmac_key, data, hashlib.sha256
        ).hexdigest()

    def check_access(self, user_role: str) -> bool:
        """
        Check if a user with a specific role is allowed to perform an action.

        :param user_role: The role of the user attempting to access or modify data.
        :return: True if access is granted, False otherwise.
        """
        if user_role in self.allowed_roles:
            logger.info(f"Access granted for role '{user_role}'.")
            return True
        else:
            logger.warning(
                f"Access denied for role '{user_role}'. Unauthorized access attempt logged."
            )
            return False

    def encrypt(self, data: str, user_role: str) -> Dict[str, str]:
        """
        Encrypt the given data using AES encryption if the user role is authorized.

        :param data: The plaintext data to encrypt (string or JSON).
        :param user_role: The role of the user requesting encryption.
        :return: A dictionary containing Base64 encoded IV, encrypted data, and HMAC.
        """
        if not self.check_access(user_role):
            raise PermissionError("Unauthorized access.")

        logger.info("Encrypting data using AES.")
        iv = os.urandom(
            16
        )  # Generate a random IV (Initialization Vector)
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()

        padded_data = self._pad(
            data.encode()
        )  # Pad data before encryption
        encrypted_data = (
            encryptor.update(padded_data) + encryptor.finalize()
        )

        # Generate HMAC for the encrypted data to ensure integrity
        hmac_value = self._generate_hmac(encrypted_data)

        logger.info("Data encrypted successfully.")
        return {
            "iv": base64.b64encode(iv).decode(),
            "encrypted_data": base64.b64encode(
                encrypted_data
            ).decode(),
            "hmac": hmac_value,
        }

    def decrypt(
        self, encrypted_payload: Dict[str, str], user_role: str
    ) -> str:
        """
        Decrypt the given AES encrypted data if the user role is authorized and the HMAC is valid.

        :param encrypted_payload: A dictionary containing the encrypted data, IV, and HMAC.
        :param user_role: The role of the user requesting decryption.
        :return: The decrypted plaintext data as a string.
        """
        if not self.check_access(user_role):
            raise PermissionError("Unauthorized access.")

        iv = base64.b64decode(encrypted_payload["iv"])
        encrypted_data = base64.b64decode(
            encrypted_payload["encrypted_data"]
        )
        received_hmac = encrypted_payload["hmac"]

        # Validate HMAC to ensure the integrity of the encrypted data
        expected_hmac = self._generate_hmac(encrypted_data)
        if not hmac.compare_digest(received_hmac, expected_hmac):
            logger.error(
                "HMAC validation failed. Data integrity compromised."
            )
            raise ValueError("Data integrity validation failed.")

        logger.info("HMAC validated successfully. Decrypting data.")
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        decrypted_padded_data = (
            decryptor.update(encrypted_data) + decryptor.finalize()
        )
        decrypted_data = self._unpad(decrypted_padded_data)

        logger.info("Data decrypted successfully.")
        return decrypted_data.decode()


# Example usage: Encrypting and decrypting a string or JSON with access control

if __name__ == "__main__":
    secure_comm = SecureCommunicationAES()

    # Encrypt a simple string with an authorized role
    user_role = "doctor"
    message = "This is sensitive health information."
    encrypted_message = secure_comm.encrypt(message, user_role)
    print(f"Encrypted payload: {encrypted_message}")

    # Decrypt the message with the same authorized role
    decrypted_message = secure_comm.decrypt(
        encrypted_message, user_role
    )
    print(f"Decrypted message: {decrypted_message}")

    # Attempt to encrypt with an unauthorized role
    try:
        unauthorized_role = "patient"
        encrypted_message = secure_comm.encrypt(
            message, unauthorized_role
        )
    except PermissionError as e:
        print(e)

    # Encrypt a JSON object
    sample_json = json.dumps(
        {
            "name": "John Doe",
            "ssn": "123-45-6789",
            "diagnosis": "Hypertension",
        }
    )
    encrypted_json = secure_comm.encrypt(sample_json, user_role)
    print(f"Encrypted JSON payload: {encrypted_json}")

    # Decrypt the JSON object
    decrypted_json = secure_comm.decrypt(encrypted_json, user_role)
    print(f"Decrypted JSON: {decrypted_json}")
