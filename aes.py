import json
from medguard.secure_communications import SecureCommunicationAES

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
