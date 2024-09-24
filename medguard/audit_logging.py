from loguru import logger
from typing import List


class AccessControl:
    """
    A class to manage access control and audit logging for sensitive data operations.

    This class enforces role-based access control and logs all access to sensitive data.
    """

    def __init__(self, allowed_roles: List[str]) -> None:
        """
        Initialize the AccessControl class with a list of allowed roles.

        :param allowed_roles: A list of roles that are authorized to access sensitive data.
        """
        self.allowed_roles = allowed_roles
        logger.info(
            "AccessControl initialized with roles: {}", allowed_roles
        )

    def check_access(self, user_role: str, action: str) -> bool:
        """
        Check if a user with a specific role is allowed to perform an action.

        :param user_role: The role of the user attempting to perform the action.
        :param action: The action the user is attempting to perform.
        :return: True if access is granted, False otherwise.
        """
        if user_role in self.allowed_roles:
            logger.info(
                f"Access granted for role '{user_role}' to perform action: {action}"
            )
            return True
        else:
            logger.warning(
                f"Access denied for role '{user_role}' to perform action: {action}"
            )
            return False


# Example usage
# if __name__ == "__main__":
#     acl = AccessControl(allowed_roles=["doctor", "nurse", "admin"])

#     user_role = "doctor"
#     action = "view_patient_record"

#     if acl.check_access(user_role, action):
#         print(f"{user_role} is allowed to {action}.")
#     else:
#         print(f"{user_role} is not allowed to {action}.")
