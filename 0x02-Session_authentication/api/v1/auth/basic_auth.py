#!/usr/bin/env python3
"""Basic authentication module for the API."""

import re
import base64
import binascii
from typing import Tuple, TypeVar
from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Basic authentication class implementing helper methods
    for Basic Auth."""

    def extract_base64_authorization_header(
            self,
            authorization_header: str) -> str:
        """Extracts the Base64 part of the Authorization header for
        Basic Authentication.

        Args:
            authorization_header (str): The full Authorization header string.

        Returns:
            str: The Base64-encoded part of the header if valid, else None.
        """
        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            field_match = re.fullmatch(pattern, authorization_header.strip())
            if field_match is not None:
                return field_match.group('token')
        return None

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        """Decodes a Base64-encoded authorization header.

        Args:
            base64_authorization_header (str): The Base64-encoded
            string to decode.

        Returns:
            str: The decoded string if successful, else None.
        """
        if type(base64_authorization_header) == str:
            try:
                res = base64.b64decode(
                        base64_authorization_header,
                        validate=True)
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        """
        Returns the user email and password from the
        Base64 decoded value
        """

        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        credentials = decoded_base64_authorization_header.split(':', 1)

        return credentials[0], credentials[1]

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """Retrieves a user based on email and password credentials.

        Args:
            user_email (str): The user's email address.
            user_pwd (str): The user's password.

        Returns:
            User: The matching User object if found and valid, else None.
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ overloads Auth and retrieves the User instance for a request """
        auth_header = self.authorization_header(request)

        if not auth_header:
            return None

        encoded = self.extract_base64_authorization_header(auth_header)

        if not encoded:
            return None

        decoded = self.decode_base64_authorization_header(encoded)

        if not decoded:
            return None

        email, pwd = self.extract_user_credentials(decoded)

        if not email or not pwd:
            return None

        user = self.user_object_from_credentials(email, pwd)

        return user
