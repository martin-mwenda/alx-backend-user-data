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

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """Extracts user credentials from a Base64-decoded authorization
        header for Basic Authentication.

        Args:
            dec_authorization_h (str): Decoded Base64 string containing
            user credentials.

        Returns:
            Tuple[str, str]: A tuple of (user, password) if valid,
            else (None, None).
        """
        if type(decoded_base64_authorization_header) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            field_match = re.fullmatch(
                    pattern,
                    decoded_base64_authorization_header()
                    )
            if field_match is not None:
                user = field_match.group('user')
                password = field_match.group('password')
                return user, password
        return None, None

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
        """Retrieves the user instance based on the Authorization header.

        Args:
            request: The Flask request object.

        Returns:
            User: The authenticated user instance, or None if not
            authenticated.
        """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
