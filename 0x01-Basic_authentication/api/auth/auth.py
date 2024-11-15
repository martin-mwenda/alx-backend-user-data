#!/usr/bin/env python3
"""Authentication module for the API.
Handles the authentication processes including checking authorization
requirements, retrieving authorization headers, and identifying
the current user.
"""

import re
from typing import List, TypeVar
from flask import request


class Auth:
    """A class to manage API authentication.

    Provides mechanisms to determine if a request path requires authentication,
    retrieve authorization headers from requests, and identify
    the current user.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checks if a path requires authentication.

        Determines if a specific API endpoint path should
        require authentication. A path does not require authentication
        if it matches any pattern in the list of excluded paths.

        Args:
            path (str): The request path to check.
            excluded_paths (List[str]): List of paths that do not
            require authentication.

        Returns:
            bool: True if the path requires authentication, False otherwise.
        """
        if path is not None and excluded_paths is not None:
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ''
                if exclusion_path[-1] == '*':
                    pattern = '{}.*'.format(exclusion_path[0:-1])
                elif exclusion_path[-1] == '/':
                    pattern = '{}/*'.format(exclusion_path[0:-1])
                else:
                    pattern = '{}/*'.format(exclusion_path)
                if re.match(pattern, path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """Gets the authorization header field from the request.

        Retrieves the 'Authorization' header from the request if available.

        Args:
            request (Flask request): The Flask request object.

        Returns:
            str: The authorization header value, or None if unavailable.
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Gets the current user from the request.

        This method is a placeholder for future functionality to
        identify the user making the request.

        Args:
            request (Flask request): The Flask request object.

        Returns:
            TypeVar('User'): None, as the method is currently a placeholder.
        """
        return None
