#!/usr/bin/env python3
""" End-to-end integration test"""

import requests

BASE_URL = 'http://localhost:5000'
EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


def register_user(email: str, password: str) -> None:
    """Test for validating user registration."""
    data = {"email": email, "password": password}
    response = requests.post(f'{BASE_URL}/users', data=data)

    msg = {"email": email, "message": "user created"}

    assert response.status_code == (
            200,
            f"Failed to register user: {response.text}"
            )
    assert response.json() == msg, f"Unexpected response: {response.text}"


def log_in_wrong_password(email: str, password: str) -> None:
    """Test for validating login with wrong password."""
    data = {"email": email, "password": password}
    response = requests.post(f'{BASE_URL}/sessions', data=data)

    assert response.status_code == (
            401,
            f"Unexpected status: {response.status_code}, {response.text}"
            )


def log_in(email: str, password: str) -> str:
    """Test for validating successful login."""
    data = {"email": email, "password": password}
    response = requests.post(f'{BASE_URL}/sessions', data=data)

    msg = {"email": email, "message": "logged in"}

    assert response.status_code == 200, f"Failed login: {response.text}"
    assert response.json() == msg, f"Unexpected response: {response.text}"

    return response.cookies.get("session_id")


def profile_unlogged() -> None:
    """Test for validating profile request without login."""
    cookies = {"session_id": ""}
    response = requests.get(f'{BASE_URL}/profile', cookies=cookies)

    assert response.status_code == (
            403,
            f"Unexpected status: {response.status_code}, {response.text}"
            )


def profile_logged(session_id: str) -> None:
    """Test for validating profile request logged in."""
    cookies = {"session_id": session_id}
    response = requests.get(f'{BASE_URL}/profile', cookies=cookies)

    msg = {"email": EMAIL}

    assert response.status_code == (
            200,
            f"Failed profile fetch: {response.text}"
            )
    assert response.json() == msg, f"Unexpected response: {response.text}"


def log_out(session_id: str) -> None:
    """Test for validating logout endpoint."""
    cookies = {"session_id": session_id}
    response = requests.delete(f'{BASE_URL}/sessions', cookies=cookies)

    msg = {"message": "Bienvenue"}

    assert response.status_code == 200, f"Failed to logout: {response.text}"
    assert response.json() == msg, f"Unexpected response: {response.text}"


def reset_password_token(email: str) -> str:
    """Test for validating password reset token."""
    data = {"email": email}
    response = requests.post(f'{BASE_URL}/reset_password', data=data)

    assert response.status_code == (
            200,
            f"Failed to get reset token: {response.text}"
            )

    reset_token = response.json().get("reset_token")
    assert reset_token, "Reset token is missing"

    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Test for validating password reset (update)."""
    data = {
            "email": email,
            "reset_token": reset_token,
            "new_password": new_password}
    response = requests.put(f'{BASE_URL}/reset_password', data=data)

    msg = {"email": email, "message": "Password updated"}

    assert response.status_code == (
            200,
            f"Failed to update password: {response.text}"
            )
    assert response.json() == msg, f"Unexpected response: {response.text}"


if __name__ == "__main__":

    # Register user
    register_user(EMAIL, PASSWD)

    # Test invalid login attempt
    log_in_wrong_password(EMAIL, NEW_PASSWD)

    # Test profile without login
    profile_unlogged()

    # Successful login
    session_id = log_in(EMAIL, PASSWD)

    # Test profile with valid session
    profile_logged(session_id)

    # Test logout
    log_out(session_id)

    # Reset password and update
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)

    # Test login with new password
    log_in(EMAIL, NEW_PASSWD)
