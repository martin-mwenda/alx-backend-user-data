#!/usr/bin/env python3
"""
Password hashing and validation utilities.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Generate a salted, hashed password from a string input."""
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Check if a provided password matches the stored hashed password."""
    return bcrypt.checkpw(password.encode(), hashed_password)
