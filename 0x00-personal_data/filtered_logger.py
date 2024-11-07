#!/usr/bin/env python3
"""
Module for handling Personal Data
"""

import re
from typing import List


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str
        ) -> str:
    """Filters a log line by obfuscating specified fields.
    """
    pattern = f"({'|'.join(fields)})=[^\\{separator}]*"
    return re.sub(pattern, lambda x: f"{x.group(1)}={redaction}", message)
