#!/usr/bin/env python3
"""Module for filtering and logging user data while
obfuscating sensitive information."""

import os
import re
import logging
import mysql.connector
from typing import List

# Patterns for extracting and replacing sensitive data in log messages.
patterns = {
    'extract': lambda fields, separator: r'(?P<field>{})=[^{}]*'.format(
        '|'.join(fields), separator),
    'replace': lambda redaction: r'\g<field>={}'.format(redaction),
}

# Fields that contain personal information to be redacted from logs.
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str
        ) -> str:
    """Filters a log line to obfuscate sensitive fields using
    regular expressions.

    Args:
        fields (List[str]): List of field names (e.g., 'name', 'email')
        to redact. redaction (str): The value to replace sensitive fields
        with (e.g., '***'). message (str): The log message containing
        sensitive data. separator (str): The separator character used to
        split the fields in the message.

    Returns:
        str: The message with sensitive fields replaced by the
        redaction string.
    """
    # Use the defined patterns to extract and replace sensitive fields.
    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """Creates and returns a logger instance configured to log user data.

    Returns:
        logging.Logger: The logger instance.
    """
    # Initialize the logger with a stream handler and a custom formatter.
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Prevent propagation to root logger.
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Establishes and returns a connection to the MySQL database.

    Returns:
        mysql.connector.connection.MySQLConnection: The database connection.
    """
    # Fetch database credentials from environment variables or default values.
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")

    # Connect to the database.
    connection = mysql.connector.connect(
        host=db_host,
        port=3306,  # Default MySQL port.
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return connection


def main():
    """Fetches user records from the database and logs the data
    with redacted fields."""
    # Define the fields to be logged and redacted.
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')

    # SQL query to select all user data from the 'users' table.
    query = "SELECT {} FROM users;".format(fields)

    # Get the logger instance and the database connection.
    info_logger = get_logger()
    connection = get_db()

    # Execute the query and log the results.
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            # Create a log record by combining the column names and values.
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))  # Format the message.

            # Log the record using the logger.
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)  # Handle the log record.


class RedactingFormatter(logging.Formatter):
    """Formatter class that redacts sensitive fields in log messages."""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initializes the formatter with a list of fields to redact.

        Args:
            fields (List[str]): List of fields to redact.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields  # Fields to redact in the log message.

    def format(self, record: logging.LogRecord) -> str:
        """Formats the log record, redacting sensitive fields.

        Args:
            record (logging.LogRecord): The log record to format.

        Returns:
            str: The formatted log message with sensitive fields redacted.
        """
        # First format the message normally, then apply redaction.
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt


if __name__ == "__main__":
    main()
