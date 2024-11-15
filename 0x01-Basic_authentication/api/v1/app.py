#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404


# Add the 401 Unauthorized error handler
@app.errorhandler(401)
def unauthorized_error(error) -> str:
    """ Unauthorized handler """
    return jsonify({"error": "Unauthorized"}), 401


# New 403 error handler
@app.errorhandler(403)
def forbidden(error) -> str:
    """ Forbidden handler """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def authenticate_user():
    """Checks if a user is authorized before processing a request.

    For paths requiring authentication, validates the authorization header.
    Raises a 401 error if the header is missing, or a 403 error if the user
    cannot be authenticated. Skips authentication for paths
    in `excluded_paths`.

    Raises:
        401: Missing authorization header for protected routes.
        403: Unauthenticated user.
    """
    if auth:
        excluded_paths = [
            '/api/v1/status/',
            '/api/v1/unauthorized/',
            '/api/v1/forbidden/',
        ]
        if auth.require_auth(request.path, excluded_paths):
            auth_header = auth.authorization_header(request)
            user = auth.current_user(request)
            if auth_header is None:
                abort(401)
            if user is None:
                abort(403)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
