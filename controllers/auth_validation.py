import jwt
import os
import logging
from odoo import http
from odoo.http import request
from odoo import http, exceptions

_logger = logging.getLogger(__name__)

SECRET_KEY = 'your_secret_key_here'  # Ganti dengan kunci rahasia Anda

class authValidation:

    @staticmethod
    def verify_jwt_token(token):
        try:
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = request.env['res.users'].browse([user_id])
            if user.jwt_token != token:
                raise jwt.InvalidTokenError('Token does not match')
            return user
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            _logger.warning(f'JWT verification failed: {str(e)}')
            raise exceptions.AccessDenied(str(e))
