from odoo.http import Response

def set_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = 'http://localhost:5173/'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

def cors_dispatch(func):
    def wrapper(*args, **kwargs):
        response = func(*args, **kwargs)
        if isinstance(response, Response):
            return set_cors_headers(response)
        return response
    return wrapper
