# -*- coding: utf-8 -*-
import json
import math
import logging
import jwt
from datetime import datetime, timedelta
from odoo import http, fields
from .auth_validation import authValidation, SECRET_KEY
import requests
from odoo import http
from odoo.http import request
from odoo import http, _, exceptions
from odoo.http import request

from .serializers import Serializer
from .exceptions import QueryFormatError
from odoo.exceptions import ValidationError



_logger = logging.getLogger(__name__)


def error_response(error, msg):
    return {
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": 200,
            "message": msg,
            "data": {
                "name": str(error),
                "debug": "",
                "message": msg,
                "arguments": list(error.args),

                "exception_type": type(error).__name__
            }
        }
    }

#
class OdooAPI(http.Controller):

    def _check_access(self, required_groups):
        """ Helper method to check if the current user belongs to any of the required groups. """
        user = request.env.user
        for group in required_groups:
            if user.has_group(group):
                return True
        return False

    # def _verify_jwt_token(self, token):
    #     try:
    #         decoded_token = jwt.decode(token, self.SECRET_KEY, algorithms=['HS256'])
    #         user_id = decoded_token['user_id']
    #         user = request.env['res.users'].browse([user_id])
    #         if user.jwt_token != token:
    #             raise jwt.InvalidTokenError('Token does not match')
    #         return user
    #     except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
    #         raise http.AuthenticationError(str(e))

    @http.route('/api/login', type='json', auth='public', methods=['POST'], csrf=False)
    def api_login(self, **kw):
        try:
            # Retrieve raw data and parse JSON manually
            params = json.loads(request.httprequest.data.decode())
            login = params.get('login')
            password = params.get('password')

            if not login :
                return {'status': 'error', 'message': 'Login and password required'}

            uid = request.session.authenticate(request.db, login, password)
            if uid:
                user = request.env['res.users'].browse([uid])

                # Generate JWT token
                expiration = datetime.utcnow() + timedelta(hours=1)
                token = jwt.encode({
                    'user_id': user.id,
                    'exp': expiration
                }, SECRET_KEY, algorithm='HS256')

                # Save the token and expiration in the user
                user.write({
                    'jwt_token': token,
                    'jwt_token_expiration': fields.Datetime.to_string(expiration)
                })

                return {
                    'status': 'success',
                    'user_id': user.id,
                    'session_id': request.session.sid,
                    'name': user.name,
                    'email': user.email,
                    'token': token
                }
            else:
                return {'status': 'error', 'message': 'Invalid credentials'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # @http.route('/api/login', type='json', auth='public', methods=['POST'], csrf=False)
    # def api_login(self, **kw):
    #     try:
    #         # Retrieve raw data and parse JSON manually
    #         params = json.loads(request.httprequest.data.decode())
    #         login = params.get('login')
    #         password = params.get('password')
    #
    #         if not login or not password:
    #             return {'status': 'error', 'message': 'Login and password required'}
    #
    #         uid = request.session.authenticate(request.db, login, password)
    #         if uid:
    #             user = request.env['res.users'].browse([uid])
    #             return {
    #                 'status': 'success',
    #                 'user_id': user.id,
    #                 'session_id': request.session.sid,
    #                 'name': user.name,
    #                 'email': user.email,
    #             }
    #         else:
    #             return {'status': 'error', 'message': 'Invalid credentials'}
    #     except Exception as e:
    #         return {'status': 'error', 'message': str(e)}


    # @http.route(
    #     '/auth/',
    #     type='json', auth='none', methods=["POST"], csrf=False)
    # def authenticate(self, *args, **post):
    #     try:
    #         login = post["login"]
    #     except KeyError:
    #         raise exceptions.AccessDenied(message='`login` is required.')
    #
    #     try:
    #         password = post["password"]
    #     except KeyError:
    #         raise exceptions.AccessDenied(message='`password` is required.')
    #
    #     try:
    #         db = post["db"]
    #     except KeyError:
    #         raise exceptions.AccessDenied(message='`db` is required.')
    #
    #     http.request.session.authenticate(db, login, password)
    #     res = request.env['ir.http'].session_info()
    #     return res

# class OdooAPI(http.Controller):
#     @http.route('/auth/', type='json', auth='none', methods=["POST"], csrf=False)
#     def authenticate(self, **post):
#             login = post.get("login")
#             password = post.get("password")
#             db = post.get("db")
#
#             # Check for missing parameters and raise appropriate exceptions
#             if not login:
#                 raise exceptions.AccessDenied(message='`login` is required.')
#             if not password:
#                 raise exceptions.AccessDenied(message='`password` is required.')
#             if not db:
#                 raise exceptions.AccessDenied(message='`db` is required.')
#
#             # Authenticate the user
#             try:
#                 request.session.authenticate(db, login, password)
#             except exceptions.AccessDenied:
#                 raise exceptions.AccessDenied(message='Invalid credentials.')
#
#             # Retrieve and return session info
#             res = request.env['ir.http'].session_info()
#             return res

    @http.route(
        '/object/<string:model>/<string:function>',
        type='json', auth='user', methods=["POST"], csrf=False)
    def call_model_function(self, model, function, **post):
        args = []
        kwargs = {}
        if "args" in post:
            args = post["args"]
        if "kwargs" in post:
            kwargs = post["kwargs"]
        model = request.env[model]
        result = getattr(model, function)(*args, **kwargs)
        return result

    @http.route(
        '/object/<string:model>/<int:rec_id>/<string:function>',
        type='json', auth='user', methods=["POST"], csrf=False)
    def call_obj_function(self, model, rec_id, function, **post):
        args = []
        kwargs = {}
        if "args" in post:
            args = post["args"]
        if "kwargs" in post:
            kwargs = post["kwargs"]
        obj = request.env[model].browse(rec_id).ensure_one()
        result = getattr(obj, function)(*args, **kwargs)
        return result

    # @http.route(
    #     '/api/<string:model>',
    #     type='http', auth='user', methods=['GET'], csrf=False)
    # def get_model_data(self, model, **params):
    #     try:
    #         records = request.env[model].search([])
    #     except KeyError as e:
    #         msg = "The model `%s` does not exist." % model
    #         res = error_response(e, msg)
    #         return http.Response(
    #             json.dumps(res),
    #             status=200,
    #             mimetype='application/json'
    #         )
    #
    #     if "query" in params:
    #         query = params["query"]
    #     else:
    #         query = "{*}"
    #
    #     if "order" in params:
    #         orders = json.loads(params["order"])
    #     else:
    #         orders = ""
    #
    #     if "filter" in params:
    #         filters = json.loads(params["filter"])
    #         records = request.env[model].search(filters, order=orders)
    #
    #     prev_page = None
    #     next_page = None
    #     total_page_number = 1
    #     current_page = 1
    #
    #     if "page_size" in params:
    #         page_size = int(params["page_size"])
    #         count = len(records)
    #         total_page_number = math.ceil(count/page_size)
    #
    #         if "page" in params:
    #             current_page = int(params["page"])
    #         else:
    #             current_page = 1  # Default page Number
    #         start = page_size*(current_page-1)
    #         stop = current_page*page_size
    #         records = records[start:stop]
    #         next_page = current_page+1 \
    #             if 0 < current_page + 1 <= total_page_number \
    #             else None
    #         prev_page = current_page-1 \
    #             if 0 < current_page - 1 <= total_page_number \
    #             else None
    #
    #     if "limit" in params:
    #         limit = int(params["limit"])
    #         records = records[0:limit]
    #
    #     try:
    #         serializer = Serializer(records, query, many=True)
    #         data = serializer.data
    #     except (SyntaxError, QueryFormatError) as e:
    #         res = error_response(e, e.msg)
    #         return http.Response(
    #             json.dumps(res),
    #             status=200,
    #             mimetype='application/json'
    #         )
    #
    #     res = {
    #         "count": len(records),
    #         "prev": prev_page,
    #         "current": current_page,
    #         "next": next_page,
    #         "total_pages": total_page_number,
    #         "result": data
    #     }
    #     return http.Response(
    #         json.dumps(res),
    #         status=200,
    #         mimetype='application/json'
    #     )

    @http.route('/api/<string:model>', type='http', auth='user', methods=['GET'], csrf=False)
    def get_model_data(self, model, **params):
        auth_header = request.httprequest.headers.get('Authorization')
        if not auth_header:
            return http.Response(
                json.dumps({'status': 'error', 'message': 'Missing Authorization header'}),
                status=401,
                mimetype='application/json'
            )

        token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header

        try:
            authValidation.verify_jwt_token(token)
        except http.AuthenticationError as e:
            return http.Response(
                json.dumps({'status': 'error', 'message': str(e)}),
                status=401,
                mimetype='application/json'
            )

        try:
            records = request.env[model].search([])
        except KeyError as e:
            msg = f"The model `{model}` does not exist."
            res = {'status': 'error', 'message': msg}
            return http.Response(
                json.dumps(res),
                status=400,
                mimetype='application/json'
            )

        if "query" in params:
            query = params["query"]
        else:
            query = "{*}"

        if "order" in params:
            orders = json.loads(params["order"])
        else:
            orders = ""

        if "filter" in params:
            filters = json.loads(params["filter"])
            records = request.env[model].search(filters, order=orders)

        prev_page = None
        next_page = None
        total_page_number = 1
        current_page = 1

        if "page_size" in params:
            page_size = int(params["page_size"])
            count = len(records)
            total_page_number = math.ceil(count / page_size)

            if "page" in params:
                current_page = int(params["page"])
            else:
                current_page = 1  # Default page Number
            start = page_size * (current_page - 1)
            stop = current_page * page_size
            records = records[start:stop]
            next_page = current_page + 1 \
                if 0 < current_page + 1 <= total_page_number \
                else None
            prev_page = current_page - 1 \
                if 0 < current_page - 1 <= total_page_number \
                else None

        if "limit" in params:
            limit = int(params["limit"])
            records = records[:limit]

        try:
            serializer = Serializer(records, query, many=True)
            data = serializer.data
        except (SyntaxError, QueryFormatError) as e:
            res = {'status': 'error', 'message': str(e)}
            return http.Response(
                json.dumps(res),
                status=400,
                mimetype='application/json'
            )

        res = {
            "count": len(records),
            "prev": prev_page,
            "current": current_page,
            "next": next_page,
            "total_pages": total_page_number,
            "result": data
        }
        return http.Response(
            json.dumps(res),
            status=200,
            mimetype='application/json'
        )

    @http.route(
        '/api/<string:model>/<int:rec_id>',
        type='http', auth='user', methods=['GET'], csrf=False)
    def get_model_rec(self, model, rec_id, **params):
        auth_header = request.httprequest.headers.get('Authorization')
        if not auth_header:
            return http.Response(
                json.dumps({'status': 'error', 'message': 'Missing Authorization header'}),
                status=401,
                mimetype='application/json'
            )

        token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header

        try:
            authValidation.verify_jwt_token(token)
        except http.AuthenticationError as e:
            return http.Response(
                json.dumps({'status': 'error', 'message': str(e)}),
                status=401,
                mimetype='application/json'
            )

        try:
            records = request.env[model].search([])
        except KeyError as e:
            msg = "The model `%s` does not exist." % model
            res = error_response(e, msg)
            return http.Response(
                json.dumps(res),
                status=200,
                mimetype='application/json'
            )

        if "query" in params:
            query = params["query"]
        else:
            query = "{*}"

        # TODO: Handle the error raised by `ensure_one`
        record = records.browse(rec_id).ensure_one()

        try:
            serializer = Serializer(record, query)
            data = serializer.data
        except (SyntaxError, QueryFormatError) as e:
            res = error_response(e, e.msg)
            return http.Response(
                json.dumps(res),
                status=200,
                mimetype='application/json'
            )

        return http.Response(
            json.dumps(data),
            status=200,
            mimetype='application/json'
        )

    @http.route('/api/<string:model>/', type='json', auth='user', methods=['POST'], csrf=False)
    def post_model_data(self, model, **post):
        auth_header = request.httprequest.headers.get('Authorization')
        if not auth_header:
            return http.Response(
                json.dumps({'status': 'error', 'message': 'Missing Authorization header'}),
                status=401,
                mimetype='application/json'
            )

        token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header

        try:
            authValidation.verify_jwt_token(token)
        except exceptions.AccessDenied as e:
            return http.Response(
                json.dumps({'status': 'error', 'message': str(e)}),
                status=401,
                mimetype='application/json'
            )

        try:
            data = post['data']
        except KeyError:
            msg = "`data` parameter is not found in POST request body"
            return http.Response(
                json.dumps({'status': 'error', 'message': msg}),
                status=400,
                mimetype='application/json'
            )

        try:
            model_to_post = request.env[model]
        except KeyError:
            msg = f"The model `{model}` does not exist."
            return http.Response(
                json.dumps({'status': 'error', 'message': msg}),
                status=400,
                mimetype='application/json'
            )

        try:
            # Handle data validation if necessary
            if "context" in post:
                context = post["context"]
                record = model_to_post.with_context(**context).create(data)
            else:
                record = model_to_post.create(data)

            res = {

                'status': 201,
                'message': f'Record successfully created in model {model}',
                'record_id': record.id,
                'input_data': data  # Include the input data in the response

            }
            # response = request.make_response(
            #     json.dumps(res),
            #     headers=[('Content-Type', 'application/json')],
            #     status=201
            # )
            return res
        except exceptions.ValidationError as e:
            msg = str(e)
            return http.Response(
                json.dumps({'status': 'error', 'message': msg}),
                status=400,
                mimetype='application/json'
            )
        except Exception as e:
            msg = str(e)
            return http.Response(
                json.dumps({'status': 'error', 'message': msg}),
                status=500,
                mimetype='application/json'
            )

    @http.route(
        '/api/<string:model>/<int:rec_id>/', type='json', auth="user", methods=['PUT'], csrf=False)
    def put_model_record(self, model, rec_id, **post):
        auth_header = request.httprequest.headers.get('Authorization')
        if not auth_header:
            return http.Response(
                json.dumps({'status': 'error', 'message': 'Missing Authorization header'}),
                status=401,
                mimetype='application/json'
            )

        token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header

        try:
            authValidation.verify_jwt_token(token)
        except http.AuthenticationError as e:
            return http.Response(
                json.dumps({'status': 'error', 'message': str(e)}),
                status=401,
                mimetype='application/json'
            )

        try:
            model_to_put = request.env[model]
        except KeyError:
            msg = "The model `%s` does not exist." % model
            raise exceptions.ValidationError(msg)

        data = post

        if "context" in data:
            context = data.pop("context")
            rec = model_to_put.with_context(**context).browse(rec_id).ensure_one()
        else:
            rec = model_to_put.browse(rec_id).ensure_one()

        try:
            rec.write(data)
            return {'result': True}
        except Exception as e:
            return {'result': False, 'error': str(e)}


    # This is for single record update
    @http.route(
        '/api/<string:model>/<int:rec_id>/',
        type='json', auth="user", methods=['PUT'], csrf=False)
    def put_model_record(self, model, rec_id, **post):
        auth_header = request.httprequest.headers.get('Authorization')
        if not auth_header:
            return http.Response(
                json.dumps({'status': 'error', 'message': 'Missing Authorization header'}),
                status=401,
                mimetype='application/json'
            )

        token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header

        try:
            authValidation.verify_jwt_token(token)
        except http.AuthenticationError as e:
            return http.Response(
                json.dumps({'status': 'error', 'message': str(e)}),
                status=401,
                mimetype='application/json'
            )

        try:
            data = post['data']
        except KeyError:
            msg = "`data` parameter is not found on PUT request body"
            raise exceptions.ValidationError(msg)

        try:
            model_to_put = request.env[model]
        except KeyError:
            msg = "The model `%s` does not exist." % model
            raise exceptions.ValidationError(msg)

        if "context" in post:
            # TODO: Handle error raised by `ensure_one`
            rec = model_to_put.with_context(**post["context"])\
                .browse(rec_id).ensure_one()
        else:
            rec = model_to_put.browse(rec_id).ensure_one()

        # TODO: Handle data validation
        for field in data:
            if isinstance(data[field], dict):
                operations = []
                for operation in data[field]:
                    if operation == "push":
                        operations.extend(
                            (4, rec_id, _)
                            for rec_id
                            in data[field].get("push")
                        )
                    elif operation == "pop":
                        operations.extend(
                            (3, rec_id, _)
                            for rec_id
                            in data[field].get("pop")
                        )
                    elif operation == "delete":
                        operations.extend(
                            (2, rec_id, _)
                            for rec_id
                            in data[field].get("delete")
                        )
                    else:
                        data[field].pop(operation)  # Invalid operation

                data[field] = operations
            elif isinstance(data[field], list):
                data[field] = [(6, _, data[field])]  # Replace operation
            else:
                pass

        try:
            return rec.write(data)
        except Exception as e:
            # TODO: Return error message(e.msg) on a response
            return False

    # This is for bulk update
    @http.route(
        '/api/<string:model>/',
        type='json', auth="user", methods=['PUT'], csrf=False)
    def put_model_records(self, model, **post):
        auth_header = request.httprequest.headers.get('Authorization')
        if not auth_header:
            return http.Response(
                json.dumps({'status': 'error', 'message': 'Missing Authorization header'}),
                status=401,
                mimetype='application/json'
            )

        token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header

        try:
            authValidation.verify_jwt_token(token)
        except http.AuthenticationError as e:
            return http.Response(
                json.dumps({'status': 'error', 'message': str(e)}),
                status=401,
                mimetype='application/json'
            )

        try:
            data = post['data']
        except KeyError:
            msg = "`data` parameter is not found on PUT request body"
            raise exceptions.ValidationError(msg)

        try:
            model_to_put = request.env[model]
        except KeyError:
            msg = "The model `%s` does not exist." % model
            raise exceptions.ValidationError(msg)

        # TODO: Handle errors on filter
        filters = post["filter"]

        if "context" in post:
            recs = model_to_put.with_context(**post["context"])\
                .search(filters)
        else:
            recs = model_to_put.search(filters)

        # TODO: Handle data validation
        for field in data:
            if isinstance(data[field], dict):
                operations = []
                for operation in data[field]:
                    if operation == "push":
                        operations.extend(
                            (4, rec_id, _)
                            for rec_id
                            in data[field].get("push")
                        )
                    elif operation == "pop":
                        operations.extend(
                            (3, rec_id, _)
                            for rec_id
                            in data[field].get("pop")
                        )
                    elif operation == "delete":
                        operations.extend(
                            (2, rec_id, _)
                            for rec_id in
                            data[field].get("delete")
                        )
                    else:
                        pass  # Invalid operation

                data[field] = operations
            elif isinstance(data[field], list):
                data[field] = [(6, _, data[field])]  # Replace operation
            else:
                pass

        if recs.exists():
            try:
                return recs.write(data)
            except Exception as e:
                # TODO: Return error message(e.msg) on a response
                return False
        else:
            # No records to update
            return True

    # This is for deleting one record
    @http.route('/api/<string:model>/<int:rec_id>/', type='http', auth='user', methods=['DELETE'], csrf=False)
    def delete_model_record(self, model, rec_id, **post):
        auth_header = request.httprequest.headers.get('Authorization')
        if not auth_header:
            return http.Response(
                json.dumps({'status': 'error', 'message': 'Missing Authorization header'}),
                status=401,
                mimetype='application/json'
            )

        token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header

        try:
            authValidation.verify_jwt_token(token)
        except http.AuthenticationError as e:
            return http.Response(
                json.dumps({'status': 'error', 'message': str(e)}),
                status=401,
                mimetype='application/json'
            )

        try:
            model_to_del_rec = request.env[model]
        except KeyError as e:
            msg = f"The model `{model}` does not exist."
            res = {'status': 'error', 'message': msg}
            return http.Response(
                json.dumps(res),
                status=400,
                mimetype='application/json'
            )

        rec = model_to_del_rec.browse(rec_id)
        if not rec.exists():
            return http.Response(
                json.dumps({'status': 'error', 'message': 'Record not found'}),
                status=404,
                mimetype='application/json'
            )

        try:
            rec.ensure_one()  # Ensure that we are dealing with a single record
            deleted_record_info = {
                "model": model,
                "record_id": rec.id,
                "record_name": rec.name_get()[0][1] if rec.name else "Unnamed record"
            }
            is_deleted = rec.unlink()
            if is_deleted:
                res = {
                    "status": "success",
                    "message": "Record successfully deleted",
                    "deleted_record": deleted_record_info
                }
                return http.Response(
                    json.dumps(res),
                    status=200,
                    mimetype='application/json'
                )
            else:
                res = {
                    "status": "error",
                    "message": "Failed to delete record"
                }
                return http.Response(
                    json.dumps(res),
                    status=400,
                    mimetype='application/json'
                )
        except Exception as e:
            res = {'status': 'error', 'message': str(e)}
            return http.Response(
                json.dumps(res),
                status=400,
                mimetype='application/json'
            )

    # This is for bulk deletion
    @http.route(
        '/api/<string:model>/',
        type='http', auth="user", methods=['DELETE'], csrf=False)
    def delete_model_records(self, model, **post):
        auth_header = request.httprequest.headers.get('Authorization')
        if not auth_header:
            return http.Response(
                json.dumps({'status': 'error', 'message': 'Missing Authorization header'}),
                status=401,
                mimetype='application/json'
            )

        token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header

        try:
            authValidation.verify_jwt_token(token)
        except http.AuthenticationError as e:
            return http.Response(
                json.dumps({'status': 'error', 'message': str(e)}),
                status=401,
                mimetype='application/json'
            )
        filters = json.loads(post["filter"])

        try:
            model_to_del_rec = request.env[model]
        except KeyError as e:
            msg = "The model `%s` does not exist." % model
            res = error_response(e, msg)
            return http.Response(
                json.dumps(res),
                status=200,
                mimetype='application/json'
            )

        # TODO: Handle error raised by `filters`
        recs = model_to_del_rec.search(filters)

        try:
            is_deleted = recs.unlink()
            res = {
                "result": is_deleted
            }
            return http.Response(
                json.dumps(res),
                status=200,
                mimetype='application/json'
            )
        except Exception as e:
            res = error_response(e, str(e))
            return http.Response(
                json.dumps(res),
                status=200,
                mimetype='application/json'
            )

    @http.route(
        '/api/<string:model>/<int:rec_id>/<string:field>',
        type='http', auth="user", methods=['GET'], csrf=False)
    def get_binary_record(self, model,  rec_id, field, **post):
        auth_header = request.httprequest.headers.get('Authorization')
        if not auth_header:
            return http.Response(
                json.dumps({'status': 'error', 'message': 'Missing Authorization header'}),
                status=401,
                mimetype='application/json'
            )

        token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header

        try:
            authValidation.verify_jwt_token(token)
        except http.AuthenticationError as e:
            return http.Response(
                json.dumps({'status': 'error', 'message': str(e)}),
                status=401,
                mimetype='application/json'
            )

        try:
            request.env[model]
        except KeyError as e:
            msg = "The model `%s` does not exist." % model
            res = error_response(e, msg)
            return http.Response(
                json.dumps(res),
                status=200,
                mimetype='application/json'
            )

        rec = request.env[model].browse(rec_id).ensure_one()
        if rec.exists():
            src = getattr(rec, field).decode("utf-8")
        else:
            src = False
        return http.Response(
            src
        )

# class hallowApi (http.Controller):
#     @http.route('/api', auth='public', website=False, type='http', methods=['GET'], csrf=False)
#     def hello(self, **kw):
#         return "hello wordllll"
#
#     @http.route('/api/auth', type='json', auth='none', methods=['POST'], csrf=False)
#     def api_login(self, **kw):
#         params = request.jsonrequest
#         login = params.get('login')
#         password = params.get('password')
#
#         if not login or not password:
#             return {'status': 'error', 'message': 'Login and password required'}
#
#         uid = request.session.authenticate(request.db, login, password)
#         if uid:
#             user = request.env['res.users'].browse([uid])
#             return {
#                 'status': 'success',
#                 'user_id': user.id,
#                 'session_id': request.session.sid,
#                 'name': user.name,
#                 'email': user.email,
#             }
#         else:
#             return {'status': 'error', 'message': 'Invalid credentials'}
#
# class HrEmployeeAPI(http.Controller):
#
#     @http.route('/api/hr/employees', type='http', auth='none', methods=['GET'], csrf=False)
#     def get_employees(self, **kwargs):
#         api_key = request.httprequest.headers.get('X-API-Key')
#         if not api_key or api_key != 'odoo1234':
#             return request.make_response(json.dumps({'error': 'Unauthorized'}),
#                                          headers=[('Content-Type', 'application/json')], status=401)
#
#         employees = request.env['hr.employee'].sudo().search([])
#
#         # Urutkan karyawan berdasarkan ID
#         sorted_employees = sorted(employees, key=lambda x: x.id)
#
#         employee_data = []
#         for employee in sorted_employees:
#             employee_data.append({
#                 'id': employee.id,
#                 'name': employee.name,
#                 'department': employee.department_id.name,
#                 'job_title': employee.job_id.name,
#                 'work_email': employee.work_email,
#             })
#         return request.make_response(json.dumps(employee_data), headers=[('Content-Type', 'application/json')])
