# -*- coding: utf-8 -*-

from . import controllers
from . import models

from . import controllers

# def add_cors_middleware():
#     from odoo.http import root, request, Response
#
#     def cors_start_response(status, headers, exc_info=None):
#         headers.append(('Access-Control-Allow-Origin', '*'))
#         headers.append(('Access-Control-Allow-Methods', 'POST, GET, OPTIONS'))
#         headers.append(('Access-Control-Allow-Headers', 'Content-Type, Authorization'))
#         return original_start_response(status, headers, exc_info)
#
#     original_start_response = root.start_response
#     root.start_response = cors_start_response

    # @root.route('/api/login', methods=['OPTIONS'], auth='none')
    # def options_login():
    #     headers = [
    #         ('Access-Control-Allow-Origin', '*'),
    #         ('Access-Control-Allow-Methods', 'POST, GET, OPTIONS'),
    #         ('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    #     ]
    #     return Response(status=200, headers=headers)

# Tambahkan middleware dan route OPTIONS saat modul diinisialisasi
# add_cors_middleware()
