# -*- coding: utf-8 -*-

from odoo import models, fields, api

class ResUsers(models.Model):
    _inherit = 'res.users'

    jwt_token = fields.Char(string='JWT Token')
    jwt_token_expiration = fields.Datetime(string='JWT Token Expiration')
