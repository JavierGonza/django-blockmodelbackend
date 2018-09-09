# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from ipware import get_client_ip

from .models import IpBlock, UserBlock


UserModel = get_user_model()
BLOCK_TYPE = getattr(settings, "BLOCK_TYPE", "both")


class BlockModelBackendException(ValidationError):
    pass


class BlockModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if BLOCK_TYPE in ('both', 'ip'):
            ip = get_client_ip(request)[0]
            try:
                block_ip = IpBlock.objects.get(ip=ip)
            except IpBlock.DoesNotExist:
                block_ip = IpBlock.create(ip=ip)
            else:
                if block_ip.is_blocked:
                    raise BlockModelBackendException(_("IP blocked."))

        # procesa el usuario
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        try:
            user = UserModel._default_manager.get_by_natural_key(username)
        except UserModel.DoesNotExist:
            if BLOCK_TYPE in ('both', 'ip'):
                block_ip.fail_access()
            UserModel().set_password(password)
        else:
            if BLOCK_TYPE in ('both', 'user'):
                block_user = UserBlock.objects.get_or_create(user=user.username)[0]
                if block_user.is_blocked:
                    raise ValidationError(_("Username blocked."))
            if self.user_can_authenticate(user):
                if user.check_password(password):
                    if BLOCK_TYPE in ('both', 'ip'):
                        block_ip.unlock()
                    if BLOCK_TYPE in ('both', 'user'):
                        block_user.unlock()
                    return user
                else:
                    if BLOCK_TYPE in ('both', 'user'):
                        block_user.fail_access()
