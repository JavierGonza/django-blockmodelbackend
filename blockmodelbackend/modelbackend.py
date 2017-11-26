# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ValidationError, ImproperlyConfigured
from django.utils.translation import ugettext_lazy as _
from ipware.ip import get_real_ip, get_ip

from .models import IpBlock, UserBlock


UserModel = get_user_model()
NETWORK_SCOPE = settings.get("NETWORK_SCOPE", "wan")


class BlockModelBackendException(ValidationError):
    pass


class BlockModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if NETWORK_SCOPE == "wan":
            ip = get_real_ip(request)
        elif NETWORK_SCOPE == "lan":
            ip = get_ip(request)
        else:
            raise ImproperlyConfigured(_("NETWORK_SCOPE property has a not valid value."))
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
            block_ip.fail_access()
            UserModel().set_password(password)
        else:
            try:
                block_user = UserBlock.objects.get(user=user)
            except UserBlock.DoesNotExist:
                block_user = UserBlock.create(user=user)
            else:
                if block_user.is_blocked:
                    raise ValidationError(_("Username blocked."))

            if self.user_can_authenticate(user):
                if user.check_password(password):
                    block_user.unlock()
                    block_ip.unlock()
                    return user
                else:
                    block_user.fail_access()
