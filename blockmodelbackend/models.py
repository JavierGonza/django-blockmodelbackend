# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings
from django.db import models
from django.utils import timezone


MAX_ACCESS_ATTEMPTS = getattr(settings, "MAX_ACCESS_ATTEMPTS", 3)
LOCK_DURATION = getattr(settings, "LOCK_DURATION", 5)
DELTA_LOCK_DURATION = getattr(settings, "DELTA_LOCK_DURATION", 1)
USER_PERMANENT_BLOCK = getattr(settings, "USER_PERMANENT_BLOCK", False)
IP_PERMANENT_BLOCK = getattr(settings, "IP_PERMANENT_BLOCK", False)


def default_block_duration():
    return timezone.timedelta(0)


class BaseBlock(models.Model):
    access_atempts_number = models.IntegerField(default=0)
    last_atempt = models.DateTimeField(null=True)
    lock_duration = models.DurationField(default=default_block_duration)
    prev_locks_number = models.IntegerField(default=0)
    permanent_block = models.BooleanField(default=False)

    class Meta:
        abstract = True

    @classmethod
    def create(cls, **kwargs):
        block = cls(**kwargs)
        return block

    @property
    def is_blocked(self):
        return self.permanent or (self.last_atempt and self.last_atempt + self.lock_duration >= timezone.now())

    @property
    def permanent(self):
        return self.permanent_block

    def fail_access(self):
        self.access_atempts_number += 1
        if self.access_atempts_number >= MAX_ACCESS_ATTEMPTS:
            self.last_atempt = timezone.now()
            minutes = LOCK_DURATION * (DELTA_LOCK_DURATION * (self.prev_locks_number + 1) or 1.0)
            self.lock_duration = timezone.timedelta(minutes=minutes)
            self.access_atempts_number = 0
            self.prev_locks_number += 1
            self.permanent_block = self.permanent
        self.save()

    def unlock(self):
        if self.id:
            self.delete()


class UserBlock(BaseBlock):
    user = models.CharField(max_length=150, blank=False, unique=True)

    @property
    def permanent(self):
        return USER_PERMANENT_BLOCK


class IpBlock(BaseBlock):
    ip = models.GenericIPAddressField(blank=False, unique=True)

    @property
    def permanent(self):
        return IP_PERMANENT_BLOCK
