from __future__ import annotations

from django.contrib.auth.mixins import AccessMixin
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy

from allauth_2fa.utils import user_has_valid_totp_device


class ValidTOTPDeviceRequiredMixin(AccessMixin):
    no_valid_totp_device_url = reverse_lazy("two-factor-setup")

    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        return (
            super().dispatch(request, *args, **kwargs)
            if user_has_valid_totp_device(request.user)
            else self.handle_missing_totp_device()
        )

    def handle_missing_totp_device(self) -> HttpResponse:
        return HttpResponseRedirect(self.no_valid_totp_device_url)
