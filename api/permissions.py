from rest_framework.permissions import BasePermission
from django.http.request import HttpRequest


class IsOwnerOrAdmin(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        return obj == request.user


class IsAnonymous(BasePermission):
    def has_permission(self, request: HttpRequest, view):
        if request.user.is_anonymous:
            return True
