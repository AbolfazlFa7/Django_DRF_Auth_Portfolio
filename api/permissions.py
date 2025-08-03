from rest_framework.permissions import BasePermission


class IsOwnerOrAdmin(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        return obj == request.user


class IsAnonymous(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_anonymous:
            return True
