from rest_framework.permissions import BasePermission, SAFE_METHODS

class CreateAccountPerm(BasePermission):

    def has_permission(self, request, view):
        """
        Custom permission to only allow authenticated users with admin status to perform
        certain actions.
        """
        if request.method in SAFE_METHODS:
            return True
        if request.method == "POST":
            return request.user and request.user.is_authenticated and request.user.is_staff
        return False