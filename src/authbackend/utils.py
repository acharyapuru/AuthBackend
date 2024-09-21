from functools import wraps
from rest_framework.exceptions import PermissionDenied

def login_checker(view_func):
    @wraps(view_func)
    def _wrapped_view(self, request, *args, **kwargs):
        # For class-based views, `self` is passed in, so we access `self.request.user`
        user = request.user if hasattr(request, 'user') else self.request.user

        if user and user.is_authenticated:
            raise PermissionDenied("You are already logged in")

        return view_func(self, request, *args, **kwargs)

    return _wrapped_view
