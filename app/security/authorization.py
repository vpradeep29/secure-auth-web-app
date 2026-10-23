from functools import wraps
from flask import abort
from flask_login import current_user

def admin_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if current_user.role != "admin":
            abort(403)
        return view_function(*args, **kwargs)
    return wrapped_view
