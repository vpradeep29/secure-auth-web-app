import re
from wtforms.validators import ValidationError

PASSWORD_RULES = (
    (r'[A-Z]', 'an uppercase letter'),
    (r'[a-z]', 'a lowercase letter'),
    (r'\d', 'a digit'),
    (r'[^A-Za-z0-9]', 'a special character'),
)

def password_strength_error(password: str) -> str | None:
    '''Return the first password-policy failure, or None if all rules pass.'''
    for pattern, requirement in PASSWORD_RULES:
        if not re.search(pattern, password or ''):
            return f'Password must contain {requirement}.'
    return None

def password_strength(_form, field):
    '''WTForms-compatible validator for the registration form.'''
    message = password_strength_error(field.data or '')
    if message:
        raise ValidationError(message)
