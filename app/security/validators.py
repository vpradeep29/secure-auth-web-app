import re
from wtforms.validators import ValidationError

def password_strength(_form, field):
    value = field.data or ''
    rules = ((r'[A-Z]', 'an uppercase letter'), (r'[a-z]', 'a lowercase letter'), (r'\d', 'a digit'), (r'[^A-Za-z0-9]', 'a special character'))
    for pattern, requirement in rules:
        if not re.search(pattern, value):
            raise ValidationError(f'Password must contain {requirement}.')
