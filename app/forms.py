import re
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

def password_strength(_form, field):
    value = field.data or ""
    rules = [(r"[A-Z]", "an uppercase letter"), (r"[a-z]", "a lowercase letter"),
             (r"\\d", "a digit"), (r"[^A-Za-z0-9]", "a special character")]
    for pattern, requirement in rules:
        if not re.search(pattern, value):
            raise ValidationError(f"Password must contain {requirement}.")

class RegistrationForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=12, max=128), password_strength])
    confirm_password = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password", message="Passwords must match.")])
    submit = SubmitField("Create account")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=1, max=128)])
    submit = SubmitField("Sign in")
