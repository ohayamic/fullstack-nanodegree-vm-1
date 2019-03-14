from flask_wtf import FlaskForm
from catalog.catalogDB import User
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from catalog import db


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(max=45), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    signin = SubmitField("Sign In")


class SignUpForm(FlaskForm):
    username = StringField("UserName", validators=[DataRequired(), Length(max=25)])
    email = StringField("Email", validators=[DataRequired(), Length(max=45), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    signup = SubmitField("Sign Up")

    def validate_username(self, username):
        user = db.session.query(User).filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                "That username is taken. Please choose a different one."
            )

    def validate_email(self, email):
        user = db.session.query(User).filter_by(email=email.data).first()
        if user:
            raise ValidationError("That email is taken. Please choose a different one.")

