from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from app.models import User
from werkzeug.security import check_password_hash
from flask_login import current_user
from flask_bcrypt import Bcrypt

# Используйте Bcrypt из Flask-Bcrypt
bcrypt = Bcrypt()
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Такое имя уже существует.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Такая почта уже используется.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Запомнить меня')
    submit = SubmitField('Login')

class EditProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Почта', validators=[DataRequired(), Email()])
    old_password = PasswordField('Текущий пароль')
    new_password = PasswordField('Новый пароль')
    confirm_new_password = PasswordField('Подтверждение нового пароля', validators=[EqualTo('new_password')])
    submit = SubmitField('Сохранить изменения')

    def validate_old_password(self, old_password):
        user = User.query.filter_by(id=current_user.id).first()
        if not bcrypt.check_password_hash(user.password, old_password.data):
            raise ValidationError('Неверный текущий пароль.')

    def validate_new_password(self, new_password):
        if self.old_password.data == new_password.data:
            raise ValidationError('Новый пароль должен отличаться от текущего.')