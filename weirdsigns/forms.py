from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from werkzeug.utils import secure_filename
from wtforms import SubmitField, StringField, PasswordField, BooleanField,DecimalField
#from wtforms import DateField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email, Length, EqualTo

class FileUploadForm(FlaskForm):
    title = StringField("Caption", validators=[DataRequired()])
    wherefound = StringField("Where did you see this?", validators=[DataRequired()])
    photo = FileField(validators=[FileRequired(),FileAllowed(['jpg','jpeg','png'], 'Images only!')])
    long = DecimalField()
    lat = DecimalField()
    submit = SubmitField("Submit")

class RegistrationForm(FlaskForm):
    username = StringField("Username",validators=[DataRequired(), Length(min=2,max=20)])
    email = StringField("Email", validators=[DataRequired(),Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(),EqualTo("password")])
    iagree =  BooleanField("I agree to the terms and conditions above", validators=[DataRequired()])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(),Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")

class ForgotForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(),Email()])
    submit = SubmitField("Send Password Reset Link")

class ForgotChangeForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(),EqualTo("password")])
    submit = SubmitField("Login")

class ChangeForm(FlaskForm):
    oldpassword = PasswordField("Old Password", validators=[DataRequired()])
    password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(),EqualTo("password")])
    submit = SubmitField("Change")

class SignSubmitByIdForm(FlaskForm):
    signids = StringField("idlist", validators=[DataRequired()])
    submit = SubmitField("show")
