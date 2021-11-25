from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,UserMixin,login_user,login_required,logout_user,current_user

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import current_user
from flask_bcrypt import Bcrypt



import secrets
import os
from PIL import Image

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'


# forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class VideoForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    thumbnail = FileField('Upload Video Thumbnail', validators=[DataRequired(), FileAllowed(['jpg', 'png'])])
    video = FileField('Upload Video File', validators=[DataRequired(), FileAllowed(['mp4'])])
    submit = SubmitField('Upload')

class SearchForm(FlaskForm):
    search = StringField('Search', validators=[DataRequired()])
    submit = SubmitField('Search')
# models
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Video', backref='uploader', lazy=True)

class Video(db.Model):
    __searchable__ = ['title', 'video']
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    thumbnail = db.Column(db.String(20), nullable=False, default='default.jpg')
    video = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# routes
@app.route('/', methods=['GET', 'POST'])
def home():  # put application's code here
    videos = Video.query.all()
    search_form = SearchForm()
    if search_form.validate_on_submit():
        print(search_form.search.data)
        return redirect(url_for('search', query=search_form.search.data))
    return render_template('home.html',title='Home',videos=videos, search_form=search_form)

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been created. You can now login', 'success')
        return redirect(url_for('home'))
    search_form = SearchForm()
    if search_form.validate_on_submit():
        print(search_form.search.data)
        return redirect(url_for('search', query=search_form.search.data))
    return render_template('register.html', title='Register', form=form , search_form=search_form)

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    search_form = SearchForm()
    if search_form.validate_on_submit():
        print(search_form.search.data)
        return redirect(url_for('search', query=search_form.search.data))
    return render_template('login.html', title='Login', form=form, search_form=search_form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

def save_picture(form_picture,path):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, f'static/{path}', picture_fn)

    if path == "thumbnails":
        output_size = (125, 125)
        i = Image.open(form_picture)
        i.thumbnail(output_size)
        i.save(picture_path)
    elif path == "videos":
        form_picture.save(picture_path)
    return picture_fn

@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    form = VideoForm()
    if form.validate_on_submit():
        thumbnail_name = save_picture(form.thumbnail.data, 'thumbnails')
        video_name = save_picture(form.video.data, 'videos')
        video = Video(title=form.title.data, description=form.description.data, thumbnail=thumbnail_name, video=video_name, user_id=current_user.id)
        db.session.add(video)
        db.session.commit()
        flash('Your videos has been uploaded', 'success')
        return redirect(url_for('home'))
    search_form = SearchForm()
    if search_form.validate_on_submit():
        print(search_form.search.data)
        return redirect(url_for('search', query=search_form.search.data))
    return render_template('upload.html', title='Upload', form=form,search_form=search_form)

@app.route('/videos/<int:video_id>')
@login_required
def video(video_id):
    video = Video.query.get_or_404(video_id)
    search_form = SearchForm()
    if search_form.validate_on_submit():
        return redirect(url_for('search', query=search_form.search.data))
    return render_template('video.html', title=video.title, video=video, search_form=search_form)

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    user = User.query.get_or_404(user_id)
    videos = Video.query.filter_by(uploader=user).all()
    search_form = SearchForm()
    if search_form.validate_on_submit():
        return redirect(url_for('search', query=search_form.search.data))
    return render_template('profile.html', title='Profile', user=user, videos=videos,search_form=search_form)

@app.route("/search", methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        search = request.form.get('search')
        print(search)
        if search:
            search = "%{}%".format(search)
            results = Video.query.filter(Video.title.like(f"%{search}%"))
            print(results)
            search_form = SearchForm()
            if search_form.validate_on_submit():
                return redirect(url_for('search', query=search_form.search.data))
            return render_template('search.html', title='Search', results=results,search_form=search_form)
    return redirect(url_for('home'))
if __name__ == '__main__':
    app.run()
