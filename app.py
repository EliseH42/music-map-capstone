from numpy import empty
import pandas
from flask import (
    Flask, Blueprint, flash, g, redirect, render_template, request, session, url_for
    )
from flask_sqlalchemy import SQLAlchemy
import folium
from datetime import datetime
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, validators
from flask_wtf.file import FileField
from wtforms.validators import DataRequired, Length, ValidationError
from flask_login import LoginManager, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ["HEROKU_URI"]
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(50), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    joined_at = db.Column(db.DateTime(), default = datetime.utcnow, index = True)
    locations = db.relationship('Coord', backref='User', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self,password):
        return check_password_hash(self.password_hash,password)

    def is_authenticated(self):
        return login_correct(self.username, self.password_hash)

    def get_id(self):
        return self.id

    def is_active(self):
        return True

    def is_anonymous(self):
        return False


class Coord(db.Model):
    __tablename__ = "Coord"
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    userid = db.Column(db.ForeignKey('Users.id'), nullable=False)
    location = db.Column(db.String[50])
    latitude = db.Column(db.Float, nullable=False)
    longitude= db.Column(db.Float, nullable=False)
    songname = db.Column(db.String[30])
    songlink = db.Column(db.String[200])


def login_correct(username, password):
    user = User.query.filter_by(username=username).first()
    return user != None and user.check_password(password)

@login_manager.user_loader
def load_user(userid):
    return User.query.filter_by(id=userid).first()


class LoginForm(FlaskForm):
    username = StringField(name="Username",  validators= [DataRequired(), Length(3, 30)])
    password = PasswordField(name="Password",  validators= [DataRequired(), Length(3, 20)])

class RegisterForm(FlaskForm):
    username = StringField("Username",  validators= [DataRequired(), Length(3, 30)])
    password = PasswordField("Password", validators= [DataRequired(), Length(3, 20)])
    confirm = PasswordField('Repeat Password')

class LocationForm(FlaskForm):
    userid = User.id
    location = StringField(name="Location Name",  validators= [DataRequired(), Length(3, 30)])
    latitude  = StringField(name="Latitude",  validators= [DataRequired(), Length(2, 11)])
    longitude = StringField(name="Longitude",  validators= [DataRequired(), Length(2, 11)])
    songname = StringField(name="Song Name",  validators= [DataRequired(), Length(3, 30)])
    songlink = StringField(name="Song Link",  validators= [DataRequired(), Length(5, 200)])

def sorter(e):
    return float(e)

def load_map(userid):
    coords = Coord.query.filter_by(userid = userid).all()

    print(coords)

    lat = [i.latitude for i in coords]
    long = [i.longitude for i in coords]

    lat.sort(key = sorter)
    long.sort(key = sorter)
    median = len(lat) // 2

    if median == 0:
        lat.append(41.5)
        long.append(-101)

    map = folium.Map(location=[lat[median],long[median]], zoom_start=10, tiles='OpenStreetMap')
    fg = folium.FeatureGroup(name="myMap")
    
    for coord in coords:
        fg.add_child(folium.Marker(location=(coord.latitude, coord.longitude), popup = f'{coord.location}, <a href="{coord.songlink}", target="_blank">{coord.songname}</a>', icon = folium.Icon(color="blue")))
    map.add_child(fg)

    map.add_child(folium.LatLngPopup())
    map.save("./templates/Map1.html")


@app.route('/')
def index():

    return render_template("index.html")


@app.route('/maps', methods=['GET'])
@login_required
def maps():
    form = LocationForm(request.form)
    load_map(current_user.get_id())

    my_map = open("./templates/Map1.html").read()

    return render_template("maps.html", my_map=my_map, form=form)


@app.route('/map_helper')
def map_helper():

    return render_template("Map1.html")


@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()
    username = form.username.data
    password = form.password.data

    user = User.query.filter_by(username=username).first()

    if user.check_password(password):
        
        login_user(user, remember=True)
    else:
        flash('Invalid username/password')
        return render_template('login.html', form = form)
    return redirect(url_for('maps'))


@app.route('/login', methods=['GET'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('maps'))

    return render_template('login.html', form = LoginForm())


@app.route('/register', methods=['GET'])
def register_page():

    return render_template('register.html', form=RegisterForm())


@app.route('/register', methods=['POST'])
def register():
    form = RegisterForm(request.form)
    user = User(username = form.username.data,
            password_hash = generate_password_hash(form.password.data))

    login_user(user, remember=True)
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('maps'))


@app.route('/maps', methods=['POST'])
@login_required
def addsong():
    form = LocationForm(request.form)

    location = Coord(location = form.location.data,
                userid = current_user.get_id(),
                latitude = form.latitude.data,
                longitude = form.longitude.data,
                songname = form.songname.data,
                songlink = form.songlink.data)

    db.session.add(location)
    db.session.commit()

    load_map(current_user.get_id())

    return render_template("maps.html", form=LocationForm())


db.create_all()

if __name__ =="__main__":
    app.run(debug = False, port="5001")