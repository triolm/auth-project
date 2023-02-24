from flask import Flask, render_template, request, redirect
from flask_login import LoginManager, login_user, logout_user, current_user
from Auth import getUser, newUser
from bson import ObjectId
from User import User
import pymongo

db = pymongo.MongoClient("mongodb://localhost:27017/")["authApp"]

login_manager = LoginManager()

app = Flask(__name__)
login_manager.init_app(app)

app.config['SECRET_KEY'] = "THIS IS A BAD SECRET KEY"


@login_manager.user_loader
def load_user(user_id):
    return User(db["Users"].find_one(ObjectId(user_id)))


@app.route("/")
def index():
    print(type(current_user))
    if (not current_user.is_authenticated):
        return redirect("./login")
    return render_template("./home.html")


@app.route('/login')
def login_page():
    if (current_user.is_authenticated):
        return redirect("./")
    return render_template("./login.html")


@app.route('/login', methods=['POST'])
def login():
    user = getUser(request.form.get("username"), request.form.get("password"))
    login_user(user)
    return "logged in"


@app.route('/signup', methods=["POST"])
def signup():
    user = newUser(request.form.get("username"),
                   request.form.get("password"),
                   request.form.get("isAdmin"))
    print(request.form.get("isAdmin"))
    login_user(user)
    return render_template("./signup.html")


@app.route('/signup')
def signup_page():
    return render_template("./signup.html")


@app.route('/logout')
def logout():
    logout_user()
    return "logged out"
