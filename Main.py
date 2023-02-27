from flask import Flask, render_template, request, redirect, flash
from flask_login import LoginManager, login_user, logout_user, current_user
from Auth import get_unlocked_user, lock_user, make_admin, new_user, unlock_user
from bson import ObjectId
from User import User, lock_expired
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
    if (not current_user.is_authenticated):
        return redirect("./login")
    return render_template("./home.html", page="home")


@app.route('/login')
def login_page():
    if (current_user.is_authenticated):
        return redirect("./")
    return render_template("./login.html", page="login")


@app.route('/login', methods=['POST'])
def login():
    try:
        user = get_unlocked_user(request.form.get("username"),
                                 request.form.get("password"))
        login_user(user)
        return redirect("./")
    except Exception as e:
        flash(str(e))
        return redirect("./login")


@app.route('/signup', methods=["POST"])
def signup():
    try:
        user = new_user(request.form.get("username"),
                        request.form.get("password"),
                        request.form.get("isAdmin"))
        login_user(user)
        return redirect("./")
    except Exception as e:
        flash(str(e))
        return redirect("./signup")


@app.route('/signup')
def signup_page():
    if (current_user.is_authenticated):
        return redirect("./")
    return render_template("./signup.html", page="signup")


@app.route("/lock", methods=["POST"])
def lock():
    if (current_user.is_authenticated and current_user.is_admin()):
        lock_user(request.form.get("username"))
        return redirect("/manageusers")
    return redirect("./home")


@app.route("/unlock", methods=["POST"])
def unlock():
    if (current_user.is_authenticated and current_user.is_admin()):
        unlock_user(request.form.get("username"))
        return redirect("/manageusers")
    return redirect("./home")


@app.route("/promote", methods=["POST"])
def promote():
    if (current_user.is_authenticated and current_user.is_admin()):
        make_admin(request.form.get("username"))
        return redirect("/manageusers")
    return redirect("./home")


@app.route("/manageusers")
def manage_users():
    if (current_user.is_authenticated and current_user.is_admin()):
        users = list(db["Users"].find())
        for user in users:
            if (user.get("locked") == True and lock_expired(user.get("locktime"))):
                unlock_user(user.get("username"))
                user.update({"locked": False})
        return render_template("./manageusers.html", users=users, page="manageusers.html")
    return render_template("./home.html", page="home")


@app.route('/logout')
def logout():
    logout_user()
    return redirect("./")
