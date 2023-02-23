from flask import Flask
from flask_login import LoginManager

login_manager = LoginManager()

app = Flask(__name__)
login_manager.init_app(app)

@app.route('/')
def hello():
    return '<p>gkjghsdklfjghlskfj</p>'
