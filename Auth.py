import hashlib
import secrets
import pymongo
from User import User
import re
import time

password_requirements = "(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*(\W)).{8,}"

# username should be lowercase
# what if user's account gets deleted while they're still signed in
# is admin can be null

db = pymongo.MongoClient("mongodb://localhost:27017/")["authApp"]


def hashPassword(password, salt):
    salty = password + salt
    return hashlib.sha256(salty.encode()).hexdigest()


def new_user(username, password, isAdmin=False):
    isAdmin = bool(isAdmin)
    if (not username or username == ""):
        raise Exception("Please enter a username")

    if (db["Users"].find_one({"username": username})):
        raise Exception("Username already in use")

    if (re.search(password_requirements, password) == None):
        raise Exception("Password not strong enough")

    salt = secrets.token_hex(16)

    db["Users"].insert_one({"username": username,
                            "password": hashPassword(password, salt),
                            "isAdmin": isAdmin,
                            "salt": salt,
                            "locktime": 0,
                            "locked": False})
    return User(db["Users"].find_one({"username": username}))


def lock_user(username):
    db["Users"].update_one({
        'username': username
    }, {
        '$set': {
            'locktime': time.time(),
            'locked': True
        }
    }, upsert=False)


def unlock_user(username):
    db["Users"].update_one({
        'username': username
    }, {
        '$set': {
            'locked': False
        }
    }, upsert=False)


def get_user(username, password):
    user = db["Users"].find_one({"username": username})
    if (user != None and user["password"] == hashPassword(password, user["salt"])):
        return User(user)
    raise Exception("Username and password do not match")


def get_unlocked_user(username, password):
    user = get_user(username, password)
    if (user.locked()):
        raise Exception("Account locked")
    return user
