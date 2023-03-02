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
# what if login fails on account that doesn't exist
# what if an account is unlocked, should it require three more attempts to lock

db = pymongo.MongoClient("mongodb://localhost:27017/")["authApp"]


def hashPassword(password, salt):
    salty = password + salt
    return hashlib.sha256(salty.encode()).hexdigest()


def new_user(username, password, isAdmin=False):
    username = username.lower()
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


def set_locked_status(username, status):
    db["Users"].update_one({
        'username': username.lower()
    }, {
        '$set': {
            'locktime': time.time(),
            'locked': status
        }
    }, upsert=False)


def lock_user(username):
    set_locked_status(username.lower(), True)


def unlock_user(username):
    set_locked_status(username.lower(), False)


def make_admin(username):
    db["Users"].update_one({
        'username': username.lower()
    }, {
        '$set': {
            'isAdmin': True
        }
    }, upsert=False)


def get_user(username, password):
    username = username.lower()
    user = db["Users"].find_one({"username": username})
    userObj = User(user)
    if (user == None):
        raise Exception("Username and password do not match")

    if (user.get("password") == hashPassword(password, user["salt"])):
        if (userObj.locked() != user.get("locked")):
            set_locked_status(user.get(username), userObj.locked())
        return userObj

    fails = user.get("failedAttempts")

    if (fails == None):
        fails = [time.time()]
    else:
        fails.append(time.time())
        print(fails)

    db["Users"].update_one({
        'username': username
    }, {
        '$set': {
            'failedAttempts': fails
        }
    }, upsert=False)

    if (userObj.lock_possible()):
        lock_user(username)
        raise Exception("To many failed attempts; Account locked")

    raise Exception("Username and password do not match")


def get_unlocked_user(username, password):
    user = get_user(username, password)
    if (user.locked()):
        raise Exception("Account locked")
    return user
