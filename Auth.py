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


def set_locked_status(username, status):
    db["Users"].update_one({
        'username': username
    }, {
        '$set': {
            'locktime': time.time(),
            'locked': status
        }
    }, upsert=False)


def lock_user(username):
    set_locked_status(username, True)


def unlock_user(username):
    set_locked_status(username, False)


def make_admin(username):
    db["Users"].update_one({
        'username': username
    }, {
        '$set': {
            'isAdmin': True
        }
    }, upsert=False)


def get_user(username, password):
    user = db["Users"].find_one({"username": username})
    userObj = User(user)
    if (user != None):
        if (user.get("password") == hashPassword(password, user["salt"])):
            if (userObj.locked() != user.get("locked")):
                set_locked_status(user.get(username), userObj.locked())
            return userObj

        fails = user.get("failedAttempts")
        if (fails == None):
            fails = [time.time()]
        else:
            fails.append(time.time())

            db["Users"].update_one({
                'username': username
            }, {
                '$set': {
                    'failedAttempts': fails
                }
            }, upsert=False)

            if (userObj.lock_possible):
                db["Users"].update_one({
                    'username': username
                }, {
                    '$set': {
                        'locked': True
                    }
                }, upsert=False)

    raise Exception("Username and password do not match")


def get_unlocked_user(username, password):
    user = get_user(username, password)
    if (user.locked()):
        raise Exception("Account locked")
    return user
