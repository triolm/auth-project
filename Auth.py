import hashlib
import secrets
import pymongo
from User import User

# username should be lowercase

db = pymongo.MongoClient("mongodb://localhost:27017/")["authApp"]


def hashPassword(password, salt):
    salty = password + salt
    return hashlib.sha256(salty.encode()).hexdigest()


def newUser(username, password, isAdmin=False):
    if (db["Users"].find_one({"username": username})):
        raise Exception("Username already in use")

    salt = secrets.token_hex(16)

    db["Users"].insert_one({"username": username,
                            "password": hashPassword(password, salt),
                            "isAdmin": isAdmin,
                            "salt": salt})
    return User(db["Users"].find_one({"username": username}))


def getUser(username, password):
    user = db["Users"].find_one({"username": username})
    if (user != None and user["password"] == hashPassword(password, user["salt"])):
        return User(user)
    return None


# newUser("123", "456")
