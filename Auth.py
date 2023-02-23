import hashlib
import pymongo
import secrets

db = pymongo.MongoClient("mongodb://localhost:27017/")["authApp"]

# 745 80

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


def login(username, password):
    user = db["Users"].find_one({"username": username})
    if (user != None and user["password"] == hashPassword(password, user["salt"])):
        print("logged in")
    else:
        print("username and password do not match")

# newUser(input("username"), input("password"))
# newUser(input("username"), input("password"), True)

login(input("username"), input("password"))
