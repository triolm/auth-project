from flask_login import UserMixin
import time


class User (UserMixin):
    def __init__(self, user):
        self.json = user

    def get_id(self):
        return str(self.json.get("_id"))

    def is_authenticated(self):
        return True

    # def is_active(self):
    #     return self.active

    def is_anonymous(self):
        return False

    def get_username(self):
        return self.json.get("username")

    def is_admin(self):
        return self.json.get("isAdmin")

    def check_lock(self):
        if (self.json.get("locked")
           and lock_expired(self.json.get("locktime"))):
            self.json.update({"locked": False})

    def locked(self):
        self.check_lock()
        return self.json.get("locked")

    def lock_possible(self):
        if (self.json.get("failedAttempts") == None):
            return 0
        n = 0
        for i in self.json.get("failedAttempts"):
            if (not lock_expired(i)):
                n += 1
        return n


def lock_expired(locktime):
    return time.time() - locktime > 60 * 60
