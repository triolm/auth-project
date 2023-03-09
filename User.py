from flask_login import UserMixin
import time


class User (UserMixin):
    def __init__(self, user):
        self.json = user

    def get_id(self):
        # return str(self.json.get("_id"))
        return self.json.get("username")

    def is_authenticated(self):
        return True

    def is_active(self):
        return not self.locked()

    def is_anonymous(self):
        return False

    def get_username(self):
        return self.json.get("username")

    def is_admin(self):
        return bool(self.json.get("isAdmin"))

    def check_lock(self):
        if (self.json.get("locked")
           and lock_expired(self.json.get("locktime"))):
            self.json.update({"locked": False})

    def locked(self):
        self.check_lock()
        return self.json.get("locked")


def lock_expired(locktime):
    # return time.time() - locktime > 10
    return time.time() - locktime > 60 * 60
