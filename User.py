from flask_login import UserMixin


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
