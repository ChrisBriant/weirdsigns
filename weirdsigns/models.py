from datetime import datetime
from weirdsigns import db, login_manager
from flask_login import UserMixin
from bson import ObjectId

class User:
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    def get_id(self):
        return self.id

    def get_username(self):
        return self.username

    @login_manager.user_loader
    def load_user(id):
        u = db.users.find_one({"_id":ObjectId(id)})
        if not u:
            return None
        return User(id=id,username=u["username"])
