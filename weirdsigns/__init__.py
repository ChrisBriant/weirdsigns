from flask import Flask
from flask_bootstrap import Bootstrap
from flask_datepicker import datepicker
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_pymongo import PyMongo,pymongo
from bson import ObjectId
import os

app = Flask(__name__, static_folder="static")

app.config["SECRET_KEY"] = "$2a$04$5NwD/PAOChKgbgZkGnE0h.wNzQ3d33UIoNQnAY17fxqbuvy2/l1Ga"
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'media/img/')

"""
@app.context_processor
def set_pagetitle(title="latest"):
    print(title)
    return dict(pagetitle=title)
    """

client = pymongo.MongoClient("mongodb+srv://Biceptio:WilliamTheWeak1ng!@cluster0-d1os1.mongodb.net/<dbname>?retryWrites=true&w=majority")
db = client.weirdsigns

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
Bootstrap(app)
datepicker(app)

from weirdsigns import routes
