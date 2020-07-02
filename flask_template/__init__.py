from flask import Flask
from flask_bootstrap import Bootstrap
from flask_datepicker import datepicker



app = Flask(__name__, static_folder="static")

app.config["SECRET_KEY"] = "$2a$04$5NwD/PAOChKgbgZkGnE0h.wNzQ3d33UIoNQnAY17fxqbuvy2/l1Ga"

Bootstrap(app)
datepicker(app)

from flask_template import routes
