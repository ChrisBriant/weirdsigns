from flask import render_template, flash, redirect, url_for, request, jsonify
from wtforms.validators import ValidationError
from flask_template import app
from flask_template.forms import *



@app.route("/", methods=['GET', 'POST'])
@app.route("/home", methods=['GET', 'POST'])
def home():
    return render_template("home.html")
