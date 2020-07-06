from flask import render_template, flash, redirect, url_for, request, jsonify, send_from_directory
from wtforms.validators import ValidationError
from weirdsigns import app,db, bcrypt
from weirdsigns.forms import *
from weirdsigns.models import User
from bson import ObjectId, Decimal128
from flask_login import login_user, current_user, logout_user, login_required
import os, secrets, datetime, uuid

#For sending the media location
@app.route('/pictures/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

@app.route('/pictures/mostrecent')
def most_recent_file():
    filename = db.signs.find().sort([( '$natural', 1 )] ).limit(1)
    print(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               'deadrat.jpeg')

@app.route("/", methods=['GET', 'POST'])
@app.route("/home", methods=['GET', 'POST'])
def home():
    form = LoginForm()
    if form.validate_on_submit():
        user_dict = db.users.find_one({"email":form.email.data })
        if user_dict and bcrypt.check_password_hash(user_dict["password"],form.password.data):
            user = User(id=str(user_dict["_id"]), username=user_dict["username"])
            login_user(user, remember=form.remember.data)
            return redirect(url_for("home"))
        else:
            flash(f"Login unsuccessful!","danger")
    else:
        errors = [form.errors[k] for k in form.errors.keys()]
        flash(errors,"danger")
    #signs = db.signs.find().sort([( '$natural', 1 )] ).limit(10)
    #signs = None
    return render_template("home.html",form=form,home=True)


@app.route("/latest", methods=['GET', 'POST'])
def latest():
    signs = db.signs.find().sort([( '$natural', -1 )] ).limit(10)
    signs=list(signs)
    print(signs)
    for s in signs:
        s['created'] = s['created'].strftime("%d/%m/%Y, %H:%M:%S")
    return render_template("latest.html",home=True, signs=signs)


@app.route("/ratesign", methods=['POST'])
@login_required
def rate_sign():
    if current_user.is_authenticated:
        data = request.get_json(force=True)
        try:
            db.signs.update_one({"_id":ObjectId(data["signId"]),'ratings.user_id': {'$ne': ObjectId(current_user.id)}}, {"$addToSet": {"ratings":{"user_id":ObjectId(current_user.id),"rating":data["rating"] } }}, upsert=True)
        except Exception as e:
            print(e)
        print(data)
        print(ObjectId(current_user.id))
    return jsonify(success=True)


@app.route('/addsign', methods=['GET', 'POST'])
def addsign():
    if not current_user.is_authenticated:
        flash(f"Please login to upload a sign","danger")
        return redirect(url_for('login'))
    form = FileUploadForm();
    if form.validate_on_submit():
        f = form.photo.data
        filename = secure_filename(f.filename)
        ext = filename.split('.')[1]
        newfilename = uuid.uuid4().hex + '.' + ext
        filepath = os.path.join(app.instance_path, 'media/img', newfilename)
        f.save(filepath)
        print(app.instance_path)
        user_dict = db.users.find_one({"_id":ObjectId(current_user.get_id()) })
        del user_dict["password"]
        sign_dict = {  "title":form.title.data,
                        "wherefound":form.wherefound.data,
                        "file":newfilename,
                        "creator":user_dict,
                        "created":datetime.datetime.now(),
                        "long":Decimal128(form.long.data),
                        "lat":Decimal128(form.lat.data)
        }
        sign_id= db.signs.insert_one(sign_dict)
        return redirect(url_for('home'))
    return render_template('addsign.html', form=form)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        logout_user()
        return redirect(url_for("login"))
    form = RegistrationForm()
    if form.validate_on_submit():
        #Check username and password unique in database
        if db.users.find_one({"$or":[{"username":{'$regex': form.username.data, '$options': '-i'}},{"email":{'$regex': form.email.data, '$options': '-i'}}]}):
            flash(f"An account with this username or password already exists","danger")
        else:
            #proceed
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
            hash = secrets.token_hex(20)
            user_dict = {"username":form.username.data,"email":form.email.data,"password":hashed_password,"enabled":False,
                            "hash":hash,"dateregistered":datetime.datetime.now()}
            db.users.insert_one(user_dict)
            #Send verifitcation email
            #sendconfirmation(form.email.data, hash, form.username.data)
            flash(f"Account created for { form.username.data }!","success")
            flash(f"Please check your email and click on the link to verify your email address","warning")
    elif form.errors:
        errorstring = "You have the following errors on the form:"
        flash(errorstring,"danger")
        errorvals = [x[0] for x in list(form.errors.values())]
        errorlist = list(map(lambda x, y: x+ ': ' +y, list(form.errors.keys()), errorvals  ))
        for error in errorlist:
            flash(error,"danger")
            errorstring = errorstring + error
    return render_template("register.html", title="Register", form=form)

@app.route("/confirm/<string:confirm_hash>")
def confirm(confirm_hash):
    user = db.user.find_one({"hash":confirm_hash})
    if user:
        if user["dateregistered"] + datetime.timedelta(hours=1) > datetime.datetime.now():
            #Enable Account
            db.user.update_one(   { "_id": user["_id"] },
                                  { "$set": { "enabled": True} }
            )
            db.user.update_one(   { "_id": user["_id"] },
                                  { "$unset": { "hash": ""} }
            )
            flash("Account confrimed, please login below","success")
        else:
            db.user.delete_one( { "_id": user["_id"] } )
            flash("Sorry account has expired","danger")
    return redirect(url_for("login"))

@app.route("/forgot/<string:confirm_hash>", methods=["GET","POST"])
@app.route("/forgot", methods=["GET","POST"])
def forgot(confirm_hash=None):
    forgot = True #Change password mode is forgot
    forgotform = ForgotForm()
    form = ForgotChangeForm()
    if not confirm_hash:
        confirmed = False #For determining if sending email or changing the password
        if forgotform.validate_on_submit():
            forgothash = secrets.token_hex(20)
            db.user.update_one(   { "email": forgotform.email.data },
                                  { "$set": { "forgothash": forgothash, "dateforgot" : datetime.datetime.now() } }
            )
            sendforgot(forgotform.email.data, forgothash)
            flash(f"An email with a password reset link has been sent to this email address if it is registered on the system.","warning")
        elif forgotform.errors:
            errorstring = "You have the following errors on the form:"
            flash(errorstring,"danger")
            errorvals = [x[0] for x in list(forgotform.errors.values())]
            errorlist = list(map(lambda x, y: x+ ': ' +y, list(form.errors.keys()), errorvals  ))
            for error in errorlist:
                flash(error,"danger")
                errorstring = errorstring + error
    else:
        confirmed = True
        if form.validate_on_submit():
            user = db.user.find_one({"forgothash":confirm_hash})
            if user:
                if user["dateforgot"] + datetime.timedelta(hours=1) > datetime.datetime.now():
                    #Get password hash and update
                    hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
                    db.user.update_one(   { "_id": user["_id"] },
                                          { "$set": { "password": hashed_password} }
                    )
                    db.user.update_one(   { "_id": user["_id"] },
                                          { "$unset": { "forgothash": "","dateforgot": ""} }
                    )
                    flash("Password Rest, please login below","success")
                    return redirect(url_for("login"))
                else:
                    db.user.update_one(   { "_id": user["_id"] },
                                          { "$unset": { "forgothash": "","dateforgot": ""} }
                    )
                    flash("Sorry your password reset has expired, please try again","danger")
                    return redirect(url_for("forgot"))
        elif forgotform.errors:
            errorstring = "You have the following errors on the form:"
            flash(errorstring,"danger")
            errorvals = [x[0] for x in list(forgotform.errors.values())]
            errorlist = list(map(lambda x, y: x+ ': ' +y, list(form.errors.keys()), errorvals  ))
            for error in errorlist:
                flash(error,"danger")
                errorstring = errorstring + error
    return render_template("forgot.html", forgotform=forgotform, form=form, forgot=forgot, confirmed=confirmed)

@app.route("/changepassword", methods=["GET","POST"])
@login_required
def change():
    myid = ObjectId(current_user.get_id())
    form = ChangeForm()
    if form.validate_on_submit():
        user = db.user.find_one({"_id":myid})
        if user and bcrypt.check_password_hash(user["password"],form.oldpassword.data):
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
            db.user.update_one(   { "_id": user["_id"] },
                                  { "$set": { "password": hashed_password} }
            )
            flash("Password Rest, please login below","success")
            return redirect(url_for("home"))
        else:
            flash("Password change unsuccessfull, please check your old password and try again","danger")
    elif form.errors:
        flash("Password change unsuccessfull, please try again","danger")
    return render_template("change.html", form=form)


@app.route("/login", methods=["GET","POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = LoginForm()
    if form.validate_on_submit():
        user_dict = db.users.find_one({"email":form.email.data })
        if user_dict and bcrypt.check_password_hash(user_dict["password"],form.password.data):
            user = User(id=str(user_dict["_id"]), username=user_dict["username"])
            login_user(user, remember=form.remember.data)
            return redirect(url_for("home"))
        else:
            flash(f"Login unsuccessful!","danger")
    else:
        errors = [form.errors[k] for k in form.errors.keys()]
        flash(errors,"danger")
    return render_template("login.html", title="Login", form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))
