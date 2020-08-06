from flask import render_template, flash, redirect, url_for, request, jsonify, send_from_directory
from wtforms.validators import ValidationError
from weirdsigns import app,db, bcrypt
from weirdsigns.forms import *
from weirdsigns.models import User
from weirdsigns.email import sendconfirmation, sendforgot
from bson import ObjectId, Decimal128
from flask_login import login_user, current_user, logout_user, login_required
import os, secrets, datetime, uuid, PIL
from bson.json_util import dumps
from PIL import Image


#Resize image
def resize_picture(size, file, path):
    img = PIL.Image.open(file)
    img = img.resize(size, PIL.Image.ANTIALIAS)
    img.save(path)


#Process the sign data
def process_signs(signs):
    for s in signs:
        s['created'] = s['created'].strftime("%d/%m/%Y, %H:%M:%S")
        if s.get('location'):
            #convert to long and lat
            s['long'] = s['location']['coordinates'][0]
            s['lat'] = s['location']['coordinates'][1]
            print(s['location']);
        if s.get("ratings") and current_user.is_authenticated:
            if ObjectId(current_user.id) in [rating['user_id'] for rating in s['ratings']]:
                s["already_rated"] = True
        else:
            s["already_rated"] = False
        #Set rating classes for easy output
        s['starclasses'] = []
        if s['AverageRating']:
            avgnearesthalf = round(s['AverageRating']*2)/2
            if not avgnearesthalf.is_integer():
                halfstar = True
            else:
                halfstar = False
            avgwholepart = avgnearesthalf // 1
            print(avgwholepart)
            for i in range(1,6):
                if i <= avgwholepart:
                    s['starclasses'].append('fa fa-star')
                elif halfstar:
                    s['starclasses'].append('fa fa-star-half')
                    halfstar = False
                else:
                    s['starclasses'].append('fa fa-star-o')
        if s.get('comments'):
            for c in s['comments']:
                c['date_posted'] = c['date_posted'].strftime("%d/%m/%Y, %H:%M:%S")
    return signs


#For sending the media location
@app.route('/pictures/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

@app.route('/pictures/mostrecent')
def most_recent_file():
    filename = db.signs.find().sort([( '$natural', -1 )] ).limit(1)
    return send_from_directory(app.config['UPLOAD_FOLDER'],filename[0]['file'])

@app.route("/", methods=['GET', 'POST'])
@app.route("/home", methods=['GET', 'POST'])
def home():
    message= ''
    form = LoginForm()
    if form.validate_on_submit():
        user_dict = db.users.find_one({"email":form.email.data })
        if user_dict["enabled"] and bcrypt.check_password_hash(user_dict["password"],form.password.data):
            user = User(id=str(user_dict["_id"]), username=user_dict["username"])
            login_user(user, remember=form.remember.data)
            return redirect(url_for("latest"))
        else:
            flash(u"Login unsuccessful!","danger")
            message = "Login unsuccessful!"
    else:
        print(form.errors)
    return render_template("home.html",form=form,home=True,message=message)


@app.route("/latest", methods=['GET', 'POST'])
def latest():
    #signs = db.signs.find().sort([( '$natural', -1 )] ).limit(10)
    signs = db.signs.aggregate([
        { '$addFields' : {
                'title' : '$title',
                'creator': '$creator',
                'created': '$created',
                'wherefound' : '$wherefound',
                'ratings' : '$ratings',
                'long' : '$long',
                'lat' : '$lat',
                'location': '$location',
                'file' : '$file',
                'AverageRating' : { '$avg': "$ratings.rating" },
                'NumberOfRatings': { '$size': { "$ifNull": [ "$ratings", [] ] } }
            }
        },
        { '$sort' : {
                'created' : -1,
            },
        },
        { '$limit' : 10 }
    ])
    #signs=list(signs)
    signs = process_signs(list(signs))
    return render_template("latest.html",home=True, signs=signs,title="latest")

@app.route("/popular", methods=['GET', 'POST'])
def popular():
    """
    signs = db.signs.aggregate([
       { '$match': { status: "A" } },
       { $group: { _id: "$cust_id", total: { $sum: "$amount" } } }
    ])
    """

    """
    signs = db.signs.aggregate(([
    { '$unwind': '$ratings' },
    {
        '$group': {
          '_id': '_id',
          'TotalRating': { '$sum': "ratings.rating" }
        }
      }
    ]))
    """

    """
    signs = db.signs.aggregate([
        {
            '$project' : {
                'title' : '$title',
                'creator': '$creator',
                'created': '$created',
                'wherefound' : '$wherefound',
                'ratings' : '$ratings',
                'long' : '$long',
                'lat' : '$lat',
                'file' : '$file',
                'AverageRating' : { '$avg': "$ratings.rating" }
            }
        }
    ])
    """

    signs = db.signs.aggregate([
        { '$addFields' : {
                'title' : '$title',
                'creator': '$creator',
                'created': '$created',
                'wherefound' : '$wherefound',
                'ratings' : '$ratings',
                'long' : '$long',
                'lat' : '$lat',
                'location': '$location',
                'file' : '$file',
                'AverageRating' : { '$avg': "$ratings.rating" },
                'NumberOfRatings': { '$size': { "$ifNull": [ "$ratings", [] ] } }
            }
        },
        { '$sort' : {
                'AverageRating' : -1,
                'NumberOfRatings': -1
            },
        },
        { '$limit' : 10 }
    ])
    signs=process_signs(list(signs))
    return render_template("latest.html",home=True, signs=signs, title="Most Popular")


@app.route("/bylocation", methods=['GET', 'POST'])
def bylocation():
    form = SignSubmitByIdForm()
    signs = None
    if form.validate_on_submit():
        #objectids = [{'_id':ObjectId(id)} for id in form.signids.data.split(',')]
        objectids = [ObjectId(id) for id in form.signids.data.split(',')]
        #print('here',objectids)
        #signs = db.signs.find(objectids)
        #signs=db.signs.find({ "_id": {'$in': objectids} })
        signs=db.signs.aggregate(
                [ { '$match' : {'_id': {'$in': objectids} } },
                { '$addFields' : {
                        'title' : '$title',
                        'creator': '$creator',
                        'created': '$created',
                        'wherefound' : '$wherefound',
                        'ratings' : '$ratings',
                        'long' : '$long',
                        'lat' : '$lat',
                        'location': '$location',
                        'file' : '$file',
                        'AverageRating' : { '$avg': "$ratings.rating" },
                        'NumberOfRatings': { '$size': { "$ifNull": [ "$ratings", [] ] } }
                    }
                }]
            )
        signs=process_signs(list(signs))
        print(signs)
        return render_template("latest.html", signs=signs, title="View By Location")
    else:
        print(form.errors)
        return render_template("bylocation.html", signs=signs, form=form)


@app.route("/ratesign", methods=['POST'])
@login_required
def rate_sign():
    if current_user.is_authenticated:
        data = request.get_json(force=True)
        try:
            db.signs.update_one({"_id":ObjectId(data["signId"]),'ratings.user_id': {'$ne': ObjectId(current_user.id)}}, {"$addToSet": {"ratings":{"user_id":ObjectId(current_user.id),"rating":int(data["rating"]) } }}, upsert=True)
        except Exception as e:
            print(e)
        print(data)
        print(ObjectId(current_user.id))
    return jsonify(success=True)

@app.route("/getsignswithin", methods=['POST'])
def signs_within():
    print('getsignswithin')
    data = request.get_json(force=True)

    signs = db.signs.find({
      'location': {
         '$geoWithin': {
            '$box': [
              [ data['extent'][0],data['extent'][1] ],
              [ data['extent'][2],data['extent'][3] ]
            ]
         }
      }
    }).limit(10)
    #print(dumps(list(signs)))
    #return jsonify(success=True)
    return dumps(list(signs)), 200, {'ContentType':'application/json'}


@app.errorhandler(413)
def largefile_error(e):
    print("Large file")
    return redirect(url_for("addsign")), 413


@app.route('/addsign', methods=['GET', 'POST'])
def addsign():
    if not current_user.is_authenticated:
        flash(f"Please login to upload a sign","danger")
        return redirect(url_for('home'))
    #try:
    form = FileUploadForm();
    """
    except Exception as e:
        print(e)
        flash(u"File size too large: please choose a file under 4mb","danger")
        return redirect(url_for("home"))
        """
    if form.validate_on_submit():
        f = form.photo.data
        filename = secure_filename(f.filename)
        ext = filename.split('.')[1]
        newfilename = uuid.uuid4().hex + '.' + ext
        filepath = os.path.join(app.instance_path, 'media/img', newfilename)
        #f.save(filepath)
        resize_picture((260, 180),form.photo.data,filepath)
        print(app.instance_path)
        user_dict = db.users.find_one({"_id":ObjectId(current_user.get_id()) })
        del user_dict["password"]
        sign_dict = {  "title":form.title.data,
                        "wherefound":form.wherefound.data,
                        "file":newfilename,
                        "creator":user_dict,
                        "created":datetime.datetime.now(),
                        "location": {
                            "type":"Point",
                            "coordinates" : [ Decimal128(form.long.data), Decimal128(form.lat.data)]
                        }

        }
        sign_id= db.signs.insert_one(sign_dict)
        return redirect(url_for('latest'))
    return render_template('addsign.html', form=form)


@app.route('/gosign/<string:object_id>', methods=['GET', 'POST'])
def gosign(object_id):
    if current_user.is_authenticated:
        username = current_user.get_username()
        userid = current_user.get_id()
    else:
        username = "Anonymous"
        userid = None
    form = CommentForm()
    if form.validate_on_submit():
        print("Here")
        db.signs.update_one(   { "_id": ObjectId(object_id) },
                              { "$push": { "comments": { "comment": form.comment.data.strip(),
                                                         "username" : username,
                                                         "user_id" : userid,
                                                         "date_posted" : datetime.datetime.now()
                                                        }}}
        )
    else:
        print(form.errors)
    sign=db.signs.aggregate(
            [ { '$match' : {'_id': ObjectId(object_id) } },
            { '$addFields' : {
                    'title' : '$title',
                    'creator': '$creator',
                    'created': '$created',
                    'wherefound' : '$wherefound',
                    'ratings' : '$ratings',
                    'long' : '$long',
                    'lat' : '$lat',
                    'location': '$location',
                    'file' : '$file',
                    'AverageRating' : { '$avg': "$ratings.rating" },
                    'NumberOfRatings': { '$size': { "$ifNull": [ "$ratings", [] ] } }
                }
            }]
        )
    sign = process_signs(list(sign))[0]
    return render_template('gosign.html', sign=sign, form=form)

@app.route("/register", methods=['GET', 'POST'])
def register():
    error_message = None
    success_message = None
    if current_user.is_authenticated:
        logout_user()
        return redirect(url_for("home"))
    form = RegistrationForm()
    if form.validate_on_submit():
        #sendtestmessage('me@test.com',form.email.data)
        #Check username and password unique in database
        if db.users.find_one({"$or":[{"username":{'$regex': form.username.data, '$options': '-i'}},{"email":{'$regex': form.email.data, '$options': '-i'}}]}):
            error_message = "An account with this username or password already exists"
            flash(u"An account with this username or password already exists","danger")
        else:
            #proceed
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
            hash = secrets.token_hex(20)
            user_dict = {"username":form.username.data,"email":form.email.data,"password":hashed_password,"enabled":False,
                            "hash":hash,"dateregistered":datetime.datetime.now()}
            db.users.insert_one(user_dict)
            #Send verifitcation email
            sendconfirmation(form.email.data, hash, form.username.data)
            success_message = "Account created for " + form.username.data +"!\n" + \
                "Please check your email and click on the link to verify your email address"
            flash(u"Account created for " + form.username.data +"!\n" + \
                "Please check your email and click on the link to verify your email address",'success')
    elif form.errors:
        print(form.errors)
        error_message = "You have errors on the form"
        flash(u"You have errors on the form","danger")
        """
        flash(errorstring,"danger")
        errorvals = [x[0] for x in list(form.errors.values())]
        errorlist = list(map(lambda x, y: x+ ': ' +y, list(form.errors.keys()), errorvals  ))
        for error in errorlist:
            flash(error,"danger")
            errorstring = errorstring + error
        """
    return render_template("register.html", title="Register", form=form, error_message=error_message,success_message=success_message)

@app.route("/confirm/<string:confirm_hash>")
def confirm(confirm_hash):
    success_message = None
    error_message = None
    user = db.users.find_one({"hash":confirm_hash})
    print("hash",confirm_hash)
    form = LoginForm()
    if user:
        if user["dateregistered"] + datetime.timedelta(hours=1) > datetime.datetime.now():
            #Enable Account
            db.users.update_one(   { "_id": user["_id"] },
                                  { "$set": { "enabled": True} }
            )
            db.users.update_one(   { "_id": user["_id"] },
                                  { "$unset": { "hash": ""} }
            )
            SUCCESS_MESSAGE="Account confrimed, please login below"
            flash(u"Account confrimed, please login below","success")
        else:
            db.users.delete_one( { "_id": user["_id"] } )
            ERROR_MESSAGE = "Sorry account has expired"
            flash(u"Sorry account has expired","danger")
    return redirect(url_for("home",error_message=error_message,success_message=success_message,home=True))

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
            db.users.update_one(   { "email": forgotform.email.data },
                                  { "$set": { "forgothash": forgothash, "dateforgot" : datetime.datetime.now() } }
            )
            sendforgot(forgotform.email.data, forgothash)
            flash(u"An email with a password reset link has been sent to this email address if it is registered on the system","success")
        elif forgotform.errors:
            errorstring = u"You have errors on the form"
            flash(errorstring,"danger")
            """
            errorvals = [x[0] for x in list(forgotform.errors.values())]
            errorlist = list(map(lambda x, y: x+ ': ' +y, list(form.errors.keys()), errorvals  ))
            for error in errorlist:
                #flash(error,"danger")
                errorstring = errorstring + error
                """
    else:
        confirmed = True
        if form.validate_on_submit():
            user = db.users.find_one({"forgothash":confirm_hash})
            print(confirm_hash)
            print(user)
            if user:
                if user["dateforgot"] + datetime.timedelta(hours=1) > datetime.datetime.now():
                    #Get password hash and update
                    hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
                    db.users.update_one(   { "_id": user["_id"] },
                                          { "$set": { "password": hashed_password} }
                    )
                    db.users.update_one(   { "_id": user["_id"] },
                                          { "$unset": { "forgothash": "","dateforgot": ""} }
                    )
                    flash(u"Password Rest, please login below","success")
                    print("Reset")
                    return redirect(url_for("home"))
                else:
                    db.users.update_one(   { "_id": user["_id"] },
                                          { "$unset": { "forgothash": "","dateforgot": ""} }
                    )
                    flash(u"Sorry your password reset has expired, please try again","danger")
                    return redirect(url_for("forgot"))
            else:
                flash(u"Sorry user account not found","danger")
                redirect(url_for("forgot"))
        else:
            print("do wasedsdsd")
            print(form.errors)
            errorstring = u"Check that the passwords match and meet the complexity requirements"
            flash(errorstring,"danger")
            print(errorstring)
            """
            errorvals = [x[0] for x in list(forgotform.errors.values())]
            errorlist = list(map(lambda x, y: x+ ': ' +y, list(form.errors.keys()), errorvals  ))
            for error in errorlist:
                flash(error,"danger")
                errorstring = errorstring + error
                """
    return render_template("forgot.html", forgotform=forgotform, form=form, forgot=forgot, confirmed=confirmed)

@app.route("/changepassword", methods=["GET","POST"])
@login_required
def change():
    myid = ObjectId(current_user.get_id())
    form = ChangeForm()
    if form.validate_on_submit():
        user = db.users.find_one({"_id":myid})
        if user and bcrypt.check_password_hash(user["password"],form.oldpassword.data):
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
            db.users.update_one(   { "_id": user["_id"] },
                                  { "$set": { "password": hashed_password} }
            )
            flash(u"Your password has successfully been changed","success")
            #return redirect(url_for("home"))
        else:
            flash(u"Password change unsuccessfull, please check your old password and try again","danger")
    elif form.errors:
        print(form.errors)
        flash(u"Password change unsuccessfull, please try again","danger")
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
            flash(u"Login unsuccessful!","danger")
    else:
        errors = [form.errors[k] for k in form.errors.keys()]
        #flash(errors,"danger")
    return render_template("login.html", title="Login", form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))
