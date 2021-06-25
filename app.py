import os
import uuid
import datetime
from markupsafe import escape
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, jsonify, flash, redirect, session

# Local Import
import config

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///use_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.permanent_session_lifetime = datetime.timedelta(minutes=15)
app.config.from_object('config.Production')
db = SQLAlchemy(app)
app.logger.setLevel(10)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(30), nullable=False)
    lname = db.Column(db.String(30), nullable=False)
    mnum = db.Column(db.String(13), nullable=False)
    email = db.Column(db.String(60), unique=True, nullable=False)
    username = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(60), unique=True, nullable=False)


# Checking for databaseFile
if not os.path.isfile('use_data.db'):
    db.create_all()
else:
    app.logger.debug('Skipping the Database Creation File')


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/register')
def regiter():
    return render_template('reg.html')


@app.route('/data')
def showData():
    userdata = Users.query.all()
    results = list()
    for result in userdata:
        data = {}
        data['fname'] = result.fname,
        data['lname'] = result.lname,
        data['mnum'] = result.mnum,
        data['email'] = result.email,
        data['username'] = result.username,
        data['password'] = result.password
        results.append(data)
    return jsonify(
        {"Registered Users": results}
    )


def storeData(**kwargs) -> None:
    fname, lname, mnum, email, username, password = kwargs.values()
    hashed_password = generate_password_hash(
        password,
        method='sha256'
    )
    new_user = Users(
        fname=fname,
        lname=lname,
        mnum=mnum,
        email=email,
        username=username,
        password=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()
    app.logger.debug('User Registration Complete.')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        dataDict = dict()
        dataDict['fname'] = request.form.get('Fname')
        dataDict['lname'] = request.form.get('Lname')
        dataDict['mnum'] = request.form.get('mnum')
        dataDict['email'] = request.form.get('email')
        dataDict['uname'] = request.form.get('uname')
        dataDict['password'] = request.form.get('password')
        if dataDict['password'] != request.form.get('Repassword'):
            flash('Password and Reentered did not matchs')
            return redirect('register')
        else:
            app.logger.debug('Storing the data to the database')
            storeData(**dataDict)
            return redirect('login')


def authenticate(**kwargs):
    username, password = kwargs.values()
    app.logger.debug(f'Recieved credentail - {username},{password}')
    if '@' in username:
        user = Users.query.filter_by(email=username).first()
    else:
        user = Users.query.filter_by(username=username).first()
    app.logger.debug(f'Password from db - {user.password}')
    if check_password_hash(user.password, password):
        app.logger.debug('User Authentication Seccessfully')
        session['token'] = username + str(uuid.uuid4()) + password
        return True
    else:
        return False


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        dataDict = dict()
        dataDict['username'] = request.form.get('user')
        dataDict['password'] = request.form.get('pass')
        app.logger.info('Login Data Recieved')
        if authenticate(**dataDict):
            flash('Login Successul')
            return redirect('patients')
        else:
            flash('Login Unsuccessful, Check Username or password')
            return redirect('login')


def Checkpatients():
    if 'token' in session:
        app.logger.debug('Grabbed Session Token')
        token = session['token']
        app.logger.info(f'Token Grabbed from checkpatients - {token}')
        return True
    else:
        app.logger.info(f'No Token Found from checkpatients')
        return False


@app.errorhandler(404)
def user_not_authenticated(error):
    return render_template('error.html'), error


@app.route('/patients')
def patients():
    if Checkpatients():
        return render_template('patients.html')
    else:
        app.logger.error('About to return user_not_authenticated_error')
        return user_not_authenticated(404)


@app.route('/patients_model', methods=['GET', 'POST'])
def modelCheck():
    if Checkpatients():
        dataDict = dict()
        if request.method == 'POST':
            dataDict['Hospital_code'] = request.form.get('hospital_code')
            dataDict['Hospital_type_code'] = request.form.get('hospital_type')
            dataDict['City_Code_Hospital'] = request.form.get('city_code')
            dataDict['Hospital_region_code'] = request.form.get('region_code')
            dataDict['Department'] = request.form.get('dept')
            dataDict['Ward_Facility_Code'] = request.form.get('ward_code')
            dataDict['Type of Admission'] = request.form.get('type')
            dataDict['Severity of Illness'] = request.form.get('severity')
            dataDict['Visitors'] = request.form.get('visitors')
            dataDict['Age'] = request.form.get('age')
            dataDict['Admission_Deposit'] = request.form.get('deposit')
            app.logger.debug(dataDict)
        if request.method == 'GET':
            return "Output is - "
    else:
        return jsonify(
            {
                'error message': 'Authentication Unsuccessful, Login'
            }
        )


if __name__ == '__main__':
    app.run()
