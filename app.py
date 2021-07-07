import os
from re import S
import uuid
import joblib
import datetime
from flask import send_from_directory
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

try:
    import pickle
    import pandas as pd
    from sklearn.preprocessing import StandardScaler
except ImportError as err:
    app.logger.error(f'Could Not Found Necessary Library, {err}')


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

# Classifiction Paramaters
model = joblib.load('classsifier.bin')
ss = joblib.load('std_scaler.bin')
le = joblib.load('le_encoder.bin')


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'img/favicon.ico', mimetype='image/vnd.microsoft.icon')


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
            return redirect('/')
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


@app.route('/wardType')
def wardType():
    vl = Checkpatients()
    if vl:
        return render_template('ward.html')
    else:
        app.logger.error('About to return user_not_authenticated_error')
        return user_not_authenticated(404)


@app.route('/stay')
def stay():
    vl = Checkpatients()
    if vl:
        return render_template('stay.html')
    else:
        app.logger.error('About to return user_not_authenticated_error')
        return user_not_authenticated(404)


def getFrame(datalist, cols):
    df = pd.DataFrame(datalist, cols)
    return df


def label_encoded(df):
    from sklearn.preprocessing import LabelEncoder
    le = LabelEncoder()
    cat_cols = ['Hospital_type_code', 'Hospital_region_code', 'Department', 'Ward_Facility_Code',
                'Type of Admission', 'Severity of Illness', 'Age', 'City_Code_Hospital']
    for col in cat_cols:
        df[col] = le.transform(df[col])
    return df


def standard_encoded(df):
    from sklearn.preprocessing import StandardScaler
    num_cols = ['Hospital_code', 'Visitors with Patient', 'Admission_Deposit']
    ss = StandardScaler()
    df[num_cols] = ss.transform(df[num_cols].values)
    return df


def predictfrommodel(dataDict=None):
    if dataDict == None:
        app.logger.error('No Data Provided')
        return False
    datalist = [
        (dataDict['Hospital_code'],
         dataDict['Hospital_type_code'],
         dataDict['City_Code_Hospital'],
         dataDict['Hospital_region_code'],
         dataDict['Department'],
         dataDict['Ward_Facility_Code'],
         dataDict['Type of Admission'],
         dataDict['Severity of Illness'],
         dataDict['Visitors'],
         dataDict['Age'],
         dataDict['Admission_Deposit'])
    ]
    app.logger.info(f'Datalist - {datalist}')
    colss = [
        'Hospital_code',  # s
        'Hospital_type_code',
        'City_Code_Hospital',  # l
        'Hospital_region_code',  # l
        'Department',  # l
        'Ward_Facility_Code',  # l
        'Type of Admission',  # l
        'Severity of Illness',  # l
        'Visitors with Patient',  # s
        'Age',  # l
        'Admission_Deposit'  # s
    ]
    app.logger.info(f'Columns - {colss}')
    df = pd.DataFrame(datalist, columns=colss)
    app.logger.info('DataFrame')
    print(df.head())
    from sklearn.preprocessing import LabelEncoder
    # le = LabelEncoder()
    cat_cols = ['Hospital_type_code',
                'Hospital_region_code',
                'Department',
                'Ward_Facility_Code',
                'Type of Admission',
                'Severity of Illness',
                'Age',
                'City_Code_Hospital']
    for col in cat_cols:
        df[col] = le.fit_transform(df[col])
    app.logger.info("After Label Encoading")
    print(df.head())
    from sklearn.preprocessing import StandardScaler
    num_cols = ['Hospital_code', 'Visitors with Patient', 'Admission_Deposit']
    # ss = StandardScaler()
    df[num_cols] = ss.transform(df[num_cols].values)
    app.logger.info("After Standard Scaling")
    print(df.head())

    # with open('classifier.pickle', 'rb') as f:
    # model = pickle.load(f)
    app.logger.info(f"Classifier Model - {model}")
    pred = model.predict(df)
    app.logger.info(f"Predicted Value - {pred}")
    return pred


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
            output = predictfrommodel(dataDict)
            return render_template('output_ward.html', message=output[0])
            # return jsonify(
            #     {
            #         "Data Entered": dataDict,
            #         "Output (Ward Type)": str(output[0])
            #     }
            # )
    else:
        return jsonify(
            {
                'error message': 'Authentication Unsuccessful, Login'
            }
        )


if __name__ == '__main__':
    app.run()
