from database.db import initialize_db
from database.models import *
from flask import Flask, Response, request, render_template, url_for, send_file, flash, redirect, url_for
from flask_restful import Api
from flask import make_response
from flask_login import login_user, current_user, logout_user, login_required
import bcrypt
from werkzeug.utils import secure_filename
from uuid import uuid4
import os
from flask_login import LoginManager

app = Flask(__name__)
api = Api(app)

app.config['MONGODB_SETTINGS'] = {
    'db': 'medup',
    # 'host': 'localhost',
    # 'port': 27017
    'host': 'mongodb://medup:aOetlKIGdaiUB8VYB1BZvkGUSQltHi30pTyMZ7n5ksRogkUTgJluIefw5jEspLuHt6LyMaEmelCsW6DjflZyIQ==@medup.mongo.cosmos.azure.com:10255/?ssl=true&retrywrites=false&replicaSet=globaldb&maxIdleTimeMS=120000&appName=@medup@'
}
initialize_db(app)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
login_manager=LoginManager(app)
login_manager.login_view='login'
login_manager.login_message_category='info'

UPLOAD_FOLDER_PRESCRIPTIONS = 'prescriptions'
UPLOAD_FOLDER_MEDICALTESTS = 'medicaltests'
app.config['UPLOAD_FOLDER_PRESCRIPTIONS'] = UPLOAD_FOLDER_PRESCRIPTIONS
app.config['UPLOAD_FOLDER_MEDICALTESTS'] = UPLOAD_FOLDER_MEDICALTESTS
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
   
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
   
def allowed_file(filename):
 return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def make_unique(string):
    ident = uuid4().__str__()
    return f"{ident}-{string}"

def generateReturnJson(status, msg):
    retJson = {
        "status": status,
        "msg": msg
    }
    return retJson

def UserExists(email):
    result = User.objects(email=email)
    if not result:
        return False
    else:
        return True

@app.route("/")
def index():
    headers = {'Content-Type': 'text/html'}
    return make_response(render_template('index.html'),200,headers)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        content = request.get_json(force=True)
        email = content['email']
        if UserExists(email):
            return {'msg': "User already exists"}, 400
        password = content['password']
        print("role",content['role'])
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        newBody = {
            "email": email,
            "password": hashed_pw,
            "firstName": content['firstName'],
            "lastName": content['lastName'],
            "phoneNumber": content['phoneNumber'],
            "age": content['age'],
            "gender": content['gender'],
            "role": content['role']
        }
        
        user = User(**newBody).save()
        return redirect(url_for('login'))
        # headers = {'Content-Type': 'text/html'}
        # return make_response(render_template('login.html'),200,headers)
        # id = user.id
        # return {'id': str(id), 'msg': "Account successfully created"}, 200
    headers = {'Content-Type': 'text/html'}
    return make_response(render_template('signup.html'),200,headers)

def verifyCredentials(email, password):
    if not UserExists(email):
        return generateReturnJson(400, "Email doesn't exist"), True

    correct_pw = verifyPw(email, password)

    if not correct_pw:
        return generateReturnJson(400, "The password you entered is incorrect"), True

    return None, False

def verifyPw(email, password):
    if not UserExists(email):
        return False

    hashed_pw = User.objects.get(email=email)['password']
    print(hashed_pw)
    if bcrypt.checkpw(password.encode('utf8'), hashed_pw.encode('utf8')):
        return True
    else:
        return False

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for("home"))
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('login.html'),200,headers)

    if request.method == 'POST':  
        content = request.get_json(force=True)
        email = content['email']
        password = content["password"]
        retJson, error = verifyCredentials(email, password)
        if error:
            return retJson, 400
        else:
            user = User.objects(email=email).first()
            login_user(user)
            return redirect(url_for("home"))    


@login_manager.user_loader
def load_user(id):
    return User.objects(id=id).first()

@app.route("/logout")
def logout():
    logout_user()
    return redirect('/')

@app.route("/home")
@login_required
def home():
    if current_user.is_authenticated:
        email = current_user.email
        role = User.objects(email=email).first().role.lower()
        headers = {'Content-Type': 'text/html'}
        if role == "doctor":
            return make_response(render_template('doctors/docdash.html'),200,headers)
        elif role == "patient":           
            return make_response(render_template('patients/patdash.html'),200,headers)
        else:
            return make_response(render_template('tech/techdash.html'),200,headers)

@app.route("/prescription", methods=['GET', 'POST'])
@login_required
def prescription():
    if request.method == 'GET':
        email = request.form['email']
        user = User.objects(email=email).first()
        id = str(user.id)
        prescriptions = Prescription.objects(patientID=id).to_json()
        return prescriptions, 200

    if request.method == 'POST':
        file = request.files['file']
        patientID = request.form['patientID']
        doctorID = request.form['doctorID']
        filename = uuid4().__str__()
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            unique_filename = make_unique(original_filename)
            path = os.path.join(app.config['UPLOAD_FOLDER_PRESCRIPTIONS'], patientID, doctorID)
            try:
                os.makedirs(path, exist_ok = True)
                print("Directory '%s' created successfully" % path)
            except OSError as error:
                print("Directory '%s' can not be created" % path)
            file.save(os.path.join(path, unique_filename))
            prescription = Prescription(patientID=patientID, doctorID=doctorID, filename=unique_filename)
            prescription.save()
            return redirect(url_for('home'))
        else:
            flash('Invalid Upload only txt, pdf, png, jpg, jpeg, gif') 
        return redirect('/') 

@app.route("/prescription/<filename>", methods=['GET'])
@login_required
def downloadPrescription(filename):
    patientID = request.form['patientID']
    doctorID = request.form['doctorID']
    path = os.path.join(app.config['UPLOAD_FOLDER_PRESCRIPTIONS'], patientID, doctorID, filename)
    return send_file(path)

@app.route("/medicaltest", methods=['GET', 'POST'])
@login_required
def booktest():
    if request.method == 'GET':
        # email = request.form['email']
        # user = User.objects(email=email).first()
        # id = str(user.id)
        # medicaltests = MedicalTest.objects(patientID=id).to_json()
        # return medicaltests, 200
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('patients/bookmedtest.html'),200,headers)

    if request.method == 'POST':
        file = request.files['file']
        patientID = request.form['patientID']
        labopID = request.form['labopID']
        filename = uuid4().__str__()
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            unique_filename = make_unique(original_filename)
            path = os.path.join(app.config['UPLOAD_FOLDER_MEDICALTESTS'], patientID, labopID)
            try:
                os.makedirs(path, exist_ok = True)
                print("Directory '%s' created successfully" % path)
            except OSError as error:
                print("Directory '%s' can not be created" % path)
            file.save(os.path.join(path, unique_filename))
            medicaltests = MedicalTest(patientID=patientID, labopID=labopID, filename=unique_filename)
            medicaltests.save()
            return redirect('/')
        else:
            flash('Invalid Upload only txt, pdf, png, jpg, jpeg, gif') 
        return redirect('/')

@app.route("/medicaltest/<filename>", methods=['GET'])
@login_required
def downloadMedicalTest(filename):
    patientID = request.form['patientID']
    labopID = request.form['labopID']
    path = os.path.join(app.config['UPLOAD_FOLDER_MEDICALTESTS'], patientID, labopID, filename)
    return send_file(path)

@app.route("/appointment", methods=['GET'])
@login_required
def book_app():
    headers = {'Content-Type': 'text/html'}
    return make_response(render_template('patients/book_app.html'),200,headers)

@app.route("/requestbed", methods=['GET', 'POST'])
@login_required
def requestbed():
    if request.method == 'GET':
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('patients/requestbed.html'),200,headers)

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'GET':
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('patients/profile.html'),200,headers)

@app.route("/user", methods=['GET', 'POST'])
@login_required
def user():
    if request.method == 'GET':
        headers = {'Content-Type': 'application/json'}
        return make_response(current_user.to_json(),200,headers)

if __name__ == "__main__":
    app.run(debug=True)
