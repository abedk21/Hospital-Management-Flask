from database.db import initialize_db
from database.models import *
from flask import Flask, Response, request, render_template, url_for, send_file, flash, redirect
from flask_bootstrap import Bootstrap
from flask_restful import Api, Resource
from flask import make_response, render_template
import bcrypt
from werkzeug.utils import secure_filename
from uuid import uuid4
import os

app = Flask(__name__)
api = Api(app)

app.config['MONGODB_SETTINGS'] = {
    'db': 'medup',
    'host': 'localhost',
    'port': 27017
}
initialize_db(app)

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

class Index(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('index.html'),200,headers)

class Register(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('signup.html'),200,headers)

    def post(self):
        email = request.form['email']
        if UserExists(email):
            return {'msg': "User already exists"}, 400
        password = request.form['password']
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        newBody = {
            "email": request.form['email'],
            "password": hashed_pw,
            "firstName": request.form['firstName'],
            "lastName": request.form['lastName'],
            "phoneNumber": request.form['phoneNumber'],
            "age": request.form['age'],
            "gender": request.form['gender'],
            "role": request.form['role']
        }
        
        user = User(**newBody).save()
        redirect('/login')
        # headers = {'Content-Type': 'text/html'}
        # return make_response(render_template('login.html'),200,headers)
        # id = user.id
        # return {'id': str(id), 'msg': "Account successfully created"}, 200

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

class Login(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('login.html'),200,headers)

    def post(self):
        body = request.get_json()
        email = request.form['email']
        password = request.form["password"]

        retJson, error = verifyCredentials(email, password)
        if error:
            return retJson, 400
        else:
            retJson = generateReturnJson(200, "Login successful")
            return retJson

class Prescriptions(Resource):
    def get(self):
        email = request.form['email']
        user = User.objects(email=email).first()
        id = str(user.id)
        prescriptions = Prescription.objects(patientID=id).to_json()
        return prescriptions, 200

    def post(self):
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
            return redirect('/')
        else:
            flash('Invalid Upload only txt, pdf, png, jpg, jpeg, gif') 
        return redirect('/') 

class DownloadPrescription(Resource):
    def get(self, filename):
        patientID = request.form['patientID']
        doctorID = request.form['doctorID']
        path = os.path.join(app.config['UPLOAD_FOLDER_PRESCRIPTIONS'], patientID, doctorID, filename)
        return send_file(path)

class MedicalTests(Resource):
    def get(self):
        email = request.form['email']
        user = User.objects(email=email).first()
        id = str(user.id)
        medicaltests = MedicalTests.objects(patientID=id).to_json()
        return medicaltests, 200

    def post(self):
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
            medicaltests = MedicalTests(patientID=patientID, labopID=labopID, filename=unique_filename)
            medicaltests.save()
            return redirect('/')
        else:
            flash('Invalid Upload only txt, pdf, png, jpg, jpeg, gif') 
        return redirect('/')

class DownloadMedicalTest(Resource):
    def get(self, filename):
        patientID = request.form['patientID']
        labopID = request.form['labopID']
        path = os.path.join(app.config['UPLOAD_FOLDER_MEDICALTESTS'], patientID, labopID, filename)
        return send_file(path)

# class Patient(Resource):
#     def get(self):
#         patients = User.objects
#         return send_file(path)

api.add_resource(Index, "/")
api.add_resource(Register, "/register")
api.add_resource(Login, "/login")
api.add_resource(Prescriptions, "/prescription")
api.add_resource(DownloadPrescription, "/prescription/<filename>")
api.add_resource(MedicalTests, "/medicaltest")
api.add_resource(DownloadMedicalTest, "/medicaltest/<filename>")
# api.add_resource(Patient, "/patient")

if __name__ == "__main__":
    app.run(debug=True)
