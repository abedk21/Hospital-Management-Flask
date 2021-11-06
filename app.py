from database.db import initialize_db
from database.models import *
from flask import Flask, Response, request, render_template, url_for, send_file, flash, redirect
from flask_bootstrap import Bootstrap
from flask_restful import Api, Resource
from flask import make_response, render_template
import bcrypt
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
api = Api(app)

app.config['MONGODB_SETTINGS'] = {
    'db': 'medup',
    'host': 'localhost',
    'port': 27017
}
initialize_db(app)

UPLOAD_FOLDER = 'prescriptions'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
   
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
   
def allowed_file(filename):
 return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
        filename = secure_filename(file.filename)
        if file and allowed_file(file.filename):
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            prescription = Prescription(patientID=patientID, filename=file.filename)
            prescription.save()
            return redirect('/')
        else:
            flash('Invalid Upload only txt, pdf, png, jpg, jpeg, gif') 
        return redirect('/') 

class DownloadPrescription(Resource):
    def get(self, filename):
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        return send_file(path)

api.add_resource(Index, "/")
api.add_resource(Register, "/register")
api.add_resource(Login, "/login")
api.add_resource(Prescriptions, "/prescription")
api.add_resource(DownloadPrescription, "/prescription/<filename>")

if __name__ == "__main__":
    app.run(debug=True)
