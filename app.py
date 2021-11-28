from database.db import *
from database.models import *
from mongoengine.queryset.visitor import Q
from flask import Flask, request, render_template, url_for, send_file, flash, redirect, url_for, jsonify
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

def UserExists(email):
    result = User.objects(email=email)
    if not result:
        return False
    else:
        return True

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    headers = {'Content-Type': 'text/html'}
    return make_response(render_template('index.html'),200,headers)

@app.route("/contactus")
def contact():
    return render_template("contact_us.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        content = request.get_json(force=True)
        email = content['email']
        if UserExists(email):
            headers = {'Content-Type': 'application/json'}
            return make_response(jsonify({"msg": "User already exists"}), 400, headers)
        password = content['password']
        role = content['role']
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        department = ""
        if(role == "Doctor" or role == "Labop"):
            department = content['department']
        newBody = {
            "email": email,
            "password": hashed_pw,
            "firstName": content['firstName'],
            "lastName": content['lastName'],
            "phoneNumber": content['phoneNumber'],
            "age": content['age'],
            "gender": content['gender'],
            "department": department,
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
        return True

    correct_pw = verifyPw(email, password)

    if not correct_pw:
        return True

    return False

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
        error = verifyCredentials(email, password)
        if error:
            headers = {'Content-Type': 'application/json'}
            return make_response(jsonify({"msg": "Wrong email or password"}), 400, headers)
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
        role = current_user.role.lower()
        headers = {'Content-Type': 'text/html'}
        if role == "doctor":
            return make_response(render_template('doctors/docdash.html'),200,headers)
        elif role == "patient":           
            return make_response(render_template('patients/patdash.html'),200,headers)
        elif role == "labop":
            return make_response(render_template('tech/techdash.html'),200,headers)
        elif role == "admin":
            return make_response(render_template('admin/admindash.html'),200,headers)

@app.route("/addstaff")
@login_required
def addstaff():
    role = current_user.role.lower()
    headers = {'Content-Type': 'text/html'}
    if role == "admin":
        return make_response(render_template('admin/addstaff.html'),200,headers)

@app.route("/viewstaff")
@login_required
def viewstaff():
    role = current_user.role.lower()
    headers = {'Content-Type': 'text/html'}
    if role == "admin":
        return make_response(render_template('admin/viewstaff.html'),200,headers)

@app.route("/getstaff", methods=['GET'])
@login_required
def getstaff():
    role = current_user.role.lower()
    headers = {'Content-Type': 'application/json'}
    if role == "admin":
        staff = User.objects.filter(Q(role="Doctor") | Q(role="Labop"))
        headers = {'Content-Type': 'application/json'}
        return make_response(staff.to_json(),200,headers)

@app.route("/deletestaff", methods=['DELETE'])
@login_required
def deletestaff():
    role = current_user.role.lower()
    headers = {'Content-Type': 'application/json'}
    if role == "admin":
        content = request.get_json(force=True)
        id = content['id']
        staff = User.objects(id=id).first().delete()
        return "",200

@app.route("/editstaff", methods=['GET', 'POST'])
@login_required
def editstaff():
    role = current_user.role.lower()
    if role == "admin":
        if request.method == 'GET':
            headers = {'Content-Type': 'text/html'}
            return make_response(render_template('admin/editstaff.html'),200,headers)

@app.route("/viewprescriptions", methods=['GET', 'POST'])
@login_required
def viewprescriptions():
    if request.method == 'GET':
        if current_user.role == "Patient":
            headers = {'Content-Type': 'text/html'}
            return make_response(render_template('patients/viewprescriptions.html'),200,headers)
        if current_user.role == "Doctor":
            headers = {'Content-Type': 'text/html'}
            return make_response(render_template('doctors/viewprescriptions.html'),200,headers)

@app.route("/viewtestresults", methods=['GET', 'POST'])
@login_required
def viewtestresults():
    if request.method == 'GET':
        if current_user.role == "Patient":
            headers = {'Content-Type': 'text/html'}
            return make_response(render_template('patients/viewtestresult.html'),200,headers)
        if current_user.role == "Labop":
            headers = {'Content-Type': 'text/html'}
            return make_response(render_template('tech/viewtestresult.html'),200,headers)

@app.route("/prescription", methods=['GET', 'POST'])
@login_required
def prescription():
    if request.method == 'GET':
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('doctors/prescription.html'),200,headers)

    if request.method == 'POST':
        # print("request: ",request.get_json(force=True))
        file = request.files['file']
        patientID = request.form['patientID']
        doctorID = current_user.id
        appID = request.form['appID']
        filename = uuid4().__str__()
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            unique_filename = make_unique(original_filename)
            path = os.path.join(app.config['UPLOAD_FOLDER_PRESCRIPTIONS'], patientID, str(doctorID))
            try:
                os.makedirs(path, exist_ok = True)
                print("Directory '%s' created successfully" % path)
            except OSError as error:
                print("Directory '%s' can not be created" % path)
            file.save(os.path.join(path, unique_filename))
            prescription = Prescription(patientID=patientID, doctorID=str(doctorID), appID=appID, filename=unique_filename)
            prescription.save()
            Appointment.objects(id = appID).update(
                prescription = True
                )
            return redirect(url_for('home'))
        else:
            flash('Invalid Upload only txt, pdf, png, jpg, jpeg, gif') 
        return redirect('/') 

@app.route("/getprescription", methods=['GET'])
@login_required
def downloadprescription():
    if current_user.role == "Patient":
        patientID = str(current_user.id)
        doctorID = request.args.get('doctorID')
        appID = request.args.get('appID')
        filename = Prescription.objects(appID=appID).first().filename
        path = os.path.join(app.config['UPLOAD_FOLDER_PRESCRIPTIONS'], patientID, doctorID, filename)
        return send_file(path)
    if current_user.role == "Doctor":
        doctorID = str(current_user.id)
        patientID = request.args.get('patientID')
        appID = request.args.get('appID')
        filename = Prescription.objects(appID=appID).first().filename
        path = os.path.join(app.config['UPLOAD_FOLDER_PRESCRIPTIONS'], patientID, doctorID, filename)
        return send_file(path)

@app.route("/deleteprescription", methods=['DELETE'])
@login_required
def deleteprescription():
    if current_user.role == "Doctor":
        content = request.get_json(force=True)
        doctorID = str(current_user.id)
        patientID = content['patientID']
        appID = content['appID']
        prescription = Prescription.objects(appID=appID).first()
        filename = prescription.filename
        prescription.delete()
        path = os.path.join(app.config['UPLOAD_FOLDER_PRESCRIPTIONS'], patientID, doctorID, filename)
        if os.path.exists(path):
            os.remove(path)
        else:
            print("The file does not exist")
        Appointment.objects(id = appID).update(
            prescription = False
        )
        return "",200

@app.route("/deletemedicaltest", methods=['DELETE'])
@login_required
def deletemedtest():
    if current_user.role == "Labop":
        content = request.get_json(force=True)
        labopID = str(current_user.id)
        patientID = content['patientID']
        appID = content['appID']
        medtest = MedicalTest.objects(appID=appID).first()
        filename = medtest.filename
        medtest.delete()
        path = os.path.join(app.config['UPLOAD_FOLDER_MEDICALTESTS'], patientID, labopID, filename)
        if os.path.exists(path):
            os.remove(path)
        else:
            print("The file does not exist")
        MedicalTestApp.objects(id = appID).update(
            result = False
        )
        return "",200

@app.route("/viewmedicalappointments", methods=['GET', 'POST'])
@login_required
def viewmedtestapps():
    if request.method == 'GET':
        if current_user.role == "Labop":
            headers = {'Content-Type': 'text/html'}
            return make_response(render_template('tech/bookings.html'),200,headers)

@app.route("/medicaltest", methods=['GET', 'POST'])
@login_required
def medicaltest():
    if request.method == 'GET':
        if current_user.role == "Patient":
            headers = {'Content-Type': 'text/html'}
            return make_response(render_template('patients/bookmedtest.html'),200,headers)
        if current_user.role == "Labop":
            headers = {'Content-Type': 'text/html'}
            return make_response(render_template('tech/medtest.html'),200,headers)

    if request.method == 'POST':
        file = request.files['file']
        patientID = request.form['patientID']
        labopID = str(current_user.id)
        appID = request.form['appID']
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
            medicaltests = MedicalTest(patientID=patientID, labopID=labopID, appID=appID, filename=unique_filename)
            medicaltests.save()
            MedicalTestApp.objects(id = appID).update(
                result = True
            )
            return redirect('/')
        else:
            flash('Invalid Upload only txt, pdf, png, jpg, jpeg, gif') 
        return redirect('/')

@app.route("/getmedicaltest", methods=['GET'])
@login_required
def downloadMedicalTest():
    if current_user.role == "Patient":
        patientID = str(current_user.id)
        labopID = request.args.get('labopID')
        appID = request.args.get('appID')
        filename = MedicalTest.objects(appID=appID).first().filename
        path = os.path.join(app.config['UPLOAD_FOLDER_MEDICALTESTS'], patientID, labopID, filename)
        return send_file(path)
    if current_user.role == "Labop":
        labopID = str(current_user.id)
        patientID = request.args.get('patientID')
        appID = request.args.get('appID')
        filename = MedicalTest.objects(appID=appID).first().filename
        path = os.path.join(app.config['UPLOAD_FOLDER_MEDICALTESTS'], patientID, labopID, filename)
        return send_file(path)

@app.route("/bookappointment", methods=['GET', 'POST'])
@login_required
def book_app():
    if request.method == 'GET':
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('patients/book_app.html'),200,headers)

@app.route("/appointment", methods=['GET', 'POST', 'DELETE'])
@login_required
def appointment():
    if request.method == 'GET':
        headers = {'Content-Type': 'text/html'}
        if current_user.role == "Patient":
            return make_response(render_template('patients/bookings.html'),200,headers)
        if current_user.role == "Doctor":
            return make_response(render_template('doctors/bookings.html'),200,headers)
    if request.method == 'POST':
        content = request.get_json(force=True)
        Appointment(patientID=str(current_user.id),doctorID=content['doctorID'],prescription=False,date=content['date'],timeSlot=content['timeSlot'],note=content['note']).save()
        headers = {'Content-Type': 'text/html'}
        return make_response("",200,headers)
    if request.method == 'DELETE':
        content = request.get_json(force=True)
        appointment = Appointment.objects(id=content['appID'])
        appointment.delete()
        headers = {'Content-Type': 'application/json'}
        return make_response(jsonify({"msg": "Appointment cancelled"}), 200, headers)

@app.route("/bookmedicaltest", methods=['GET', 'POST', 'DELETE'])
@login_required
def bookmedicaltest():
    if request.method == 'GET':
        headers = {'Content-Type': 'text/html'}
        if current_user.role == "Patient":
            return make_response(render_template('patients/medtestbookings.html'),200,headers)
        if current_user.role == "Labop":
            return make_response(render_template('doctors/medtestbookings.html'),200,headers)
    if request.method == 'POST':
        content = request.get_json(force=True)
        MedicalTestApp(patientID=str(current_user.id),labopID=content['labopID'],result=False,date=content['date'],timeSlot=content['timeSlot'],note=content['note']).save()
        headers = {'Content-Type': 'text/html'}
        return make_response("",200,headers)
    if request.method == 'DELETE':
        content = request.get_json(force=True)
        appointment = MedicalTestApp.objects(id=content['appID'])
        appointment.delete()
        headers = {'Content-Type': 'application/json'}
        return make_response(jsonify({"msg": "Medical Test Booking Cancelled"}), 200, headers)

@app.route("/appointments", methods=['GET', 'POST'])
@login_required
def appointments():
    if request.method == 'GET':
        newBody = []
        if current_user.role == "Doctor":
            appointments = Appointment.objects(doctorID=str(current_user.id))
            for appointment in appointments:
                patient = User.objects(id=str(appointment.patientID)).first()
                newBody.append({
                "appointment": json.loads(appointment.to_json()),
                "patient": json.loads(patient.to_json())
                })
            headers = {'Content-Type': 'application/json'}
            return make_response(json.dumps(newBody),200,headers)
        if current_user.role == "Patient":
            appointments = Appointment.objects(patientID=str(current_user.id))
            for appointment in appointments:
                doctor = User.objects(id=str(appointment.doctorID)).first()
                newBody.append({
                "appointment": json.loads(appointment.to_json()),
                "doctor": json.loads(doctor.to_json())
                })
            headers = {'Content-Type': 'application/json'}
            return make_response(json.dumps(newBody),200,headers)

@app.route("/medtestapps", methods=['GET', 'POST'])
@login_required
def medtestapps():
    if request.method == 'GET':
        newBody = []
        if current_user.role == "Labop":
            appointments = MedicalTestApp.objects(labopID=str(current_user.id))
            for appointment in appointments:
                patient = User.objects(id=str(appointment.patientID)).first()
                newBody.append({
                "appointment": json.loads(appointment.to_json()),
                "patient": json.loads(patient.to_json())
                })
            headers = {'Content-Type': 'application/json'}
            return make_response(json.dumps(newBody),200,headers)
        if current_user.role == "Patient":
            appointments = MedicalTestApp.objects(patientID=str(current_user.id))
            for appointment in appointments:
                labop = User.objects(id=str(appointment.labopID)).first()
                newBody.append({
                "appointment": json.loads(appointment.to_json()),
                "labop": json.loads(labop.to_json())
                })
            headers = {'Content-Type': 'application/json'}
            return make_response(json.dumps(newBody),200,headers)     

@app.route("/checkapp", methods=['GET', 'POST'])
@login_required
def check_app():
    if request.method == 'GET':
        appointments = Appointment.objects(patientID=str(current_user.id))
        headers = {'Content-Type': 'application/json'}
        return make_response(appointments.to_json(),200,headers)

@app.route("/checkmedtest", methods=['GET', 'POST'])
@login_required
def check_medtest():
    if request.method == 'GET':
        appointments = MedicalTestApp.objects(patientID=str(current_user.id))
        headers = {'Content-Type': 'application/json'}
        return make_response(appointments.to_json(),200,headers)

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
        return make_response(render_template('profile.html'),200,headers)

@app.route("/user", methods=['GET', 'POST'])
@login_required
def user():
    if request.method == 'GET':
        headers = {'Content-Type': 'application/json'}
        id = request.args.get('id')
        if id is None:          
            return make_response(current_user.to_json(),200,headers)
        user = User.objects(id=id).first()
        return make_response(user.to_json(),200,headers)


@app.route("/departments", methods=['GET', 'POST'])
def departments():
    if request.method == 'POST':
        content = request.get_json(force=True)
        departments = content['departments']
        for department in departments:
            Department(department=department).save()
        headers = {'Content-Type': 'application/json'}
        return make_response("",200,headers)
    if request.method == 'GET':
        departments = Department.objects()
        headers = {'Content-Type': 'application/json'}
        return make_response(departments.to_json(),200,headers)

@app.route("/testtypes", methods=['GET', 'POST'])
def testtypes():
    if request.method == 'POST':
        content = request.get_json(force=True)
        testtypes = content['testtypes']
        for testtype in testtypes:
            TestType(testtype=testtype).save()
            headers = {'Content-Type': 'application/json'}
        return make_response("",200,headers)
    if request.method == 'GET':
        testtypes = TestType.objects()
        headers = {'Content-Type': 'application/json'}
        return make_response(testtypes.to_json(),200,headers)

@app.route("/doctors", methods=['GET', 'POST'])
def doctors():
    if request.method == 'GET':
        doctors = User.objects(role='Doctor')
        headers = {'Content-Type': 'application/json'}
        return make_response(doctors.to_json(),200,headers)

@app.route("/labops", methods=['GET', 'POST'])
def labops():
    if request.method == 'GET':
        labops = User.objects(role='Labop')
        headers = {'Content-Type': 'application/json'}
        return make_response(labops.to_json(),200,headers)

@app.route("/update", methods=['PATCH'])
@login_required
def update():
    id = request.args.get('id')
    if id is None:
        id = current_user.id
    content = request.get_json(force=True)
    if current_user.role != "Admin":
        User.objects(id = id).update(
            firstName = content['firstName'],
            lastName = content['lastName'],
            phoneNumber = content['phoneNumber']
        )
    else:
        User.objects(id = id).update(
            firstName = content['firstName'],
            lastName = content['lastName'],
            phoneNumber = content['phoneNumber'],
            age = content['age'],
            gender = content['gender'],
            role = content['role'],
            department = content['department']
        )
    user = User.objects(id=id).first()
    headers = {'Content-Type': 'application/json'}
    return make_response(user.to_json(),200,headers)

if __name__ == "__main__":
    app.run(debug=True)
