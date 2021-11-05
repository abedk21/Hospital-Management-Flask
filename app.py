from database.db import initialize_db
from database.models import *
from flask import Flask, Response, request, render_template, url_for
from flask_bootstrap import Bootstrap
from flask_restful import Api, Resource
from flask import make_response, render_template
import bcrypt

app = Flask(__name__)
api = Api(app)

app.config['MONGODB_SETTINGS'] = {
    'db': 'medup',
    'host': 'localhost',
    'port': 27017
}
initialize_db(app)

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
        id = user.id
        return {'id': str(id), 'msg': "Account successfully created"}, 200

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

api.add_resource(Index, "/")
api.add_resource(Register, "/register")
api.add_resource(Login, "/login")


if __name__ == "__main__":
    app.run(debug=True)
