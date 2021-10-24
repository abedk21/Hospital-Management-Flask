from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.aNewDB
patients = db["Patients"]

def generateReturnJson(status, msg):
    retJson = {
        "status": status,
        "msg": msg
    }
    return retJson

def UserExists(email):
    if patients.find({"Email":email}).count() == 0:
        return False
    else:
        return True

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        email = postedData["email"]
        password = postedData["password"]
        first_name = postedData["first_name"]
        last_name = postedData["last_name"]
        phone_number = postedData["phone_number"]
        age = postedData["age"]
        gender = postedData["gender"]

        if UserExists(email):
            retJson = generateReturnJson(400, "User already exists")
            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        patients.insert({
            "Email": email,
            "Password": hashed_pw,
            "First_Name": first_name,
            "Last_Name": last_name,
            "Phone_Number": phone_number,
            "Age":age,
            "Gender":gender
        })
        retJson = generateReturnJson(200, "Account successfully created")
        return jsonify(retJson)

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

    hashed_pw = patients.find({
        "Email":email
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

class Login(Resource):
    def post(self):
        postedData = request.get_json()

        email = postedData["email"]
        password = postedData["password"]

        retJson, error = verifyCredentials(email, password)
        if error:
            return jsonify(retJson)
        else:
            retJson = generateReturnJson(200, "Login successful")

api.add_resource(Register, "/register")
api.add_resource(Login, "/login")


if __name__=="__main__":
    app.run(host='0.0.0.0')
