from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.aNewDB
patients = db["Patients"]

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
            retJson = {
                'status':400,
                'msg': 'User already exists'
            }
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

        retJson = {
            "status": 200,
            "msg": "Account successfully created"
        }
        return jsonify(retJson)

api.add_resource(Register, "/register")
api.add_resource(Login, "/login")


if __name__=="__main__":
    app.run(host='0.0.0.0')
