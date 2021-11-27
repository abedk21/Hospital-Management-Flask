from datetime import datetime
from mongoengine.fields import DateTimeField
from .db import db
import json
import mongoengine_goodjson as gj
from flask_login import UserMixin

class User(gj.Document, UserMixin):
    email = db.StringField(required=True, unique=True)
    password = db.StringField(required=True)
    firstName = db.StringField(required=True)
    lastName = db.StringField(required=True)
    phoneNumber = db.StringField(required=True)
    age = db.IntField(required=True)
    gender = db.StringField(required=True)
    role = db.StringField(required=True)
    department = db.StringField()
    date_created = DateTimeField(default=datetime.utcnow)

class Prescription(gj.Document):
    patientID = db.StringField(required=True)
    doctorID = db.StringField(required=True)
    appID = db.StringField(required=True)
    filename = db.StringField(required=True)
    date_created = DateTimeField(default=datetime.utcnow)

class MedicalTest(gj.Document):
    patientID = db.StringField(required=True)
    labopID = db.StringField(required=True)
    appID = db.StringField(required=True)
    filename = db.StringField(required=True)
    date_created = DateTimeField(default=datetime.utcnow)

class Department(gj.Document):
    department = db.StringField(required=True)
class TestType(gj.Document):
    testtype = db.StringField(required=True)
class Appointment(gj.Document):
    patientID = db.StringField(required=True)
    doctorID = db.StringField(required=True)
    prescription = db.BooleanField(required=True)
    date = db.DateTimeField(required=True)
    timeSlot = db.StringField(required=True)
    note = db.StringField(required=True)
    date_created = DateTimeField(default=datetime.utcnow)

class MedicalTestApp(gj.Document):
    patientID = db.StringField(required=True)
    labopID = db.StringField(required=True)
    result = db.BooleanField(required=True)
    date = db.DateTimeField(required=True)
    timeSlot = db.StringField(required=True)
    note = db.StringField(required=True)
    date_created = DateTimeField(default=datetime.utcnow)