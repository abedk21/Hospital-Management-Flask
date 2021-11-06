from datetime import datetime
from mongoengine.fields import DateTimeField
from .db import db
import json
import mongoengine_goodjson as gj

class User(gj.Document):
    email = db.StringField(required=True, unique=True)
    password = db.StringField(required=True)
    firstName = db.StringField(required=True)
    lastName = db.StringField(required=True)
    phoneNumber = db.StringField(required=True)
    age = db.IntField(required=True)
    gender = db.StringField(required=True)
    role = db.StringField(required=True)
    specialty = db.StringField()
    patients = db.ListField()
    date_created = DateTimeField(default=datetime.utcnow)

class Prescription(gj.Document):
    patientID = db.StringField(required=True)
    doctorID = db.StringField(required=True)
    filename = db.StringField(required=True)
    date_created = DateTimeField(default=datetime.utcnow)

class MedicalTest(gj.Document):
    patientID = db.StringField(required=True)
    filename = db.StringField(required=True)
    date_created = DateTimeField(default=datetime.utcnow)