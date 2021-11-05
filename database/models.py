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
    date_created = DateTimeField(default=datetime.utcnow)

    # def json(self):
    #     user = {
    #         "email": self.email,
    #         "first_name": self.firstName,
    #         "last_name": self.lastName,
    #         "phone_number": self.phoneNumber,
    #         "age": self.age,
    #         "gender": self.gender,
    #         "role": self.role
    #     }
    #     return json.dumps(user)

    # meta = {
    #     "indexes": ["email"],
    #     "ordering": ["date_created"]
    # }
