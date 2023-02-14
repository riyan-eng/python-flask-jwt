from flask import Flask, jsonify, request
from http import HTTPStatus
from hashlib import md5
import os
from pony.orm import Database
from pony.flask import Pony
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

db = Database()
db.bind(provider='postgres', user=os.getenv("DB_USERNAME"), password=os.getenv("DB_PASSWORD"), host=os.getenv("DB_HOST"), database=os.getenv("DB_NAME"))

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
Pony(app)
jwt = JWTManager(app)
# db.generate_mapping()


@app.route("/auth/register", methods=["POST"])
def register():
  try:
    payload = request.json
    if payload["username"] == "" or payload["password"] == "":
      return jsonify({
        "data": "require username and password",
        "message": "bad"
      }), HTTPStatus.BAD_REQUEST
    
    hashPassword = md5((payload["password"]+os.getenv("SALT_PASSWORD")).encode())    
    query = f"insert into users (username, password) values ('{payload['username']}', '{hashPassword.hexdigest()}')"
    db.execute(query)
    return jsonify({
      "data": 1,
      "message": "ok"
    }), HTTPStatus.OK
    
  except Exception as err:
    return jsonify({
      "data": str(err),
      "message": "bad"
    }), HTTPStatus.BAD_REQUEST

@app.route("/auth/login", methods=["POST"])
def login():
  try:
    payload = request.json
    if payload["username"] == "" or payload["password"] == "":
      return jsonify({
        "data": "require username and password",
        "message": "bad"
      }), HTTPStatus.BAD_REQUEST
      
    hashPassword = md5((payload["password"]+os.getenv("SALT_PASSWORD")).encode())
    query = f"select u.id, u.username from users u where u.username='{payload['username']}' and u.password='{hashPassword.hexdigest()}'"
    data = db.select(query)
    if not data:
      return jsonify({
        "data": "username or password invalid",
        "message": "bad"
      }), HTTPStatus.BAD_REQUEST
      
    access_token = create_access_token(identity=data[0][1])
    data = {
      "username": data[0][1],
      "access_token": access_token
    }
    return jsonify({
      "data": data,
      "message": "ok"
    }), HTTPStatus.OK
    
  except Exception as err:
    return jsonify({
      "data": str(err),
      "message": "bad"
    }), HTTPStatus.BAD_REQUEST
    
@app.route("/public", methods=["GET"])
def public():
  try:
    return jsonify({
      "data": 1,
      "message": "ok"
    }), HTTPStatus.OK
    
  except Exception as err:
    return jsonify({
      "data": str(err),
      "message": "bad"
    }), HTTPStatus.BAD_REQUEST
    
@app.route("/private", methods=["GET"])
@jwt_required()
def private():
  try:
    user = get_jwt_identity()
    data = {
      "user": user
    }
    return jsonify({
      "data": data,
      "message": "ok"
    }), HTTPStatus.OK
    
  except Exception as err:
    return jsonify({
      "data": str(err),
      "message": "bad"
    }), HTTPStatus.BAD_REQUEST