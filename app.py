from pymongo import MongoClient
import jwt
import datetime
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for, json
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

SECRET_KEY = 'SPARTA'

client = MongoClient('mongodb+srv://test:sparta@cluster0.ocllx.mongodb.net/Cluster0?retryWrites=true&w=majority')
db = client.dbsparta


@app.route('/')
def home():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.users.find_one({"username": payload["id"]})
        return render_template('index.html', user_info=user_info)
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="로그인 정보가 존재하지 않습니다."))


@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/index')
def index():
    return render_template('index.html')


@app.route("/signup", methods=["POST"])
def signup():
    print(request.data)
    #load data that was requested from client side
    data = json.loads(request.data)

    #check if the email already exists in our DB
    email = data.get('email', None)
    #if the email exists in our DB, user will be assigned based on given email
    user = db.users.find_one({'email': email})

    #hash password
    password = data.get('password', None)
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()


    #upload email and hashed PW to our DB
    doc = {
        'email': data.get('email', None),
        'password': hashed_password
    }

    db.users.insert_one(doc)

    return jsonify({'msg': 'signup successful!'})


@app.route("/signin", methods=["POST"])
def signin():
    print(request.data)
    data = json.loads(request.data)

    #check if the user(id and hashedPW) exists in our DB by
    result = db.users.find_one({
        'email': data.get('email', None),
        'password': hashlib.sha256(data.get('password'.encode('utf-8'))).hexdigest()
    })

    #if user exists in our DB
    if result is not None:
        #create payload(objectID of user and expiration of token)
        payload = {
            'id': str(result['_id']), #extracts and stores objectID of the user we've identified
            'exp': datetime.utcnow() + timedelta(seconds = 60*60*24) #expires in one day from the time token is created
        }
        #creates JWT w/ the payload, key and algo
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        #return token to client side
        return jsonify({'result': 'success', 'msg': "signin successful!", 'token': token})
    #if no user was found w/ corresponding id and pw
    else:
        return jsonify({'result': 'fail!', 'msg': 'wrong info'})




if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)

