from flask import Flask,jsonify,request,make_response
from flask_sqlalchemy import SQLAlchemy
import datetime
import jwt
from flask_bcrypt import Bcrypt
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] ='gfhdftygytgcgc67865fxcgfdxfhcvddxxxv'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flask.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

def token_required(func):
    @wraps(func)
    def decorated(*args,**kwargs):
        token = None
        if 'x-access-token' in request-headers:
            token = request-headers['x-access-token']
        
        if not token:
            return jsonify ({"message":"Token is Missing"}),401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            next_user = User.query.filter_by(username = data['username']).first()

        except:
            return jsonify({"message":"token is Invalid"}),401

        return func(next_user,*args, **kwargs)
    
    return decorated




@app.route('/create',methods=['POST'])
@token_required
def create_user(next_user):
    data = request.get_json()
    pw_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(email = data['email'], password = pw_hash, username = data['username'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message":"new user is successfully created"})

@app.route('/getusers',methods=['GET'])
@token_required
def getusers(next_user):
    users = User.query.all()

    output = []

    for user in users:
        user_data ={}
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['username'] = user.username

        output.append(user_data)

    return jsonify({"users":output})

@app.route('/getoneuser/<int:id>',methods=['GET'])
@token_required
def getuser(next_user,id):
    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({"'message":"No User Found"})

    user_data ={}
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['username'] = user.username

    return jsonify({"user":user_data})
    
@app.route('/user/<int:id>',methods=['DELETE'])
@token_required
def removeuser(next_user,id):
    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({"'message":"No User Found"})

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message":"User successfully deleted"})

@app.route('/login',methods=['POST','GET'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response ('Couldnot Verify',401,{'WWW-Aunthenticate': 'Basic realm: "Login Required !!!"'})
    
    user = User.query.filter_by(username = auth.username).first()

    if user:
        if bcrypt.check_password_hash(user.password,auth.password):
            token = jwt.encode({"email":user.email,"exp":datetime.datetime.utcnow() + datetime.timedelta(minutes=35)},app.config['SECRET_KEY'])
            return jsonify({"token":token.decode('utf-8')})
        
        else:
            return make_response ('Couldnot Verify111',401,{'WWW-Aunthenticate': 'Basic realm: "Login Required !!!"'})


    return make_response ('Couldnot Verify',401,{'WWW-Aunthenticate': 'Basic realm: "Login Required !!!"'})




if __name__ == '__main__':
    app.run(debug=True)