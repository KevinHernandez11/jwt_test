from jose import JWTError, jwt
from supabase import create_client, Client
from flask import Flask, request, jsonify , send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
import bcrypt
import os
import datetime

load_dotenv()
URL = os.getenv('SUPABASE_URL')
KEY = os.getenv('SUPABASE_KEY')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
cliente = create_client(URL, KEY)

def create_jwt(user_id: str):
    user_info = cliente.table('users').select('*').eq('id', user_id).execute()
    if user_info.data:
        user_info = user_info.data[0]
    
    if not user_info:
        raise ValueError("User not found")
    
    payload = {
        'user_id': user_id,
        'username': user_info['username'],
        'admin': user_info['admin'],
        'exp':datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

@app.route('/')
def index():
    return "¡Hello world!"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return send_from_directory('static', 'register.html')
    elif request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        age = data.get('age')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not all ([username, age, email, password, confirm_password]):
            return jsonify({'error': 'All fields are required'}), 400
        
        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        email_exist = cliente.table('users').select('*').eq('email', email).execute()
        if email_exist.data:
            return jsonify({'error': 'Email already exists'}), 400
        
        username_exist = cliente.table('users').select('*').eq('username', username).execute()
        if username_exist.data:
            return jsonify({'error': 'Username already exists'}), 400

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Insert the user into the database
        cliente.table('users').insert({
            'username': username,
            'age': age,
            'email': email,
            'password': hashed_password.decode('utf-8'),
            'admin': (admin := False)
        }).execute()
        return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return send_from_directory('static', 'login.html')
    elif request.method == 'POST':
        email = request.json.get('email')
        Password = request.json.get('password')

        if not email or not Password:
            return jsonify({'error': 'Email and password are required'}), 400

        user_response = cliente.table('users').select('id, email, password').eq('email', email).execute()

        if not user_response.data:
            return jsonify({'error': 'Invalid email or password'}), 401
        
        user = user_response.data[0]

        user_id = user['id']

        if not bcrypt.checkpw(Password.encode('utf-8'), user['password'].encode('utf-8')):
            return jsonify({'error': 'Invalid email or password'}), 401
        

        token = create_jwt(user_id)

        if not token:
            return jsonify({'error': 'Failed to create token'}), 500
        
        return {
            'message': 'Login successful',
            'token': token
        }, 200

 
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)