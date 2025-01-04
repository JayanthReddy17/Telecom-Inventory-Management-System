from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
from mysql.connector import pooling
import bcrypt
import jwt
import datetime
from functools import wraps

# Initialize app and middleware
app = Flask(__name__)
CORS(app)

# Configuration
PORT = 5000
JWT_SECRET = '12345'  # Replace with a secure key

# MySQL connection pooling
db_config = {
    'host': 'localhost',
    'user': 'root',  # Replace with your MySQL username
    'password': 'password',  # Replace with your MySQL password
    'database': 'inventory'  # Replace with your database name
}

connection_pool = pooling.MySQLConnectionPool(pool_name="mypool", pool_size=5, **db_config)

# Utility function to query the database
def query(sql, params=None):
    try:
        connection = connection_pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(sql, params)
        result = cursor.fetchall()
        cursor.close()
        connection.close()
        return result
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        raise

def execute(sql, params=None):
    try:
        connection = connection_pool.get_connection()
        cursor = connection.cursor()
        cursor.execute(sql, params)
        connection.commit()
        cursor.close()
        connection.close()
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        raise

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]
        if not token:
            return jsonify({'error': 'Token is missing'}), 403

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 403

        return f(current_user, *args, **kwargs)
    return decorated_function

# Routes

# User authentication
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    role = data['role']
    first_name = data['firstName']
    last_name = data['lastName']
    phone = data.get('phone')
    email = data.get('email')

    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        execute(
            '''
            INSERT INTO Users (UserName, Password, FirstName, LastName, Role, Phone, Email) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''',
            (username, hashed_password, first_name, last_name, role, phone, email)
        )
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as err:
        return jsonify({'error': 'Error registering user'}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    try:
        users = query('SELECT * FROM Users WHERE UserName = %s', (username,))
        user = users[0] if users else None
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['Password'].encode('utf-8')):
            return jsonify({'error': 'Invalid credentials'}), 401

        token = jwt.encode({
            'id': user['UserId'],
            'role': user['Role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm='HS256')

        return jsonify({'token': token})
    except Exception as err:
        return jsonify({'error': 'Error logging in'}), 500

# Product routes
@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user):
    try:
        products = query('SELECT * FROM product')
        return jsonify(products)
    except Exception as err:
        return jsonify({'error': 'Error fetching products'}), 500

@app.route('/products', methods=['POST'])
@token_required
def add_product(current_user):
    data = request.get_json()
    name = data['name']
    description = data.get('description')
    product_image = data.get('productImage')
    category = data.get('productCategoryName')
    model_number = data.get('modelNumber')
    serial_number = data.get('serialNumber')
    stock_level = data.get('stockLevel')
    reorder_point = data.get('reorderPoint')
    supplier_id = data.get('supplierId')

    try:
        execute(
            '''
            INSERT INTO product (ProductName, Description, ProductImage, ProductCategoryName, 
                                 ModelNumber, SerialNumber, StockLevel, ReorderPoint, SupplierId)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''',
            (name, description, product_image, category, model_number, serial_number, stock_level, reorder_point, supplier_id)
        )
        return jsonify({'message': 'Product added successfully'}), 201
    except Exception as err:
        return jsonify({'error': 'Error adding product'}), 400

# Supplier routes
@app.route('/suppliers', methods=['GET'])
@token_required
def get_suppliers(current_user):
    try:
        suppliers = query('SELECT * FROM supplier')
        return jsonify(suppliers)
    except Exception as err:
        return jsonify({'error': 'Error fetching suppliers'}), 500

@app.route('/transactions', methods=['POST'])
@token_required
def create_transaction(current_user):
    data = request.get_json()
    product_id = data['productId']
    quantity = data['quantity']
    transaction_type = data['type']
    user_id = current_user['id']

    try:
        execute(
            '''
            INSERT INTO transactions (productid, userid, quantity, type)
            VALUES (%s, %s, %s, %s)
            ''',
            (product_id, user_id, quantity, transaction_type)
        )
        return jsonify({'message': 'Transaction recorded successfully'}), 201
    except Exception as err:
        return jsonify({'error': 'Error recording transaction'}), 400

# Start the server
if __name__ == '__main__':
    app.run(port=PORT, debug=True)
