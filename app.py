from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import pymysql
import bcrypt
import pyotp

app = Flask(_name_)

# 🔹 MySQL Configuration for XAMPP
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",  # XAMPP default has no password
    "database": "secure_api"
}

# 🔹 Auto-create database and tables
def init_db():
    db = pymysql.connect(host=DB_CONFIG["host"], user=DB_CONFIG["user"], password=DB_CONFIG["password"])
    cursor = db.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS secure_api")
    db.commit()
    db.close()

    db = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(256) NOT NULL,
            twofa_secret VARCHAR(256) NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description VARCHAR(255),
            price DECIMAL(10,2) NOT NULL,
            quantity INT NOT NULL
        )
    """)
    
    db.commit()
    db.close()

# 🔹 Initialize database on startup
init_db()

# 🔹 JWT Configuration
app.config['JWT_SECRET_KEY'] = 'supersecretkey'
jwt = JWTManager(app)

# ✅ User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username, password = data.get("username"), data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    db = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute("INSERT INTO Users (username, password) VALUES (%s, %s)", (username, hashed_password))
    db.commit()
    db.close()

    return jsonify({"message": "User registered. Please login to set up 2FA."}), 201

# ✅ Login (Before Setting Up 2FA)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username, password = data.get("username"), data.get("password")

    db = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute("SELECT id, password, twofa_secret FROM Users WHERE username = %s", (username,))
    user = cursor.fetchone()
    db.close()

    if not user or not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Invalid username or password"}), 401

    if not user["twofa_secret"]:
        return jsonify({"message": "Login successful. Set up 2FA next."}), 200

    return jsonify({"message": "2FA already set up. Please verify your code."}), 200

# ✅ Generate QR Code for Google Authenticator
@app.route('/generate_qr/<username>', methods=['GET'])
def generate_qr(username):
    db = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute("SELECT twofa_secret FROM Users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user:
        db.close()
        return jsonify({"error": "User not found"}), 404

    if user["twofa_secret"]:
        db.close()
        return jsonify({"message": "2FA already set up. Please verify your code."}), 400

    # Generate 2FA Secret
    totp = pyotp.TOTP(pyotp.random_base32())
    secret = totp.secret
    cursor.execute("UPDATE Users SET twofa_secret = %s WHERE username = %s", (secret, username))
    db.commit()
    db.close()

    return jsonify({"secret": secret, "message": "Use this key in Google Authenticator."}), 200

# ✅ Verify 2FA Code
@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    username, twofa_code = data.get("username"), data.get("2fa_code")

    db = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute("SELECT twofa_secret FROM Users WHERE username = %s", (username,))
    user = cursor.fetchone()
    db.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    totp = pyotp.TOTP(user["twofa_secret"])
    if not totp.verify(twofa_code):
        return jsonify({"error": "Invalid 2FA code"}), 401

    token = create_access_token(identity=username)
    return jsonify({"message": "2FA verified", "token": token}), 200

# ✅ Create Product
@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    data = request.json
    name, description, price, quantity = data.get("name"), data.get("description"), data.get("price"), data.get("quantity")

    db = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute("INSERT INTO Products (name, description, price, quantity) VALUES (%s, %s, %s, %s)", 
                   (name, description, price, quantity))
    db.commit()
    db.close()

    return jsonify({"message": "Product added"}), 201

# ✅ Read All Products
@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    db = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute("SELECT * FROM Products")
    products = cursor.fetchall()
    db.close()

    return jsonify({"products": products})

# ✅ Update Product
@app.route('/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    data = request.json
    name, description, price, quantity = data.get("name"), data.get("description"), data.get("price"), data.get("quantity")

    db = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute("UPDATE Products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s", 
                   (name, description, price, quantity, product_id))
    db.commit()
    db.close()

    return jsonify({"message": "Product updated"}), 200

# ✅ Delete Product
@app.route('/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    db = pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute("DELETE FROM Products WHERE id=%s", (product_id,))
    db.commit()
    db.close()

    return jsonify({"message": "Product deleted"}), 200

# ✅ Run Flask App
if _name_ == '_main_':
    app.run(debug=True, port=5001)  # Use port 5001 to avoid Apache conflicts