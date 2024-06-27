from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from ai_module import AI_Module  # Assuming AI_Module is a class in ai_module.py that handles the AI operations
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
import logging
from Crypto.Cipher import AES
import base64
import os
from OpenSSL import SSL

context = SSL.Context(SSL.SSLv23_METHOD)
context.use_privatekey_file('yourserver.key')
context.use_certificate_file('yourserver.crt')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'  # Use your actual database URI
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
db = SQLAlchemy(app)
jwt = JWTManager(app)

logging.basicConfig(filename='api.log', level=logging.DEBUG)

class Classification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    priority = db.Column(db.String(50), nullable=False)
    probability = db.Column(db.Float, nullable=False)
    bug_classification_id = db.Column(db.Integer, db.ForeignKey('bug_classification.id'), nullable=False)

class BugClassification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    classifications = db.relationship('Classification', backref='bug_classification', lazy=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username', None)
    password = data.get('password', None)
    email = data.get('email', None)

    if not username or not password or not email:
        return jsonify({"msg": "Missing username, password or email"}), 400

    key = app.config['JWT_SECRET_KEY'].encode('utf-8')
    encrypted_password = encrypt_data(password, key)
    encrypted_email = encrypt_data(email, key)

    new_user = User(username=username, password=encrypted_password, email=encrypted_email)
    db.session.add(new_user)
    db.session.commit()

    app.logger.info('User signed up successfully')
    return jsonify({"msg": "User signed up successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', None)
    password = data.get('password', None)

    # Validate user credentials (username and password) here
    # This is just a placeholder and should be replaced with actual user validation logic

    if username == "test" and password == "test":
        access_token = create_access_token(identity=username)
        app.logger.info('User logged in successfully')
        return jsonify(access_token=access_token), 200

    app.logger.warning('Failed login attempt')
    return jsonify({"msg": "Bad username or password"}), 401

@app.route('/bug_classification', methods=['POST'])
@jwt_required
def create_bug_classification():
    data = request.get_json()
    bug_report = data['bugReportDetails']
    model_config = data['modelConfiguration']

    ai = AI_Module(model_config)
    classification_results = ai.classify_bug(bug_report)  # Assuming classify_bug is a method in AI_Module

    new_bug_classification = BugClassification()
    db.session.add(new_bug_classification)
    db.session.commit()

    for result in classification_results:
        new_classification = Classification(priority=result['priority'], probability=result['probability'], bug_classification_id=new_bug_classification.id)
        db.session.add(new_classification)

    db.session.commit()

    app.logger.info('Bug classification created successfully')
    return jsonify({"classifications": classification_results, "message": "Bug classification created successfully."}), 201

@app.route('/bug_classification/<int:id>', methods=['DELETE'])
@jwt_required
def delete_bug_classification(id):
    bug_classification = BugClassification.query.get_or_404(id)
    db.session.delete(bug_classification)
    db.session.commit()
    app.logger.info('Bug classification deleted successfully')
    return jsonify({"message": "Bug classification deleted successfully."}), 200

@app.route('/bug_classification/<int:id>', methods=['GET'])
@jwt_required
def get_bug_classification(id):
    bug_classification = BugClassification.query.get_or_404(id)
    classifications = Classification.query.filter_by(bug_classification_id=id).all()
    classification_results = [{"priority": c.priority, "probability": c.probability} for c in classifications]
    app.logger.info('Bug classification retrieved successfully')
    return jsonify({"id": bug_classification.id, "classifications": classification_results})

@app.route('/bug_classification/<int:id>', methods=['PUT'])
@jwt_required
def update_bug_classification(id):
    data = request.get_json()
    bug_report = data['bugReportDetails']
    model_config = data['modelConfiguration']

    ai = AI_Module(model_config)
    classification_results = ai.classify_bug(bug_report)

    bug_classification = BugClassification.query.get_or_404(id)
    Classification.query.filter_by(bug_classification_id=id).delete()

    for result in classification_results:
        new_classification = Classification(priority=result['priority'], probability=result['probability'], bug_classification_id=bug_classification.id)
        db.session.add(new_classification)

    db.session.commit()

    app.logger.info('Bug classification updated successfully')
    return jsonify({"classifications": classification_results, "message": "Bug classification updated successfully."}), 200

if __name__ == '__main__':
    app.run(debug=True, ssl_context=context)
