import boto3
from flask import Flask, render_template, request, redirect, session, url_for
from botocore.exceptions import ClientError
import hmac
import hashlib
import base64
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from ultralytics import YOLO
import cv2
import numpy

# Flask app initialization
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = './static/uploads'
app.config['SESSION_TYPE'] = 'filesystem'

# AWS Configuration
aws_session = boto3.Session(
    aws_access_key_id='AKIA5V6I6ZNU4BBNHJH2',
    aws_secret_access_key='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',
    region_name='ap-south-1'
)

cognito_client = aws_session.client('cognito-idp')

USER_POOL_ID = 'ap-south-1_X6QiXtw8N'
CLIENT_ID = 'c9dq2b6s999kd2dg4kd16coh5'
CLIENT_SECRET = '15vio1l6srqano9uua8bs4fcblsh9tleebfq40bnhoslrur9lnfa'

model = YOLO("./models/best.pt")

# Sample nutritional data dictionary (Replace with API call for real data)
NUTRITIONAL_INFO = {
    'rice': {'calories': 95, 'protein': 0.5, 'fat': 0.3, 'carbs': 25},
    'chapati': {'calories': 105, 'protein': 1.3, 'fat': 0.4, 'carbs': 27}
}

# Helper function: compute SECRET_HASH
def compute_secret_hash(username):
    message = username + CLIENT_ID
    digest = hmac.new(CLIENT_SECRET.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(digest).decode()

# Helper function: check authentication
def is_authenticated():
    return 'id_token' in session

@app.route('/')
def home():
    if not is_authenticated():
        return redirect(url_for('login'))
    return render_template('index.html')

# Upload and process image
# Upload and process image
# Upload and process image
# Upload and process image
# Upload and process image
# Upload and process image
@app.route('/upload', methods=['POST'])
def upload():
    if not is_authenticated():
        return redirect(url_for('login'))

    if 'image' not in request.files:
        return "No file uploaded", 400

    file = request.files['image']
    if file and file.filename:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # YOLOv8 Inference
        results = model(filepath)

        # Access the first result in the list (YOLO returns a list of results)
        result = results[0]

        # Extract detected labels and bounding boxes
        detected_labels = result.names  # List of class names
        boxes = result.boxes.xywh  # Get bounding box coordinates (x_center, y_center, width, height)
        confidences = result.boxes.conf  # Confidence scores for each detected box
        class_ids = result.boxes.cls  # Class IDs for each detected box

        # Convert class IDs to integers
        class_ids = class_ids.cpu().numpy().astype(int)

        # Get unique labels from the detected boxes
        detected_labels_in_image = {detected_labels[class_id] for class_id in class_ids}

        # Create a list of detected items with their nutritional information
        item_info = []
        for label in detected_labels_in_image:
            if label.lower() in NUTRITIONAL_INFO:
                item_info.append({
                    'item': label,
                    'calories': NUTRITIONAL_INFO[label.lower()]['calories'],
                    'protein': NUTRITIONAL_INFO[label.lower()]['protein'],
                    'fat': NUTRITIONAL_INFO[label.lower()]['fat'],
                    'carbs': NUTRITIONAL_INFO[label.lower()]['carbs']
                })

        # Annotate the image with the bounding boxes and labels
        annotated_image = result.plot()  # This automatically adds bounding boxes

        # Save the annotated (processed) image
        processed_filename = f'processed_{filename}'
        processed_filepath = os.path.join(app.config['UPLOAD_FOLDER'], processed_filename)
        cv2.imwrite(processed_filepath, annotated_image)

        # Provide the relative path for the processed image for Flask to render
        processed_image_url = f'static/uploads/{processed_filename}'

        # Render the template with the processed image displayed and the nutritional info
        return render_template(
            'index.html',
            original_image=None,  # Hide the original image
            processed_image=processed_image_url,  # Display the processed image
            item_info=item_info  # Pass the detected food and its nutritional information
        )

    return "Invalid file or no file provided", 400




# Cognito Sign-Up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        birthdate = request.form['birthdate']
        gender = request.form['gender']
        phone_number = request.form['phone_number']
        given_name = request.form['given_name']
        family_name = request.form['family_name']

        # Compute SecretHash for the email
        secret_hash = compute_secret_hash(email)

        try:
            response = cognito_client.sign_up(
                ClientId=CLIENT_ID,
                SecretHash=secret_hash,
                Username=email,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'birthdate', 'Value': birthdate},
                    {'Name': 'gender', 'Value': gender},
                    {'Name': 'phone_number', 'Value': phone_number},
                    {'Name': 'given_name', 'Value': given_name},
                    {'Name': 'family_name', 'Value': family_name}
                ]
            )
            return redirect(url_for('confirm_signup'))
        except ClientError as e:
            return f"Error: {e.response['Error']['Message']}"

    max_date = datetime.now().strftime('%Y-%m-%d')
    return render_template('signup.html', max_date=max_date)

@app.route('/confirm_signup', methods=['GET', 'POST'])
def confirm_signup():
    if request.method == 'POST':
        email = request.form['email']
        code = request.form['code']

        if not email or not code:
            error_message = "Email and confirmation code are required."
            return render_template('confirm_signup.html', error=error_message)

        try:
            response = cognito_client.confirm_sign_up(
                ClientId=CLIENT_ID,
                SecretHash=compute_secret_hash(email),
                Username=email,
                ConfirmationCode=code
            )
            success_message = "Your account has been verified successfully! Please log in."
            return render_template('login.html', success=success_message)
        except ClientError as e:
            error_message = e.response['Error']['Message']
            return render_template('confirm_signup.html', error=error_message)

    return render_template('confirm_signup.html')

# Cognito Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            response = cognito_client.initiate_auth(
                ClientId=CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password,
                    'SECRET_HASH': compute_secret_hash(email)
                }
            )
            if 'AuthenticationResult' in response:
                session['id_token'] = response['AuthenticationResult']['IdToken']
                session['username'] = email
                return redirect(url_for('home'))
            else:
                error_message = response.get('ChallengeName', 'Unexpected error occurred during login.')
                return render_template('login.html', error=f"Authentication challenge: {error_message}")
        except ClientError as e:
            error_message = e.response['Error']['Message']
            return render_template('login.html', error=f"Error: {error_message}")

    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('id_token', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)