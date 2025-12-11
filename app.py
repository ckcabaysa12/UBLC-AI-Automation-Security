import os
import json
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from openai import OpenAI
from dotenv import load_dotenv
from datetime import datetime
import smtplib 
from email.mime.text import MIMEText 
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
# --- CORRECTED IMPORTS ---
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash # <- CORRECTED
import mimetypes 

# --- NEW FIREBASE IMPORTS ---
import firebase_admin
from firebase_admin import credentials, firestore
# --- END FIREBASE IMPORTS ---

# --- Configuration and Initialization ---
load_dotenv()
app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24) 

# --- File Upload Configuration ---
UPLOAD_FOLDER = 'static/uploads/incidents' 
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- FIREBASE INITIALIZATION ---
FIREBASE_CREDENTIALS_PATH = os.getenv("FIREBASE_CREDENTIALS_PATH")
db = None

if FIREBASE_CREDENTIALS_PATH and os.path.exists(FIREBASE_CREDENTIALS_PATH):
    try:
        cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("Firebase Admin SDK initialized successfully.")
    except Exception as e:
        print(f"Error initializing Firebase: {e}")
        db = None
else:
    print("FATAL ERROR: FIREBASE_CREDENTIALS_PATH not set or file not found. Database features will fail.")

# --- OPENAI INITIALIZATION ---
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY not found. Please set it in your .env file.")
client = OpenAI(api_key=OPENAI_API_KEY)

# --- User Management (Staff Credentials from .env) ---
STAFF_USERNAME = os.getenv("STAFF_USERNAME", "ublc_security")
STAFF_PASSWORD = os.getenv("STAFF_PASSWORD", "final_exam") 

# --- Data Loading & System Prompt (Unchanged) ---
SECURITY_DATA = {}
try:
    with open('data/security_data.json', 'r', encoding='utf-8') as f:
        SECURITY_DATA = json.load(f)
    print("Security data loaded successfully.")
except Exception as e:
    print(f"Error loading security data: {e}")

SYSTEM_PROMPT = f"""
You are the **UBLC Campus Security AI Assistant**. Your knowledge is limited **ONLY** to the provided SECURITY KNOWLEDGE BASE.

**UBLC SECURITY KNOWLEDGE BASE (MUST BE USED):**
{json.dumps(SECURITY_DATA, indent=2)}

**STRICT RESPONSE RULES:**
1.  **AUTHORIZED TOPICS:** You MUST only answer questions related to **Lost and Found, Incident Reporting, Parking Rules, Visitor Policy, and Emergency Procedures**. These are the only topics you are allowed to discuss.
2.  **DATA RELIANCE:** Use the KNOWLEDGE BASE data for all answers.
3.  **FORM PROVISION:** If the user asks for a Lost Item or Incident Form, inform the user that they can use the **'Submit New Incident Report' button** located above the chat input box for immediate access to the form.
4.  **CONTEXT HANDLING:** When a user initiates a conversation about an AUTHORIZED TOPIC, maintain the context and use the data until the conversation concludes. DO NOT use the out-of-scope response unless the topic explicitly shifts away.
5.  **OUT OF SCOPE:** If the query is NOT one of the five AUTHORIZED TOPICS, you MUST respond with: "**My focus is strictly on Campus Security and Safety protocols. Please contact the respective UBLC office for that inquiry.**"
"""

# --- Helper Function for File Check ---
def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Authentication & Signup Routes (UPDATED for Firestore) ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form["username"]
        password = request.form["password"]

        # Staff Login (In-Memory/Env check)
        if username_or_email == STAFF_USERNAME and password == STAFF_PASSWORD:
            session['logged_in'] = True
            session['user_type'] = 'staff'
            session['username'] = STAFF_USERNAME
            session.pop('history', None) 
            return redirect(url_for('home'))
        
        # Student Login (Firestore check)
        if db:
            try:
                user_ref = db.collection('students').document(username_or_email)
                user_doc = user_ref.get()
                
                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    # Check the hashed password
                    if 'password' in user_data and check_password_hash(user_data['password'], password):
                        session['logged_in'] = True
                        session['user_type'] = 'student'
                        session['username'] = username_or_email
                        session.pop('history', None) 
                        return redirect(url_for('home'))
            except Exception as e:
                app.logger.error(f"Firestore read error during login: {e}")
                # Fall through to invalid credentials message

        # Invalid Credentials
        return render_template('login.html', error='Invalid credentials. Please try again.')
        
    return render_template('login.html')

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    session.pop('user_type', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if not db:
        # Prevent registration if Firebase failed to initialize
        return render_template('signup.html', error="System error: Database connection failed.")
    
    if request.method == "POST":
        full_name = request.form["full_name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        
        # Validation checks
        if password != confirm_password:
            return render_template('signup.html', error="Passwords do not match.")
        if "@ublc.edu.ph" not in email:
            return render_template('signup.html', error="Registration requires a valid @ublc.edu.ph email address.")
        
        try:
            # 1. Check if email already exists in Firestore
            user_ref = db.collection('students').document(email)
            if user_ref.get().exists:
                return render_template('signup.html', error="This email is already registered.")

            # 2. HASH THE PASSWORD (SECURE)
            hashed_password = generate_password_hash(password)
            
            # 3. WRITE DATA TO FIRESTORE
            user_data = {
                'full_name': full_name,
                'email': email,
                'password': hashed_password, # <--- SECURE HASHED PASSWORD STORED HERE
                'registration_date': firestore.SERVER_TIMESTAMP,
                'user_type': 'student'
            }
            user_ref.set(user_data)
            
            print(f"NEW STUDENT REGISTERED AND SAVED TO FIRESTORE: {email}")
            
            # 4. Create Session
            session['logged_in'] = True
            session['user_type'] = 'student'
            session['username'] = email 
            session.pop('history', None)
            
            return redirect(url_for('home'))

        except Exception as e:
            app.logger.error(f"Firestore write error during signup: {e}")
            return render_template('signup.html', error="Registration failed due to a database error. Please try again.")
            
    return render_template('signup.html')


# --- Main Chat Routes (Unchanged) ---
@app.route("/")
def home():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template("index.html")

@app.route("/chat", methods=["POST"])
def chat():
    if not session.get('logged_in'):
        return jsonify({"answer": "Please log in to use the assistant."})
    user_message = request.json.get("message")
    if not user_message:
        return jsonify({"answer": "Please provide a message."})
    
    history = session.get('history', [])
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history)
    messages.append({"role": "user", "content": user_message})
    
    try:
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages
        )
        ai_response = completion.choices[0].message.content
        history.append({"role": "user", "content": user_message})
        history.append({"role": "assistant", "content": ai_response})
        session['history'] = history
        return jsonify({"answer": ai_response})
    except Exception as e:
        app.logger.error(f"OpenAI API Error: {e}")
        return jsonify({"answer": "An error occurred while connecting to the AI. Please try again later."}), 500

# --- Flask Form Automation Routes (Unchanged) ---

@app.route("/report_form")
def report_form():
    """Renders the simple incident report form (publicly accessible)."""
    return render_template("incident_report.html")

@app.route("/submit_report", methods=["POST"])
def submit_report():
    """
    Handles form submission including file upload and sends the report with the attachment.
    """
    uploaded_file_path = None
    report_id = datetime.now().strftime('%Y%m%d%H%M%S')
    
    try:
        # 1. Handle File Upload
        file_extension = None
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and allowed_file(file.filename):
                # Sanitize filename and create unique name
                filename = secure_filename(file.filename)
                file_extension = filename.rsplit('.', 1)[1].lower()
                unique_filename = f"report_{report_id}.{file_extension}"
                uploaded_file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                # Save the file to the server
                file.save(uploaded_file_path)
                print(f"File saved successfully: {uploaded_file_path}")
            elif file.filename != '':
                # Handle case where file is provided but extension is wrong
                return render_template("report_confirmation.html", error_message="Invalid file type. Only PNG, JPG, or JPEG are allowed.")


        # 2. Capture Form Data
        report_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reporter_name": request.form.get("reporter_name"),
            "reporter_contact": request.form.get("reporter_contact"),
            "incident_type": request.form.get("incident_type"),
            "location": request.form.get("location"),
            "description": request.form.get("description")
        }

        # --- Automation: Send Email ---
        
        # Create message container - the correct MIME type is multipart/mixed
        msg = MIMEMultipart('mixed')
        msg['Subject'] = f"SECURITY ALERT: {report_data['incident_type']} - Location: {report_data['location']}"
        msg['From'] = os.getenv("SENDER_EMAIL")
        msg['To'] = os.getenv("RECIPIENT_EMAIL")

        # 3. Build Email Body (Text part)
        body_text = f"""
        *** NEW UBLC INCIDENT REPORT - ACTION REQUIRED ***

        Report ID: {report_id}
        Timestamp: {report_data['timestamp']}
        Incident Type: {report_data['incident_type']}
        Location: {report_data['location']}
        
        --- Details ---
        Reporter Name: {report_data['reporter_name'] or 'Anonymous'}
        Contact: {report_data['reporter_contact']}
        
        Description: 
        {report_data['description']}
        
        --- Attachment Status ---
        {'Image attached.' if uploaded_file_path else 'No image attached.'}
        
        --- End of Report ---
        """
        msg.attach(MIMEText(body_text, 'plain'))

        # 4. Attach Image (if uploaded and saved)
        if uploaded_file_path and os.path.exists(uploaded_file_path):
            
            # Use mimetypes to determine the exact content type (e.g., image/jpeg)
            ctype, encoding = mimetypes.guess_type(uploaded_file_path)
            if ctype is None or encoding is not None:
                ctype = 'application/octet-stream' 
            
            maintype, subtype = ctype.split('/', 1)

            with open(uploaded_file_path, 'rb') as fp:
                
                if maintype == 'image':
                    # Use MIMEImage for images
                    attachment = MIMEImage(fp.read(), _subtype=subtype)
                else:
                    # Fallback for general file types
                    attachment = MIMEText(fp.read(), _subtype=subtype)
                
                # Set the attachment name
                attachment.add_header('Content-Disposition', 'attachment', filename=f"{report_id}.{file_extension}")
                
                msg.attach(attachment)
                print(f"Attachment successfully created with MIME type: {ctype}")

        # 5. Send via SMTP
        with smtplib.SMTP(os.getenv("SMTP_SERVER"), int(os.getenv("SMTP_PORT"))) as server:
            server.starttls()
            server.login(os.getenv("SENDER_EMAIL"), os.getenv("SENDER_PASSWORD"))
            server.sendmail(os.getenv("SENDER_EMAIL"), os.getenv("RECIPIENT_EMAIL"), msg.as_string())
        
        print(f"AUTOMATION SUCCESS: Report ID {report_id} emailed to security.")

        # 6. Return confirmation message
        return render_template("report_confirmation.html", report_id=report_id, contact=report_data['reporter_contact'])

    except Exception as e:
        app.logger.error(f"Email submission error: {e}")
        # Clean up file if it was saved but email failed
        if uploaded_file_path and os.path.exists(uploaded_file_path):
            os.remove(uploaded_file_path)
        return render_template("report_confirmation.html", error=True)


if __name__ == "__main__":
    app.run(debug=True)