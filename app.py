import os
import json
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from openai import OpenAI
from dotenv import load_dotenv
from datetime import datetime, timedelta 
import smtplib 
from email.mime.text import MIMEText 
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import mimetypes 
from functools import wraps 

# --- FIREBASE IMPORTS ---
import firebase_admin
from firebase_admin import credentials, firestore
# CRITICAL: Ensure FieldFilter is imported for the 'where' clause
from google.cloud.firestore_v1.base_query import FieldFilter 
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

# --- STAFF DECORATOR ---
def staff_required(f):
    """Decorator to ensure only staff can access a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in') or session.get('user_type') != 'staff':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# --- ANALYTICS HELPER FUNCTION ---
def generate_analytics_data(reports):
    """
    Processes the list of incident reports to generate structured data for dashboard charts and KPIs.
    """
    if not reports:
        return {'timeline': {'dates': [], 'volumes': []}, 'breakdown': {'labels': [], 'data': []}, 'reports_this_week': 0, 'resolution_rate': '0.0%'}

    type_counts = {}
    daily_counts = {}
    reports_this_week_count = 0
    
    seven_days_ago = datetime.now() - timedelta(days=7)

    for report in reports:
        incident_type = report.get('incident_type', 'Other')
        type_counts[incident_type] = type_counts.get(incident_type, 0) + 1

        timestamp = report.get('timestamp')
        
        if timestamp and isinstance(timestamp, datetime):
            
            if timestamp.replace(tzinfo=None) > seven_days_ago: 
                reports_this_week_count += 1
                
            date_str = timestamp.strftime('%Y-%m-%d')
            daily_counts[date_str] = daily_counts.get(date_str, 0) + 1
        
    total_reports = len(reports)
    resolved_reports = sum(1 for r in reports if r.get('status') in ['Resolved', 'Closed'])
    
    resolution_rate = 0.0
    if total_reports > 0:
        resolution_rate = (resolved_reports / total_reports) * 100
    
    analytics_output = {
        'reports_this_week': reports_this_week_count,
        'breakdown': {
            'labels': list(type_counts.keys()),
            'data': list(type_counts.values())
        },
        'timeline': {
            'dates': sorted(daily_counts.keys()),
            'volumes': [daily_counts[d] for d in sorted(daily_counts.keys())]
        },
        'resolution_rate': f"{resolution_rate:.1f}%"
    }
    
    return analytics_output
# --- END ANALYTICS HELPER FUNCTION ---


# ----------------------------------------------------------------------------------
#                                 AUTHENTICATION ROUTES
# ----------------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form["username"]
        password = request.form["password"]

        # Staff Login
        if username_or_email == STAFF_USERNAME and password == STAFF_PASSWORD:
            session['logged_in'] = True
            session['user_type'] = 'staff'
            session['username'] = STAFF_USERNAME
            session.pop('history', None) 
            return redirect(url_for('staff_dashboard'))
        
        # Student Login (via email)
        if db:
            try:
                user_ref = db.collection('students').document(username_or_email)
                user_doc = user_ref.get()
                
                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    if 'password' in user_data and check_password_hash(user_data['password'], password):
                        session['logged_in'] = True
                        session['user_type'] = 'student'
                        session['username'] = username_or_email
                        session.pop('history', None) 
                        return redirect(url_for('home'))
            except Exception as e:
                app.logger.error(f"Firestore read error during login: {e}")

        return render_template('login.html', error='Invalid credentials. Please try again.')
        
    return render_template('login.html')

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    session.pop('user_type', None)
    session.pop('username', None)
    session.pop('history', None)
    session.pop('chat_log_id', None) # Clear the unique chat session ID
    return redirect(url_for('login'))


@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if not db:
        return render_template('signup.html', error="System error: Database connection failed.")
    
    if request.method == "POST":
        full_name = request.form["full_name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        
        if password != confirm_password:
            return render_template('signup.html', error="Passwords do not match.")
        
        try:
            user_ref = db.collection('students').document(email)
            if user_ref.get().exists:
                return render_template('signup.html', error="This email is already registered.")

            hashed_password = generate_password_hash(password)
            
            user_data = {
                'full_name': full_name,
                'email': email,
                'password': hashed_password, 
                'registration_date': firestore.SERVER_TIMESTAMP,
                'user_type': 'student'
            }
            user_ref.set(user_data)
            
            session['logged_in'] = True
            session['user_type'] = 'student'
            session['username'] = email 
            session.pop('history', None)
            
            return redirect(url_for('home'))

        except Exception as e:
            app.logger.error(f"Firestore write error during signup: {e}")
            return render_template('signup.html', error="Registration failed due to a database error. Please try again.")
            
    return render_template('signup.html')


# ----------------------------------------------------------------------------------
#                                 STAFF DASHBOARD ROUTES
# ----------------------------------------------------------------------------------

@app.route("/staff/dashboard")
@staff_required
def staff_dashboard():
    if not db:
        empty_analytics = generate_analytics_data([])
        return render_template('staff_dashboard.html', reports=[], incident_counts={}, total_reports=0, active_reports=0, analytics=empty_analytics, error="Database connection failed. Cannot fetch reports.")
    
    try:
        reports_ref = db.collection('incidents').order_by('timestamp', direction=firestore.Query.DESCENDING).stream()
        reports = []
        incident_counts = {'New': 0, 'In Progress': 0, 'Resolved': 0, 'Closed': 0}
        
        for doc in reports_ref:
            report = doc.to_dict()
            report['id'] = doc.id
            
            if report.get('timestamp') and hasattr(report['timestamp'], 'strftime'):
                 report['timestamp'] = report['timestamp'].astimezone(None)
                 report['timestamp_str'] = report['timestamp'].strftime("%b %d, %H:%M %p")
            else:
                 report['timestamp_str'] = str(report.get('timestamp', 'N/A'))
                 report['timestamp'] = None 

            status = report.get('status', 'New')
            report['status'] = status
            
            if status in incident_counts:
                incident_counts[status] += 1
            
            reports.append(report)
            
        analytics_data = generate_analytics_data(reports)
        
        total_reports = len(reports)
        active_reports = incident_counts['New'] + incident_counts['In Progress']
        
        return render_template("staff_dashboard.html", 
                               reports=reports,
                               incident_counts=incident_counts,
                               total_reports=total_reports,
                               active_reports=active_reports,
                               analytics=analytics_data)

    except Exception as e:
        app.logger.error(f"Error fetching dashboard data: {e}")
        empty_analytics = generate_analytics_data([])
        return render_template('staff_dashboard.html', reports=[], incident_counts={}, total_reports=0, active_reports=0, analytics=empty_analytics, error="Failed to load incident reports from database.")


@app.route("/staff/report/<report_id>")
@staff_required
def view_report(report_id):
    """Fetches detailed report data and returns it as JSON for the AJAX modal."""
    if not db:
        return jsonify({"error": "Database not connected."}), 500
    
    try:
        report_doc = db.collection('incidents').document(report_id).get()
        if not report_doc.exists:
            return jsonify({"error": "Report not found."}), 404
        
        report_data = report_doc.to_dict()
        report_data['id'] = report_id
        
        if report_data.get('timestamp') and hasattr(report_data['timestamp'], 'strftime'):
            report_data['timestamp_str'] = report_data['timestamp'].astimezone(None).strftime("%B %d, %Y %I:%M %p")
            
        return jsonify(report_data) 
        
    except Exception as e:
        app.logger.error(f"Error fetching report {report_id}: {e}")
        return jsonify({"error": "Failed to load report details."}), 500

@app.route("/staff/update_status/<report_id>", methods=['POST'])
@staff_required
def update_report_status(report_id):
    """Handles AJAX request to update the status of an incident report in Firestore."""
    if not db:
        return jsonify({"error": "Database not connected."}), 500
    
    try:
        new_status = request.json.get('status')
        if new_status not in ['New', 'In Progress', 'Resolved', 'Closed']:
            return jsonify({"error": "Invalid status."}), 400
            
        db.collection('incidents').document(report_id).update({'status': new_status})
        
        return jsonify({"success": True, "message": f"Status updated to {new_status}"})
        
    except Exception as e:
        app.logger.error(f"Error updating report status {report_id}: {e}")
        return jsonify({"error": "Failed to update status."}), 500

# ----------------------------------------------------------------------------------
#                                 STUDENT/CHAT ROUTES
# ----------------------------------------------------------------------------------
@app.route("/")
def home():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if session.get('user_type') == 'student':
        return render_template("index.html")
    
    if session.get('user_type') == 'staff':
        return redirect(url_for('staff_dashboard'))
    
    return redirect(url_for('login'))


@app.route("/chat", methods=["POST"])
def chat():
    if not session.get('logged_in') or session.get('user_type') != 'student':
        return jsonify({"answer": "Please log in to use the assistant."}), 401
    
    user_message = request.json.get("message")
    if not user_message:
        return jsonify({"answer": "Please provide a message."})
    
    student_email = session.get('username')
    
    # Check for an existing log session ID or create a new one
    # We use a session ID to group all messages from one conversation together
    log_session_id = session.get('chat_log_id')
    
    # Retrieve current history from session
    history = session.get('history', [])
    
    # 1. Prepare message payload for OpenAI
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history)
    messages.append({"role": "user", "content": user_message})
    
    try:
        # 2. Call OpenAI API
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages
        )
        ai_response = completion.choices[0].message.content
        
        # 3. Update history for the current session
        user_msg_log = {"role": "user", "content": user_message, "timestamp": datetime.now()}
        ai_msg_log = {"role": "assistant", "content": ai_response, "timestamp": datetime.now()}
        
        history.append(user_msg_log)
        history.append(ai_msg_log)
        
        # 4. Save updated history to Flask session
        session['history'] = history
        
        # 5. Save/Update Log in Firestore
        if db:
            log_data = {
                'user_email': student_email,
                'timestamp': firestore.SERVER_TIMESTAMP, # Timestamp of the last activity
                'messages': history # Store the full history array
            }

            if not log_session_id:
                # First message of a new session: create a new document
                doc_ref = db.collection('chat_logs').document()
                doc_ref.set(log_data)
                session['chat_log_id'] = doc_ref.id # Store the new ID in the session
            else:
                # Subsequent message: update the existing document
                db.collection('chat_logs').document(log_session_id).update(log_data)
        
        return jsonify({"answer": ai_response})
        
    except Exception as e:
        app.logger.error(f"OpenAI API or Firestore Log Error: {e}")
        return jsonify({"answer": "An error occurred while connecting to the AI. Please try again later."}), 500

# ----------------------------------------------------------------------------------
#                           STUDENT FEATURES (PROFILE & INBOX)
# ----------------------------------------------------------------------------------

@app.route("/student/inbox")
def student_inbox():
    # Enforce student login
    if not session.get('logged_in') or session.get('user_type') != 'student':
        return redirect(url_for('login'))

    student_email = session.get('username')
    
    if not db:
        # This is where the error message is rendered if the database object is None
        return render_template('student_inbox.html', reports=[], error="Database connection failed.")
    
    try:
        # THIS IS THE QUERY THAT REQUIRES THE COMPOUND INDEX
        reports_ref = db.collection('incidents').where(
            filter=FieldFilter("reporter_contact", "==", student_email)
        ).order_by('timestamp', direction=firestore.Query.DESCENDING).stream()
        
        reports = []
        for doc in reports_ref:
            report = doc.to_dict()
            report['id'] = doc.id
            if report.get('timestamp') and hasattr(report['timestamp'], 'strftime'):
                 report['timestamp_str'] = report['timestamp'].astimezone(None).strftime("%b %d, %H:%M %p")
            reports.append(report)

        return render_template("student_inbox.html", reports=reports)

    except Exception as e:
        # If the index is missing, the Firebase client throws an exception here.
        app.logger.error(f"Error fetching student inbox for {student_email}: {e}")
        return render_template('student_inbox.html', reports=[], error="Failed to load your reports. Check the Firestore Index.")

@app.route("/student/profile")
def student_profile():
    # Enforce student login
    if not session.get('logged_in') or session.get('user_type') != 'student':
        return redirect(url_for('login'))

    student_email = session.get('username')
    
    if not db:
        return render_template('student_profile.html', user_data=None, error="Database connection failed.")
    
    try:
        user_doc = db.collection('students').document(student_email).get()
        
        if user_doc.exists:
            user_data = user_doc.to_dict()
            
            if user_data.get('registration_date') and hasattr(user_data['registration_date'], 'strftime'):
                user_data['registration_date_str'] = user_data['registration_date'].astimezone(None).strftime("%B %d, %Y")
            else:
                user_data['registration_date_str'] = 'N/A'
                
            user_data.pop('password', None) 
            
            return render_template("student_profile.html", user_data=user_data)
        else:
            return render_template('student_profile.html', user_data=None, error="User profile not found in database.")

    except Exception as e:
        app.logger.error(f"Error fetching student profile for {student_email}: {e}")
        return render_template('student_profile.html', user_data=None, error="Failed to load profile.")


# ----------------------------------------------------------------------------------
#                           REPORTING AND TRACKING ROUTES
# ----------------------------------------------------------------------------------
@app.route("/report_form")
def report_form():
    """Renders the simple incident report form (publicly accessible)."""
    return render_template("incident_report.html")

@app.route("/submit_report", methods=["POST"])
def submit_report():
    """
    Handles form submission, saves data to Firestore, handles file upload, and sends the email.
    """
    uploaded_file_path = None
    # Generate unique report ID
    report_id = datetime.now().strftime('UB-%Y%m%d%H%M%S')
    
    try:
        # 1. Handle File Upload
        file_extension = None
        unique_filename = None
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_extension = filename.rsplit('.', 1)[1].lower()
                unique_filename = f"{report_id}.{file_extension}"
                uploaded_file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                file.save(uploaded_file_path)
            elif file.filename != '':
                return render_template("report_confirmation.html", error_message="Invalid file type. Only PNG, JPG, or JPEG are allowed.")

        # Determine reporter contact (if logged in, use email; otherwise, use form contact)
        reporter_contact = session.get('username') if session.get('user_type') == 'student' else request.form.get("reporter_contact")
        
        # 2. Capture Form Data
        report_data = {
            "timestamp": datetime.now(),
            "reporter_name": request.form.get("reporter_name"),
            "reporter_contact": reporter_contact, # Use logged-in email if available
            "incident_type": request.form.get("incident_type"),
            "location": request.form.get("location"),
            "description": request.form.get("description"),
            "file_url": f"/static/uploads/incidents/{unique_filename}" if uploaded_file_path else None,
            "status": "New" 
        }

        # 3. SAVE REPORT TO FIRESTORE
        if db:
            db.collection('incidents').document(report_id).set(report_data)
        else:
            print("WARNING: Report not saved to database. Firestore not initialized.")
            
        # 4. Automation: Send Email (Unchanged logic)
        
        msg = MIMEMultipart('mixed')
        msg['Subject'] = f"SECURITY ALERT: {report_data['incident_type']} - Location: {report_data['location']}"
        msg['From'] = os.getenv("SENDER_EMAIL")
        msg['To'] = os.getenv("RECIPIENT_EMAIL")

        body_text = f"""
        *** NEW UBLC INCIDENT REPORT - ACTION REQUIRED ***

        Report ID: {report_id}
        Timestamp: {report_data['timestamp'].strftime("%Y-%m-%d %H:%M:%S")}
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

        if uploaded_file_path and os.path.exists(uploaded_file_path):
            ctype, encoding = mimetypes.guess_type(uploaded_file_path)
            if ctype is None or encoding is not None:
                ctype = 'application/octet-stream' 
            
            maintype, subtype = ctype.split('/', 1)

            with open(uploaded_file_path, 'rb') as fp:
                
                if maintype == 'image':
                    attachment = MIMEImage(fp.read(), _subtype=subtype)
                else:
                    attachment = MIMEText(fp.read(), _subtype=subtype)
                
                attachment.add_header('Content-Disposition', 'attachment', filename=f"{report_id}.{file_extension}")
                
                msg.attach(attachment)

        with smtplib.SMTP(os.getenv("SMTP_SERVER"), int(os.getenv("SMTP_PORT"))) as server:
            server.starttls()
            server.login(os.getenv("SENDER_EMAIL"), os.getenv("SENDER_PASSWORD"))
            server.sendmail(os.getenv("SENDER_EMAIL"), os.getenv("RECIPIENT_EMAIL"), msg.as_string())

        # 5. Return confirmation message
        return render_template("report_confirmation.html", report_id=report_id, contact=report_data['reporter_contact'])

    except Exception as e:
        app.logger.error(f"Report submission critical error: {e}")
        if uploaded_file_path and os.path.exists(uploaded_file_path):
            os.remove(uploaded_file_path)
        return render_template("report_confirmation.html", error=True)


@app.route("/track_report", methods=["GET"])
@app.route("/track_report/<report_id>", methods=["GET"])
def track_report_status(report_id=None):
    """
    Handles report tracking. If report_id is in URL, fetch details.
    """
    if request.args.get('report_id'):
        return redirect(url_for('track_report_status', report_id=request.args.get('report_id')))
        
    if not report_id:
        return render_template('track_report.html')

    if not db:
        return render_template('track_report.html', report_id=report_id, error="System error: Database connection failed.")
    
    try:
        report_doc = db.collection('incidents').document(report_id).get()
        
        if report_doc.exists:
            report_data = report_doc.to_dict()
            
            context = {
                'report_id': report_id,
                'status': report_data.get('status', 'N/A'),
                'incident_type': report_data.get('incident_type', 'N/A'),
                'location': report_data.get('location', 'N/A'),
            }
            return render_template('track_report.html', **context)
        else:
            return render_template('track_report.html', report_id=report_id, error=f"Report ID **{report_id}** not found. Please check your ID.")
            
    except Exception as e:
        app.logger.error(f"Error tracking report {report_id}: {e}")
        return render_template('track_report.html', report_id=report_id, error="Failed to fetch report status due to a server error.")


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    app.run(debug=True, port=port)