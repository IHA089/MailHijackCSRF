import logging
from flask import Flask, request, make_response, render_template, session, jsonify, redirect, url_for, flash
from functools import wraps
import jwt as pyjwt
from collections import defaultdict
import uuid, datetime, sqlite3, hashlib, random, os, secrets, requests, string, time, urllib3

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

lab_type = "CSRF"
lab_name = "MailHijackCSRFLab"

user_data = {}
flag_data = {}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MailHijackCSRF = Flask(__name__)
MailHijackCSRF.secret_key = "vulnerable_lab_by_IHA089"

JWT_SECRET = "MoneyIsPower"

def generate_flag(length=10):
    charset = string.ascii_letters + string.digits
    random_string = ''.join(random.choices(charset, k=length))
    return random_string

def generate_code():
    first_two = ''.join(random.choices(string.digits, k=2))
    next_four = ''.join(random.choices(string.ascii_uppercase, k=4))
    last_two = ''.join(random.choices(string.digits, k=2))
    code = first_two + next_four + last_two
    return code

def create_database():
    db_path = os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        gmail TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        uuid TEXT NOT NULL,
        active TINYINT(1) DEFAULT 0,
        code TEXT NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS secondary_emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        email TEXT NOT NULL UNIQUE,
        active TINYINT(1) DEFAULT 0,
        token TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    numb = random.randint(100, 999)
    passw = "admin@"+str(numb)
    passw_hash = hashlib.md5(passw.encode()).hexdigest()
    user_uuid = str(uuid.uuid4())
    query = "INSERT INTO users (gmail, username, password, uuid, active, code) VALUES ('admin@iha089.org', 'admin', '"+passw_hash+"', '"+user_uuid+"', '1', '45AEDF32')"
    cursor.execute(query)

    for i in range(10):
        numa = random.randint(10, 100)
        numb = random.randint(100, 999)
        passw = "user@"+str(numb)
        email = "user"+str(numa)+"@iha089.org"
        username = "user"+str(numa)
        passw_hash = hashlib.md5(passw.encode()).hexdigest()
        user_uuid = str(uuid.uuid4())
        code = generate_code()
        query = "INSERT INTO users (gmail, username, password, uuid, active, code) VALUES ('"+email+"', '"+username+"', '"+passw_hash+"', '"+user_uuid+"', '1', '"+code+"')"
        cursor.execute(query)


    cursor.execute('''
    CREATE TABLE token_info(
        gmail TEXT NOT NULL,
        token TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    conn.commit()
    conn.close()
    
def check_database():
    db_path = os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    if not os.path.isfile(db_path):
        create_database()

check_database()

def get_db_connection():
    db_path=os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def check_cookies():
    user_uuid = request.cookies.get("uuid")
    jwt_token = request.cookies.get("jwt_token")

    if user_uuid in user_data and jwt_token == user_data[user_uuid]:
        decoded = pyjwt.decode(jwt_token, JWT_SECRET, algorithms="HS256")
        session['user'] = decoded['username']
        return True
    else:
        return False

@MailHijackCSRF.route('/')
def home():
    if not check_cookies():
        session.clear()
    return render_template('index.html', user=session.get('user'))

@MailHijackCSRF.route('/index.html')
def index_html():
    if not check_cookies():
        session.clear()
    return render_template('index.html', user=session.get('user'))

@MailHijackCSRF.route('/login.html')
def login_html():
    if not check_cookies():
        session.clear()
    return render_template('login.html')

@MailHijackCSRF.route('/check.html')
def check_html():
    return render_template('check.html', user=session.get('user'))

@MailHijackCSRF.route('/join.html')
def join_html():
    if not check_cookies():
        session.clear()
    return render_template('join.html')

@MailHijackCSRF.route('/forgot-password.html')
def forgor_password_html():
    if not check_cookies():
        session.clear()
    if 'user' in session:
        return render_template('dashboard.html', user=session.get('user'))
    return render_template('forgot-password.html')

@MailHijackCSRF.route('/acceptable.html')
def acceptable_html():
    if not check_cookies():
        session.clear()
    return render_template('acceptable.html', user=session.get('user'))

@MailHijackCSRF.route('/term.html')
def term_html():
    if not check_cookies():
        session.clear()
    return render_template('term.html', user=session.get('user'))

@MailHijackCSRF.route('/privacy.html')
def privacy_html():
    if not check_cookies():
        session.clear()
    return render_template('privacy.html', user=session.get('user'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        check_cookies()
        if 'user' not in session:  
            return redirect(url_for('login_html', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@MailHijackCSRF.route('/add-mail.html')
@login_required
def add_mail():
    if not check_cookies():
        session.clear()
    return render_template('addmail.html', user=session.get('user'))

@MailHijackCSRF.route('/confirm', methods=['POST'])
def confirm():
    username = request.form.get('username')
    password = request.form.get('password')
    code = request.form.get('confirmationcode')
    hash_password=hashlib.md5(password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT *FROM users WHERE username = ? or gmail = ? AND password=? AND code = ?", (username, username, hash_password, code))
    user = cursor.fetchone()
    
    if user:
        cursor.execute("UPDATE users SET active = 1 WHERE username = ? or gmail = ?", (username, username))
        conn.commit()
        conn.close()
        session['user'] = username
        
        user_uuid = user['uuid'] if 'uuid' in user else str(uuid.uuid4())

        jwt_token = pyjwt.encode({
            "username": username,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm="HS256")

        user_data[user_uuid] = jwt_token

        if 'uuid' not in user:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET uuid = ? WHERE username = ?", (user_uuid, username))
            conn.commit()
            conn.close()

        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie("uuid", user_uuid, httponly=True, samesite="None", secure=True)
        response.set_cookie("jwt_token", jwt_token, httponly=True, samesite="None", secure=True)
        return response
    
    conn.close()
    error_message = "Invalid code"
    return render_template('confirm.html', error=error_message, username=username, password=password)

@MailHijackCSRF.route('/check', methods=['POST'])
def check():
    session_code = request.form.get('sessioncode')
    session_code = session_code.split("?token=")
    token = session_code[1]
    for key, value in flag_data.items():
        if value == token:
            return render_template('success.html', user=session.get('user'))
        else:
            return render_template('check.html', error="wrong verification link")
    return render_template('check.html')

@MailHijackCSRF.route('/resend', methods=['POST'])
def resend():
    username = request.form.get('username')
    password = request.form.get('password')
    hash_password=hashlib.md5(password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT code FROM users WHERE username = ? or gmail = ? AND password = ?", (username, username, hash_password))
    code = cursor.fetchone()
    if code:
        username=username
        username = username.replace(" ", "")
        bdcontent = "<h2>Verify Your Account password</h2><p>your verification code are given below</p><div style=\"background-color: orange; color: black; font-size: 14px; padding: 10px; border-radius: 5px; font-family: Arial, sans-serif;\">"+code[0]+"</div><p>If you did not request this, please ignore this email.</p>"
        mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
        payload = {"email": username,
                    "sender":"IHA089 Labs ::: MailHijackCSRFLab",
                    "subject":"MailHijackCSRFLab::Verify Your Accout",
                    "bodycontent":bdcontent
                }
        try:
            k = requests.post(mail_server, json = payload, verify=False)
        except:
            return jsonify({"error": "Mail server is not responding"}), 500
        error_message="code sent"
    else:
        error_message="Invalid username or password"

    conn.close()
    return render_template('confirm.html', error=error_message, username=username, password=password)

@MailHijackCSRF.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        user_uuid = request.cookies.get("uuid")
        jwt_token = request.cookies.get("jwt_token")

        if user_uuid in user_data and jwt_token == user_data[user_uuid]:
            decoded = pyjwt.decode(jwt_token, JWT_SECRET, algorithms="HS256")
            session['user'] = decoded['username']
            return redirect(url_for('dashboard'))

        return render_template('login.html')

    username = request.form.get('username')
    password = request.form.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()
    hash_password = hashlib.md5(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE username = ? or gmail = ? AND password = ?", (username, username, hash_password))
    user = cursor.fetchone()
    conn.close()

    if user:
        if not user[5] == 1:
            return render_template('confirm.html', username=username, password=password)

        session['user'] = username
        user_uuid = user['uuid'] if 'uuid' in user else str(uuid.uuid4())

        jwt_token = pyjwt.encode({
            "username": username,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm="HS256")

        user_data[user_uuid] = jwt_token

        if 'uuid' not in user:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET uuid = ? WHERE username = ?", (user_uuid, username))
            conn.commit()
            conn.close()

        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie("uuid", user_uuid, httponly=True, samesite="None", secure=True) 
        response.set_cookie("jwt_token", jwt_token, httponly=True, samesite="None", secure=True)
        return response

    error_message = "Invalid username or password. Please try again."
    return render_template('login.html', error=error_message)

@MailHijackCSRF.route('/add-secondary-mail', methods=['POST'])
@login_required
def add_secondary_mail():
    if not check_cookies():
        sessioin.clear()

    secondary_email = request.form.get('secondary_email')
    
    user_uuid = request.cookies.get("uuid")
    origin = request.headers.get("Origin","")
    host = request.headers.get("Host", "")
    referer = request.headers.get("Referer", "")

    print("_----------------")
    print(origin)
    print(host)
    print(referer)

    if not secondary_email.endswith('@iha089.org'):
        error_msg = "only emails with @iha089.org domain are allowed"
        return render_template('addmail.html', error=error_msg)

    conn = get_db_connection()
    cursor = conn.cursor()
    username = session.get('user')
    cursor.execute("SELECT id FROM users WHERE username = ? OR gmail = ?", (username, username))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        error_msg = "User not found"
        return render_template('addmail.html', error=error_msg)

    cursor.execute("SELECT 1 FROM users WHERE gmail = ? OR username = ?", (secondary_email, secondary_email))
    if cursor.fetchone():
        conn.close()
        error_msg = "Email already used as primary"
        return render_template('addmail.html', error=error_msg)

    cursor.execute("SELECT 1 FROM secondary_emails WHERE email = ?", (secondary_email,))
    if cursor.fetchone():
        conn.close()
        error_msg = "Email already used as secondary"
        return render_template('addmail.html', error=error_msg)

    try:
        token = secrets.token_hex(32)

        cursor.execute("INSERT INTO secondary_emails (user_id, email, token) VALUES (?, ?, ?)", (user['id'], secondary_email, token))
        conn.commit()
        conn.close()

        if host not in origin:
            if host not in referer:
                if origin in referer:
                    if user_uuid not in flag_data:
                        flag_data[user_uuid] = token
                        print("token added in flag")

        username= secondary_email
        username = username.replace(" ", "")
        cmplt_url = "https://iha089-labs.in/verify-secondary-mail?token="+token
        bdcontent = "<h2>Verify Secondary Mail</h2><p>Click the button below to verify this mail as secondary mail on MailHijackCSRF Lab</p><a href=\""+cmplt_url+"\">Verify Your Account</a><p>If you did not request this, please ignore this email.</p>"
        mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
        payload = {"email": username,
                    "sender":"IHA089 Labs ::: MailHijackCSRFLab",
                    "subject":"MailHijackCSRFLab::Click bellow link to verify",
                    "bodycontent":bdcontent
                }
        try:
            k = requests.post(mail_server, json = payload, verify=False)
        except:
            return jsonify({"error": "Mail server is not responding"}), 500

        flash("Verification link sent")
        return redirect(url_for('profile'))
    except sqlite3.Error:
        conn.close()
        return render_template('addmail.html', error="Failed to add secondary email")

@MailHijackCSRF.route('/unlink-secondary-mail', methods=['POST'])
@login_required
def unlink_secondary_mail():
    conn = get_db_connection()
    cursor = conn.cursor()
    username = session.get('user')
    cursor.execute("SELECT id FROM users WHERE username = ? OR gmail = ?", (username, username))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return render_template('login.html')

    try:
        cursor.execute("DELETE FROM secondary_emails WHERE user_id = ?", (user['id'],))
        if cursor.rowcount == 0:
            conn.close()
            return render_template('profile.html', user=username)
        conn.commit()
        conn.close()
        return redirect(url_for('profile'))
    except sqlite3.Error:
        conn.close()
        return jsonify({"error": "Failed to unlink secondary email"}), 500

@MailHijackCSRF.route('/verify-secondary-mail', methods=['get'])
def verify_secondary_mail():
    token = request.args.get('token')
    if not token:
        flash("Token is missing.")
        return redirect(url_for('home'))
    query = "SELECT active from secondary_emails WHERE token = ?"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, (token,))
    result = cursor.fetchone()
    if result:
        if result[0] == 1:
            flash("Email Already verified")
            conn.close()
            return redirect(url_for('profile'))
        else:
            query = "UPDATE secondary_emails set active = 1 WHERE token = ?"
            cursor.execute(query, (token, ))
            conn.commit()
            conn.close()
            flash("Email verfication success")
            return redirect(url_for('profile'))
    else:
        flash("Invalid token. Please try again.")
        conn.close()
        return redirect(url_for('home'))

@MailHijackCSRF.route('/resetpassword', methods=['POST'])
def resetpassword():
    password=request.form.get('password')
    token = request.form.get('token')
    if not token or token == "11111111111111111111":
        flash("Token is missing.")
        return redirect(url_for('home'))
    query = "SELECT gmail FROM token_info where token = ?"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, (token,))
    result = cursor.fetchone()
    conn.close()
    if result:
        conn = get_db_connection()
        cursor = conn.cursor()
        hash_password = hashlib.md5(password.encode()).hexdigest()
        query = "UPDATE users SET password = ? WHERE gmail = ?"
        cursor.execute(query, (hash_password, result[0], ))
        conn.commit()
        conn.close()
        flash("Password updated successfully.")
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "UPDATE token_info SET token = 11111111111111111111 WHERE gmail = ?"
        cursor.execute(query, (result[0], ))
        conn.commit()
        conn.close()
        return redirect(url_for('login_html'))
    else:
        flash("Invalid token. Please try again.")
        return redirect(url_for('home'))
    
@MailHijackCSRF.route('/join', methods=['GET', 'POST'])
def join():
    if not check_cookies():
        session.clear()
    if 'user' in session:
        return render_template('dashboard.html', user=session.get('user'))

    email = request.form.get('email')
    username = request.form.get('username')
    password = request.form.get('password')
    if not email.endswith('@iha089.org'):
        error_message = "Only email with @iha089.org domain is allowed."
        return render_template('join.html', error=error_message)
    conn = get_db_connection()
    cursor = conn.cursor()
    hash_password = hashlib.md5(password.encode()).hexdigest()
    query = f"INSERT INTO users (gmail, username, password) VALUES ('{email}', '{username}', '{hash_password}')".format(email, username, password)
    cursor.execute("SELECT * FROM users where gmail = ?", (email,))
    if cursor.fetchone():
        error_message = "Email already taken. Please choose another."
        conn.close()
        return render_template('join.html', error=error_message)
    
    try:
        user_uuid = str(uuid.uuid4())
        code = generate_code()
        cursor.execute("INSERT INTO users (gmail, username, password, uuid, active, code) VALUES (?, ?, ?, ?, ?, ?)", (email, username, hash_password, user_uuid, '0', code))
        conn.commit()
        username=email
        username = username.replace(" ", "")
        bdcontent = "<h2>Verify Your Account password</h2><p>your verification code are given below</p><div style=\"background-color: orange; color: black; font-size: 14px; padding: 10px; border-radius: 5px; font-family: Arial, sans-serif;\">"+code+"</div><p>If you did not request this, please ignore this email.</p>"
        mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
        payload = {"email": username,
                    "sender":"IHA089 Labs ::: MailHijackCSRFLab",
                    "subject":"MailHijackCSRFLab::Verify Your Accout",
                    "bodycontent":bdcontent
                }
        try:
            k = requests.post(mail_server, json = payload, verify=False)
        except:
            return jsonify({"error": "Mail server is not responding"}), 500

        return render_template('confirm.html', username=email, password=password)
    except sqlite3.Error:
        error_message = "Something went wrong. Please try again later."
        return render_template('join.html', error=error_message)
    finally:
        conn.close()
    
@MailHijackCSRF.route('/reset', methods=['GET'])
def reset():
    token = request.args.get('token')
    if not token:
        flash("Token is missing.")
        return redirect(url_for('home'))
    query = "SELECT gmail FROM token_info where token = ?"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, (token,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return render_template('reset-password.html', token=token)
    else:
        flash("Invalid token. Please try again.")
        return redirect(url_for('home'))
    
@MailHijackCSRF.route('/forgot', methods=['POST'])
def forgot():
    try:
        data = request.get_json()
        
        if 'username' in data:
            uname = data['username']                

            conn = get_db_connection()
            cursor = conn.cursor()
            query = "SELECT 1 FROM users WHERE gmail = ?"
            cursor.execute(query, (uname,))
            result = cursor.fetchone()
            conn.close()
            if result is not None:
                token = secrets.token_hex(32)
                conn = get_db_connection()
                cursor = conn.cursor()
                query = "SELECT 1 FROM token_info WHERE gmail = ?"
                cursor.execute(query, (uname, ))
                result = cursor.fetchone()
                
                if result is not None:
                    current_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
                    query = "UPDATE token_info SET token = ?, timestamp = ? WHERE gmail = ?"
                    cursor.execute(query, (token, current_timestamp, uname, ))
                    conn.commit()
                else:
                    query = f"INSERT INTO token_info(gmail, token) VALUES ('{uname}', '{token}')".format(uname, token)
                    cursor.execute(query)
                    conn.commit()
                conn.close()
                username = uname.replace(" ","")
                cmplt_url = "https://iha089-labs.in/reset?token="+token
                bdcontent = "<h2>Reset Your Account password</h2><p>Click the button below to reset your account password on MailHijackCSRF Lab</p><a href=\""+cmplt_url+"\">Verify Your Account</a><p>If you did not request this, please ignore this email.</p>"
                mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
                payload = {"email": username,
                            "sender":"IHA089 Labs ::: MailHijackCSRFLab",
                            "subject":"MailHijackCSRFLab::Click bellow link to reset your password",
                            "bodycontent":bdcontent
                    }
                try:
                    k = requests.post(mail_server, json = payload, verify=False)
                except:
                    return jsonify({"error": "Mail server is not responding"}), 500  
            else:
                pass

            return jsonify({"message": "Reset link sent on your mail"}), 200
        else:
            return jsonify({"error": "Username is required"}), 400
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    
@MailHijackCSRF.route('/dashboard')
@MailHijackCSRF.route("/dashboard.html")
@login_required
def dashboard():
    if not check_cookies():
        session.clear()
    if 'user' not in session:
        return redirect(url_for('login_html'))
    return render_template('dashboard.html', user=session.get('user'))

@MailHijackCSRF.route('/logout.html')
def logout():
    session.clear() 
    response = make_response(redirect(url_for('login_html')))
    response.set_cookie("uuid", "", httponly=True, samesite="Strict") 
    response.set_cookie("jwt_token", "", httponly=True, samesite="Strict")
    return response

@MailHijackCSRF.route('/profile')
@MailHijackCSRF.route('/profile.html')
@login_required
def profile():
    if not check_cookies():
        session.clear()
    if 'user' not in session:
        return redirect(url_for('login_html'))

    username = session.get('user')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT email, active FROM secondary_emails WHERE user_id = (SELECT id FROM users WHERE username = ? OR gmail = ?)", (username, username))
    secondary_email = cursor.fetchone()
    conn.close()
    if secondary_email:
        if secondary_email[1] == 1:
            return render_template('profile.html', user=username, secondary_email=secondary_email[0])
        else:
            return render_template('profile.html', user=username, secondary_email=secondary_email[0]+" (Not verified)")
    else:
        return render_template('profile.html', user=username)

@MailHijackCSRF.route('/reset_password', methods=['POST'])
def reset_password():
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    token = request.form.get('token')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    expected_token = hashlib.md5(f"{user['id']}2024".encode()).hexdigest()
    if token == expected_token:
        hash_password = hashlib.md5(new_password.encode()).hexdigest()
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hash_password, user['id']))
        conn.commit()
        conn.close()
        return jsonify({"message": "Password updated successfully!"})
    
    conn.close()
    return jsonify({"error": "Invalid token"}), 400

@MailHijackCSRF.after_request
def add_cache_control_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

#MailHijackCSRF.run("127.0.0.1", 5000)
