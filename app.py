from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, make_response
from flask_mail import Mail, Message
import mysql.connector
import config
import random
import bcrypt
import os
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature  # <-- added BadSignature
import razorpay
import traceback
from utils.pdf_generator import generate_pdf

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# serializer for password reset tokens
s = URLSafeTimedSerializer(app.secret_key)

# -------------------- MAIL CONFIG --------------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)


# -------------------- DB CONNECTION --------------------
def get_db_connection():
    return mysql.connector.connect(
        host=config.DB_HOST,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME
    )


# =================================================================
# HOME
# =================================================================
@app.route('/')
def Index_Page():
    return redirect("user-login")


# =================================================================
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# =================================================================
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    name = request.form['name']
    email = request.form['email']

    MyDB = get_db_connection()
    cursor = MyDB.cursor(dictionary=True)
    cursor.execute("SELECT admin_id FROM admin WHERE email=%s", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    MyDB.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    # Store info in session until OTP is verified
    session['signup_name'] = name
    session['signup_email'] = email

    otp = random.randint(100000, 999999)
    session['admin_otp'] = otp

    msg = Message(
        subject="SMARTcart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )

    msg.body = f"Your OTP for SMartCart Admin Registration is {otp}"
    mail.send(msg)

    flash("OTP sent to your email!..", "success")
    return redirect('/verify-otp')


# =================================================================
# ROUTE 2: DISPLAY ADMIN OTP PAGE
# =================================================================
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    if 'admin_otp' not in session or 'signup_email' not in session:
        flash("Please complete signup first.", "danger")
        return redirect('/admin-signup')

    return render_template("admin/verify_otp.html")


# =================================================================
# ROUTE 3: VERIFY ADMIN OTP + SAVE ADMIN
# =================================================================
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():

    user_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('admin_otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    MyDB = get_db_connection()
    cursor = MyDB.cursor()
    cursor.execute(
        "INSERT INTO admin(name, email, password) VALUES(%s, %s, %s)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    MyDB.commit()
    cursor.close()
    MyDB.close()

    session.pop('admin_otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!...", "success")
    return redirect('/admin-login')


# =================================================================
# ROUTE 4: ADMIN LOGIN
# =================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    stored_hashed_password = admin['password']

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')


# =================================================================
# FORGOT PASSWORD PAGE (ADMIN)
# =================================================================
@app.route('/forgot_password')
def forgot_password():
    return render_template("admin/forgot_password.html")


# =================================================================
# SEND RESET LINK (ADMIN)
# =================================================================
@app.route('/send_reset_link', methods=['POST'])
def send_reset_link():
    email = request.form['email'].strip().lower()

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM admin WHERE email=%s", (email,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if not user:
        flash("Email not registered!", "danger")
        return redirect('/forgot_password')

    token = s.dumps(email, salt='password-reset-salt')
    link = url_for('reset_password', token=token, _external=True)

    msg = Message(
        "SmartCart Password Reset",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    msg.body = f"Click the link to reset your password:\n\n{link}\n\nValid for 10 minutes."

    mail.send(msg)

    flash("Reset link sent to your email!", "success")
    return redirect('/admin-login')


# =================================================================
# RESET PASSWORD PAGE (ADMIN)
# =================================================================
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=600)
    except (SignatureExpired, BadSignature):
        flash("Invalid or expired reset link! Please request a new one.", "danger")
        return redirect('/forgot_password')

    if request.method == 'POST':
        new_password = request.form['password'].strip()
        confirm = request.form['confirm_password'].strip()

        if not new_password or not confirm:
            flash("Both fields are required.", "danger")
            return redirect(url_for('reset_password', token=token))

        if new_password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_password', token=token))

        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE admin SET password=%s WHERE email=%s", (hashed_pw, email))
        conn.commit()
        cur.close()
        conn.close()

        flash("Password reset successful! Please login.", "success")
        return redirect('/admin-login')

    return render_template("admin/reset_password.html", token=token)


# =================================================================
# ROUTE 5: ADMIN DASHBOARD
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    return render_template("admin/dashboard.html", admin_name=session['admin_name'])


# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')


# ------------------- IMAGE UPLOAD PATH -------------------
UPLOAD_FOLDER = 'static/uploads/product_images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ------------------- ADMIN PROFILE IMAGE PATH -------------------
ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ADMIN_UPLOAD_FOLDER, exist_ok=True)


# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")


# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image_file.save(image_path)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO products (name, description, category, price, image) VALUES (%s, %s, %s, %s, %s)",
        (name, description, category, price, filename)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')


# =================================================================
# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# =================================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )


# =================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)


# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    MyDB = get_db_connection()
    cursor = MyDB.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    cursor.close()
    MyDB.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)


# =================================================================
# ROUTE 12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    new_image = request.files['image']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    if new_image and new_image.filename != "":
        new_filename = secure_filename(new_image.filename)
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    cursor.execute("""
        UPDATE products
        SET name=%s, description=%s, category=%s, price=%s, image=%s
        WHERE product_id=%s
    """, (name, description, category, price, final_image_name, item_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')


# =================================================================
# ROUTE 13: DELETE PRODUCT
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT image FROM products WHERE product_id=%s", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
    if os.path.exists(image_path):
        os.remove(image_path)

    cursor.execute("DELETE FROM products WHERE product_id=%s", (item_id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')


# =================================================================
# ROUTE 14: ADMIN PROFILE (VIEW)
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if not admin:
        flash("Admin not found!", "danger")
        return redirect('/admin-login')

    return render_template("admin/admin_profile.html", admin=admin)


# =================================================================
# ROUTE 14B: ADMIN PROFILE EDIT PAGE
# =================================================================
@app.route('/admin/profile/edit', methods=['GET'])
def admin_profile_edit():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if not admin:
        flash("Admin not found!", "danger")
        return redirect('/admin-login')

    return render_template("admin/admin_profile_edit.html", admin=admin)


# =================================================================
# ROUTE 15: UPDATE ADMIN PROFILE
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    new_password = request.form.get('password', '').strip()

    photo_action = request.form.get('photo_action', 'keep')
    new_image = request.files.get('profile_image')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    if not admin:
        cursor.close()
        conn.close()
        flash("Admin not found!", "danger")
        return redirect('/admin-login')

    old_image_name = admin.get('profile_image')
    old_password = admin['password']

    if new_password:
        hashed_password = bcrypt.hashpw(
            new_password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')
    else:
        hashed_password = old_password

    final_image_name = old_image_name

    if photo_action == 'update' and new_image and new_image.filename:
        new_filename = secure_filename(new_image.filename)
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        if old_image_name:
            old_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_path):
                os.remove(old_path)

        final_image_name = new_filename

    elif photo_action == 'delete':
        if old_image_name:
            old_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_path):
                os.remove(old_path)
        final_image_name = None

    cursor.execute("""
        UPDATE admin
        SET name=%s, email=%s, password=%s, profile_image=%s
        WHERE admin_id=%s
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    session['admin_name'] = name
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')


# =================================================================
# ROUTE 16: USER REGISTRATION + OTP
# =================================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form.get('password')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        conn.close()
        flash("Email already registered! Please login.", "danger")
        return redirect('/user-register')

    cursor.close()
    conn.close()

    session['regt_name'] = name
    session['regt_email'] = email

    otp = random.randint(100000, 999999)
    session['user_otp'] = otp

    msg = Message(
        subject="SMARTcart Registration OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )

    msg.body = f"Your OTP for SMartCart Registration is {otp}"
    mail.send(msg)

    flash("OTP sent to your email!..", "success")
    return redirect('/otp-verification')


# =================================================================
# ROUTE 17: USER OTP PAGE
# =================================================================
@app.route('/otp-verification', methods=['GET'])
def user_otp_verify_get():

    if 'user_otp' not in session or 'regt_email' not in session:
        flash("Please start registration first.", "danger")
        return redirect('/user-register')

    return render_template("user/user_otp_verify.html")


# =================================================================
# ROUTE 18: VERIFY USER OTP + SAVE USER
# =================================================================
@app.route('/otp-verification', methods=['POST'])
def user_otp_verify_post():

    user_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('user_otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/otp-verification')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    MyDB = get_db_connection()
    cursor = MyDB.cursor()
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES(%s, %s, %s)",
        (session['regt_name'], session['regt_email'], hashed_password)
    )
    MyDB.commit()
    cursor.close()
    MyDB.close()

    session.pop('user_otp', None)
    session.pop('regt_name', None)
    session.pop('regt_email', None)

    flash("User registered successfully! Please login.", "success")
    return redirect('/user-login')


# =================================================================
# ROUTE 19: USER LOGIN
# =================================================================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    stored_hashed_password = user['password']

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')


# =================================================================
# USER FORGOT PASSWORD
# =================================================================
@app.route('/user-forgot-password', methods=['GET'])
def user_forgot_password():
    return render_template("user/user_forgot_password.html")


# =================================================================
# USER SEND RESET LINK
# =================================================================
@app.route('/user-send-reset-link', methods=['POST'])
def user_send_reset_link():
    email = request.form['email'].strip().lower()

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if not user:
        flash("Email not registered!", "danger")
        return redirect('/user-forgot-password')

    token = s.dumps(email, salt='user-password-reset')
    link = url_for('user_reset_password', token=token, _external=True)

    msg = Message(
        "SmartCart User Password Reset",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    msg.body = f"Click the link to reset your password:\n\n{link}\n\nValid for 10 minutes."

    mail.send(msg)

    flash("Reset link sent to your email!", "success")
    return redirect('/user-login')


# =================================================================
# USER RESET PASSWORD
# =================================================================
@app.route('/user-reset-password/<token>', methods=['GET', 'POST'])
def user_reset_password(token):
    try:
        email = s.loads(token, salt='user-password-reset', max_age=600)
    except (SignatureExpired, BadSignature):
        flash("Invalid or expired reset link! Please request a new one.", "danger")
        return redirect('/user-forgot-password')

    if request.method == 'POST':
        new_pw = request.form['password'].strip()
        confirm = request.form['confirm_password'].strip()

        if not new_pw or not confirm:
            flash("All fields are required.", "danger")
            return redirect(url_for('user_reset_password', token=token))

        if new_pw != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('user_reset_password', token=token))

        hashed_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_pw, email))
        conn.commit()
        cur.close()
        conn.close()

        flash("Password reset successful! Please login.", "success")
        return redirect('/user-login')

    return render_template("user/user_reset_password.html", token=token)


# =================================================================
# ROUTE 20: USER DASHBOARD
# =================================================================
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    return render_template("user/user_home.html", user_name=session['user_name'])


# =================================================================
# ROUTE 21: USER LOGOUT
# =================================================================
@app.route('/user-logout')
def user_logout():

    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)
    flash("Logged out successfully!", "success")
    return redirect('/user-login')


# =================================================================
# ROUTE 22: USER PRODUCT LISTING
# =================================================================
@app.route('/user/products')
def user_products():

    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )


# =================================================================
# ROUTE 23: USER PRODUCT DETAILS PAGE
# =================================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)


# =================================================================
#  USER PROFILE IMAGE PATH
# =================================================================
USER_UPLOAD_FOLDER = 'static/uploads/user_profiles'
app.config['USER_UPLOAD_FOLDER'] = USER_UPLOAD_FOLDER
os.makedirs(USER_UPLOAD_FOLDER, exist_ok=True)


# =================================================================
# ROUTE: USER PROFILE (VIEW)
# =================================================================
@app.route('/user/profile', methods=['GET'])
def user_profile():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("User not found!", "danger")
        return redirect('/user-login')

    return render_template("user/user_profile.html", user=user)


# =================================================================
# ROUTE: USER PROFILE EDIT PAGE
# =================================================================
@app.route('/user/profile/edit', methods=['GET'])
def user_profile_edit():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("User not found!", "danger")
        return redirect('/user-login')

    return render_template("user/user_profile_edit.html", user=user)


# =================================================================
# ROUTE: UPDATE USER PROFILE
# =================================================================
@app.route('/user/profile', methods=['POST'])
def user_profile_update():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()

    # Password-related fields from the form
    old_password_input = request.form.get('old_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    photo_action = request.form.get('photo_action', 'keep')
    new_image = request.files.get('profile_image')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        flash("User not found!", "danger")
        return redirect('/user-login')

    old_image_name = user.get('profile_image')
    old_password_db = user['password']  # hashed password stored in DB

    # Default: keep existing password
    hashed_password = old_password_db

    # =========================================================
    # PASSWORD RESET LOGIC
    # =========================================================
    # If any of the password fields are filled, treat as password change attempt
    if old_password_input or new_password or confirm_password:

        # Ensure all fields are provided
        if not old_password_input or not new_password or not confirm_password:
            flash("Please fill all password fields to reset your password.", "danger")
            cursor.close()
            conn.close()
            return redirect('/user/profile/edit')

        # Check old password correctness
        try:
            is_correct = bcrypt.checkpw(
                old_password_input.encode('utf-8'),
                old_password_db.encode('utf-8')
            )
        except Exception:
            # In case encoding or stored value has issues
            flash("Something went wrong while checking your old password.", "danger")
            cursor.close()
            conn.close()
            return redirect('/user/profile/edit')

        if not is_correct:
            flash("Old password is incorrect!", "danger")
            cursor.close()
            conn.close()
            return redirect('/user/profile/edit')

        # Match new + confirm
        if new_password != confirm_password:
            flash("New password and Confirm New Password do not match!", "danger")
            cursor.close()
            conn.close()
            return redirect('/user/profile/edit')

        # All good – hash new password
        hashed_password = bcrypt.hashpw(
            new_password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

    # =========================================================
    # PROFILE PHOTO LOGIC
    # =========================================================
    final_image_name = old_image_name

    if photo_action == 'update' and new_image and new_image.filename:
        new_filename = secure_filename(new_image.filename)
        image_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old file if exists
        if old_image_name:
            old_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_path):
                os.remove(old_path)

        final_image_name = new_filename

    elif photo_action == 'delete':
        if old_image_name:
            old_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_path):
                os.remove(old_path)
        final_image_name = None

    # =========================================================
    # UPDATE USER RECORD
    # =========================================================
    cursor.execute("""
        UPDATE users
        SET name=%s, email=%s, password=%s, profile_image=%s
        WHERE user_id=%s
    """, (name, email, hashed_password, final_image_name, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session info
    session['user_name'] = name
    session['user_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/user/profile')


# =================================================================
# ADD ITEM TO CART
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer or url_for('user_products'))

    pid = str(product_id)

    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart

    flash("Item added to cart!", "success")
    return redirect(request.referrer or url_for('user_products'))


# =================================================================
# VIEW CART PAGE
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)


# =================================================================
# INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart

    from_page = request.args.get("from")
    if from_page == "pay":
        return redirect('/user/pay')
    else:
        return redirect('/user/cart')


# =================================================================
# DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart

    from_page = request.args.get("from")
    if from_page == "pay":
        return redirect('/user/pay')
    else:
        return redirect('/user/cart')


# =================================================================
# REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart

    flash("Item removed!", "success")
    return redirect('/user/cart')


# =================================================================
# DELIVERY ADDRESS (SESSION-BASED)
# =================================================================
@app.route('/user/address', methods=['GET', 'POST'])
def user_address():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    next_page = request.args.get('next')
    address = session.get('delivery_address', {})

    if request.method == 'POST':
        address = {
            'phone': request.form.get('phone', '').strip(),
            'address_line1': request.form.get('address_line1', '').strip(),
            'address_line2': request.form.get('address_line2', '').strip(),  # required now
            'city': request.form.get('city', '').strip(),
            'state': request.form.get('state', '').strip(),
            'pincode': request.form.get('pincode', '').strip()
        }

        if (not address['phone'] or not address['address_line1'] or not address['address_line2']
                or not address['city'] or not address['state'] or not address['pincode']):
            flash("Please fill all required address fields.", "danger")
            return redirect(url_for('user_address', next=next_page))

        session['delivery_address'] = address
        flash("Address saved successfully!", "success")

        if next_page == 'pay':
            return redirect('/user/pay')

        return redirect('/user-dashboard')

    return render_template("user/user_address.html", address=address, next_page=next_page)


# RAZORPAY LINKING
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)


# =================================================================
# ROUTE: CREATE RAZORPAY ORDER
# =================================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})
    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    # Require delivery address in session
    address = session.get('delivery_address')
    if not address or not address.get('address_line1'):
        flash("Please add your delivery address.", "warning")
        return redirect('/user/address?next=pay')

    # ✅ Calculate total properly (assuming price is in RUPEES in DB)
    try:
        total_amount = sum(
            float(item['price']) * int(item['quantity'])
            for item in cart.values()
        )
    except Exception as e:
        app.logger.error("Error calculating total amount: %s", e)
        flash("Something went wrong while calculating the total.", "danger")
        return redirect('/user/cart')

    total_amount = round(total_amount, 2)   # ✅ avoid float issues

    # ✅ Razorpay needs amount in paise (integer)
    razorpay_amount = int(total_amount * 100)

    # 🔍 Debug log – check your terminal
    app.logger.info(f"[RZP] total_amount = ₹{total_amount}, razorpay_amount = {razorpay_amount} paise")

    # 🚫 Safety checks
    if razorpay_amount <= 0:
        flash("Invalid payable amount. Please check your cart.", "danger")
        return redirect('/user/cart')

    # Guard against absurdly high values (example cap = ₹5,00,000)
    if razorpay_amount > 50000000:   # 50,000,000 paise = ₹5,00,000
        app.logger.error(f"[RZP] Amount too high: {razorpay_amount} paise (₹{total_amount})")
        flash("Order amount is too high. Please check product prices in your cart.", "danger")
        return redirect('/user/cart')

    # ✅ Create Razorpay order safely
    try:
        razorpay_order = razorpay_client.order.create({
            "amount": razorpay_amount,
            "currency": "INR",
            "payment_capture": 1
        })
    except razorpay.errors.BadRequestError as e:
        # If Razorpay still complains, log what exactly it said
        app.logger.error(f"Razorpay BadRequestError while creating order: {e}")
        flash("Payment gateway rejected the amount. Please check your cart item prices.", "danger")
        return redirect('/user/cart')

    # ✅ Store full order details for validation later
    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        razorpay_amount=razorpay_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id'],
        cart=cart,
        address=address
    )



# =================================================================
# TEMP SUCCESS PAGE (currently not used in main verified flow,
# kept for compatibility if you ever redirect here)
# =================================================================
@app.route('/payment-success')
def payment_success():
    # Accept both your custom names AND Razorpay's default names
    payment_id = (
        request.args.get('payment_id')
        or request.args.get('razorpay_payment_id')
    )
    order_id = (
        request.args.get('order_id')
        or request.args.get('razorpay_order_id')
    )

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    cart = session.get('cart', {})
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id,
        cart=cart,
        grand_total=grand_total
    )


# =================================================================
# PAYMENT FAIL PAGE
# =================================================================
@app.route('/payment-failed')
def payment_failed():
    error_message = request.args.get("error", "Transaction could not be completed.")
    return render_template("user/payment_failure.html", error_message=error_message)


# =================================================================
# Route: Verify Payment and Store Order
# =================================================================
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    # Read values posted from frontend
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    # Build verification payload required by Razorpay client.utility
    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        # This will raise an error if signature invalid
        razorpay_client.utility.verify_payment_signature(payload)

    except Exception as e:
        # Verification failed
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    # Signature verified — now store order and items into DB
    user_id = session['user_id']
    cart = session.get('cart', {})

    if not cart:
        flash("Cart is empty. Cannot create order.", "danger")
        return redirect('/user/products')

    # Calculate total amount (ensure same as earlier)
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    # DB insert: orders and order_items
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insert into orders table
        cursor.execute("""
            INSERT INTO orders (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, razorpay_order_id, razorpay_payment_id, total_amount, 'paid'))

        order_db_id = cursor.lastrowid  # newly created order's primary key

        # Insert all items
        for pid_str, item in cart.items():
            product_id = int(pid_str)
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (%s, %s, %s, %s, %s)
            """, (order_db_id, product_id, item['name'], item['quantity'], item['price']))

        # Commit transaction
        conn.commit()

        # Clear cart and temporary razorpay order id
        session.pop('cart', None)
        session.pop('razorpay_order_id', None)

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        # Rollback and log error
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()


# =================================================================
# ✅ Route: Order Success Page
# =================================================================
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=%s AND user_id=%s", (order_db_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template("user/order_success.html", order=order, items=items)


# =================================================================
# 🧾 My Orders Page (List user's orders)
# =================================================================
@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Order by order_id DESC (safer than assuming created_at exists)
    cursor.execute("SELECT * FROM orders WHERE user_id=%s ORDER BY order_id DESC", (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)


# ----------------------------
# GENERATE INVOICE PDF
# ----------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # fetch order & items
    cursor.execute("SELECT * FROM orders WHERE order_id=%s AND user_id=%s",
                   (order_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_id,))
    items = cursor.fetchall()

    # fetch user using correct column name: user_id
    cursor.execute(
        "SELECT user_id AS user_pk, name, email FROM users WHERE user_id = %s",
        (session['user_id'],)
    )
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Prefer session address, else try order fields (if you stored them)
    address = session.get('delivery_address') or {
        k: order.get(k) for k in ('address_line1', 'address_line2', 'city', 'state', 'pincode', 'phone')
    }

    html = render_template("user/invoice.html", order=order, items=items, user=user, address=address)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    try:
        content = pdf.getvalue()
    except AttributeError:
        content = pdf

    response = make_response(content)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response



# =================================================================
# MAIN
# =================================================================
if __name__ == '__main__':
    app.run(debug=True)
