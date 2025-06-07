from flask import *
from flask_login import LoginManager, UserMixin, login_required, logout_user, login_user, current_user
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
login_manager = LoginManager()
login_manager.init_app(app)

db = sqlite3.connect("users.db")
cursor = db.cursor()
ids = cursor.execute("SELECT * FROM id_table")
TARGETTED_USER_ID = 0
for id in ids:
    TARGETTED_USER_ID = id[0]
    break

class User(UserMixin):
    def __init__(self, id, email, password, name):
        self.id = id
        self.email = email
        self.password = password
        self.name = name

@login_manager.user_loader
def load_user(user_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    all_users = cursor.execute("SELECT * FROM user")

    for user in all_users:
        if user[0] == int(user_id):
            return User(user[0], user[1], user[2], user[3])

    return None

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    entered_email = request.form["email"]
    entered_password = request.form["password"]
    entered_name = request.form["name"]

    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM user WHERE email = ?", [entered_email])

    counter = 0

    for u in user:
        counter += 1

    if counter != 0:
        flash("Email already exists!", 'danger')
    else:
        cursor.execute("INSERT INTO user (email, password, name) VALUES (?, ?, ?)",
                       [entered_email, generate_password_hash(entered_password, "pbkdf2:sha256",
                                                              8), entered_name])
        db.commit()
        the_user = cursor.execute("SELECT * FROM user WHERE email = ?", [entered_email])
        user_id = None

        for u in the_user:
            user_id = u[0]

        login_user(load_user(user_id))
        global TARGETTED_USER_ID
        TARGETTED_USER_ID = user_id
        cursor.execute("UPDATE id_table SET id = ?", [TARGETTED_USER_ID])
        db.commit()
        flash("Successfully registered!", 'success')
        return redirect("/secrets")

    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    entered_email = request.form["email"]
    entered_password = request.form["password"]

    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM user WHERE email = ?", [entered_email])

    counter = 0
    targetted_user = None

    for u in user:
        counter += 1
        targetted_user = u

    if counter == 0:
        flash("Invalid email!", "danger")
    else:
        if targetted_user[1] == entered_email and check_password_hash(targetted_user[2], entered_password):
            global TARGETTED_USER_ID
            TARGETTED_USER_ID = targetted_user[0]
            cursor.execute("UPDATE id_table SET id = ?", [TARGETTED_USER_ID])
            db.commit()
            login_user(load_user(targetted_user[0]))
            flash("Successfully logged in.", 'success')
            return redirect("/secrets")
        else:
            flash("Invalid password.", 'danger')

    return render_template("login.html")


@app.route('/secrets', methods=["GET"])
@login_required
def secrets():
    global TARGETTED_USER_ID
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    users = cursor.execute("SELECT * FROM user WHERE id = ?", [TARGETTED_USER_ID])
    name = None
    for user in users:
        name = user[3]
    return render_template("secrets.html", name=name, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")

@app.route('/download')
@login_required
def download():
    return send_file("C:\\Users\\anton\\PycharmProjects\\Authentication With Flask\\com\\antoniossaliba\\static\\files\\cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)

