from flask import Flask, render_template, request, redirect, session, jsonify, send_from_directory
import random
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = "zkp_secret"

users_db = {}
login_sessions = {}

# ================= VAULT =================
UPLOAD_FOLDER = "uploads"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_user_folder(username):
    path = os.path.join(UPLOAD_FOLDER, username)
    if not os.path.exists(path):
        os.makedirs(path)
    return path

def get_user_files(username):
    return os.listdir(get_user_folder(username))


# ================= ZKP =================
p = 1019
g = 2

def password_to_secret(password):
    h = 0
    for ch in password:
        h = (h * 31 + ord(ch)) % (p - 1)
    return h

def get_ip():
    return request.remote_addr


@app.route("/")
def home():
    return redirect("/login")


# ================= REGISTER =================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if not username or not password:
            return render_template("register.html", error="Username and Password required")

        if username in users_db:
            return render_template("register.html", error="User already exists")

        secret = password_to_secret(password)
        public = pow(g, secret, p)

        users_db[username] = {
            "public": public,
            "devices": [get_ip()],
            "last_login": "-"
        }

        return render_template("register.html", success=True)

    return render_template("register.html")


# ================= LOGIN =================
@app.route("/login")
def login():
    return render_template("login.html")


# ================= ZKP STEP 1 =================
@app.route("/start_zkp", methods=["POST"])
def start_zkp():
    data = request.json
    username = data["username"]
    commitment = int(data["commitment"])

    if username not in users_db:
        return jsonify({"error": "User not found"}), 400

    challenge = random.randint(1, 10)

    login_sessions[username] = {
        "commitment": commitment,
        "challenge": challenge
    }

    return jsonify({"challenge": challenge})


# ================= ZKP VERIFY =================
@app.route("/verify_zkp", methods=["POST"])
def verify_zkp():
    data = request.json
    username = data["username"]
    response = int(data["response"])

    if username not in users_db or username not in login_sessions:
        return jsonify({"error": "Session error"}), 400

    public = users_db[username]["public"]
    commitment = login_sessions[username]["commitment"]
    challenge = login_sessions[username]["challenge"]

    left = pow(g, response, p)
    right = (commitment * pow(public, challenge, p)) % p

    if left == right:
        current_ip = get_ip()

        if current_ip not in users_db[username]["devices"]:
            return jsonify({"error": "Access Denied: Untrusted Device"}), 403

        session["user"] = username
        session["ip"] = current_ip

        users_db[username]["last_login"] = datetime.now().strftime("%d-%m-%Y %H:%M")

        session["zkp"] = {
            "commitment": commitment,
            "challenge": challenge,
            "response": response,
            "left": left,
            "right": right
        }

        return jsonify({"success": True})

    return jsonify({"error": "Authentication Failed (Invalid Password)"}), 400


# ================= DASHBOARD =================
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" not in session or session["user"] not in users_db:
        session.clear()
        return redirect("/login")

    username = session["user"]
    current_ip = get_ip()

    if request.method == "POST":
        new_ip = request.form.get("new_ip")
        if new_ip and new_ip not in users_db[username]["devices"]:
            users_db[username]["devices"].append(new_ip)

    devices = users_db[username]["devices"]
    status = "Trusted Device" if current_ip in devices else "New Device"

    return render_template(
        "dashboard.html",
        user=username,
        ip=current_ip,
        devices=devices,
        device_count=len(devices),
        status=status,
        last_login=users_db[username]["last_login"],
        zkp=session.get("zkp")
    )


@app.route("/delete_device/<ip>")
def delete_device(ip):
    username = session["user"]

    if ip in users_db[username]["devices"]:
        users_db[username]["devices"].remove(ip)

    return redirect("/dashboard")


# ================= VAULT =================
@app.route("/vault")
def vault():
    if "user" not in session:
        return redirect("/login")

    return render_template("vault.html", files=get_user_files(session["user"]))


@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return redirect("/login")

    file = request.files.get("file")

    if file:
        file.save(os.path.join(get_user_folder(session["user"]), file.filename))

    return redirect("/vault")


@app.route("/view/<filename>")
def view(filename):
    if "user" not in session:
        return redirect("/login")

    return send_from_directory(get_user_folder(session["user"]), filename)


@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        return redirect("/login")

    return send_from_directory(get_user_folder(session["user"]), filename, as_attachment=True)


@app.route("/delete/<filename>")
def delete(filename):
    if "user" not in session:
        return redirect("/login")

    path = os.path.join(get_user_folder(session["user"]), filename)
    if os.path.exists(path):
        os.remove(path)

    return redirect("/vault")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)