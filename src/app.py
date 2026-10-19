import os
import re
import secrets

import mysql.connector
from flask import Flask, jsonify, render_template, request, session
from mysql.connector import errorcode
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
)

PASSWORD_HASH_METHOD = "pbkdf2:sha256:1000000"
EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
# Проверяем хэш даже для неизвестного email, чтобы не выдавать наличие аккаунта
# существенной разницей во времени ответа.
DUMMY_PASSWORD_HASH = generate_password_hash(
    secrets.token_urlsafe(32), method=PASSWORD_HASH_METHOD, salt_length=16
)


def connect():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "185.114.247.43"),
        port=int(os.environ.get("DB_PORT", "3306")),
        user=os.environ.get("DB_USER", "sch688_vvedenie"),
        password=os.environ.get("DB_PASSWORD", "Qwerty123"),
        database=os.environ.get("DB_NAME", "pap_main"),
        connection_timeout=5,
    )


@app.route("/user_register", methods=["POST"])
def user_register():
    req = request.get_json(silent=True)
    if not isinstance(req, dict):
        return jsonify(error="Ожидается JSON с данными регистрации."), 400

    full_name = req.get("name")
    email = req.get("email")
    phone = req.get("phone")
    password = req.get("password")

    if not isinstance(full_name, str) or not 2 <= len(full_name.strip()) <= 255:
        return jsonify(error="Имя должно содержать от 2 до 255 символов."), 400
    if (
        not isinstance(email, str)
        or len(email.strip()) > 255
        or not EMAIL_PATTERN.fullmatch(email.strip())
    ):
        return jsonify(error="Укажите корректный email."), 400
    if phone is not None and (not isinstance(phone, str) or len(phone) > 50):
        return jsonify(error="Укажите корректный номер телефона."), 400
    if not isinstance(password, str) or not 8 <= len(password) <= 1024:
        return jsonify(error="Пароль должен содержать от 8 до 1024 символов."), 400

    # Пароль не обрезаем и не сохраняем: в БД передаётся только солёный хэш.
    hashed_password = generate_password_hash(
        password, method=PASSWORD_HASH_METHOD, salt_length=16
    )
    try:
        with connect() as cnx, cnx.cursor() as cur:
            cur.execute(
                """INSERT INTO users (full_name, email, phone, password_hash)
                   VALUES (%s, %s, %s, %s)""",
                (
                    full_name.strip(),
                    email.strip().lower(),
                    phone.strip() if phone else None,
                    hashed_password,
                ),
            )
            cnx.commit()
    except mysql.connector.Error as exc:
        if exc.errno == errorcode.ER_DUP_ENTRY:
            return jsonify(error="Этот email уже зарегистрирован."), 409
        app.logger.error("Ошибка MySQL при регистрации (код %s)", exc.errno)
        return jsonify(error="Не удалось зарегистрироваться. Попробуйте позже."), 503

    return jsonify(message="Регистрация успешно завершена."), 201


@app.route("/user_login", methods=["POST"])
def user_login():
    req = request.get_json(silent=True)
    if not isinstance(req, dict):
        return jsonify(error="Ожидается JSON с данными для входа."), 400

    email = req.get("email")
    password = req.get("password")
    if (
        not isinstance(email, str)
        or len(email.strip()) > 255
        or not EMAIL_PATTERN.fullmatch(email.strip())
        or not isinstance(password, str)
        or not 1 <= len(password) <= 1024
    ):
        return jsonify(error="Укажите email и пароль."), 400

    try:
        with connect() as cnx, cnx.cursor(dictionary=True) as cur:
            cur.execute(
                "SELECT id, password_hash FROM users WHERE email = %s",
                (email.strip().lower(),),
            )
            user = cur.fetchone()
    except mysql.connector.Error as exc:
        app.logger.error("Ошибка MySQL при входе (код %s)", exc.errno)
        return jsonify(error="Не удалось выполнить вход. Попробуйте позже."), 503

    stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
    try:
        password_matches = check_password_hash(stored_hash, password)
    except ValueError:
        # Повреждённые или неподдерживаемые хэши не дают доступ к аккаунту.
        password_matches = False
    if not user or not password_matches:
        return jsonify(error="Неверный email или пароль."), 401

    session.clear()
    session["user_id"] = user["id"]
    return jsonify(message="Вход выполнен."), 200


@app.route("/")
def registration():
    return render_template("registration.html")


@app.route("/login")
def login():
    return render_template("login.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
