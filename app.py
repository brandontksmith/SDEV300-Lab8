"""
app.py
"""

import os
import sys
import re
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, flash, session, request, redirect, url_for
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.secret_key = '3b1b8d13ba03a34d276ded705457112c682b4e6a'

TITLE = 'Performance Vehicles'
CREDENTIALS_FILE = os.path.join(sys.path[0] + "/" + '.credentials')
COMMON_PASSWORDS_FILE = os.path.join(sys.path[0] + "/" + "CommonPassword.txt")
AUTH_ERR_LOG = os.path.join(sys.path[0] + "/" + "auth.err.log")


def load_common_passwords():
    """
    Loads the common passwords from the common passwords file.
    :return: a list of common passwords
    """
    common_passwords = []

    file_pointer = open(COMMON_PASSWORDS_FILE, 'r')
    lines = file_pointer.readlines()

    for line in lines:
        secret = line.strip()
        common_passwords.append(secret)

    return common_passwords


def load_credentials():
    """
    Loads the credentials from the credentials file.
    :return: a list of credentials
    """
    credentials = []

    file_pointer = open(CREDENTIALS_FILE, 'r')
    lines = file_pointer.readlines()

    for line in lines:
        params = line.split(',')

        if len(params) == 0:
            continue

        credentials.append([params[0].strip(), params[1].strip()])

    return credentials


def add_login_failure(ip_address):
    """
    Writes a login failure to the Auth Error Log.
    :param ip_address: the ip address of the request
    """
    date_and_time = datetime.now()
    date_and_time = date_and_time.strftime("%m/%d/%Y %I:%M:%S %p")

    file_pointer = open(AUTH_ERR_LOG, 'a')
    file_pointer.write("[%s]: Failed login from %s\n" % (date_and_time, ip_address))
    file_pointer.close()


def add_credential(email, password):
    """
    Adds an email and password combination to the credentials file.
    :param email: the email address
    :param password: the text password
    """
    file_pointer = open(CREDENTIALS_FILE, 'a')
    file_pointer.write("%s,%s" % (email.lower(), sha256_crypt.hash(password)) + "\n")
    file_pointer.close()


def update_credential(email, new_password):
    """
    Updates the password for the given email address.
    :param email: the email address
    :param new_password: the new password
    :return: True or False
    """
    credentials = load_credentials()
    updated = False

    file_pointer = open(CREDENTIALS_FILE, 'w')

    for credential in credentials:
        if credential[0] == email.lower():
            credential[1] = new_password
            updated = True

        file_pointer.write("%s,%s" % (email.lower(), sha256_crypt.hash(credential[1])) + "\n")

    file_pointer.close()

    return updated


def get_credential(email):
    """
    Retrieves a credential by email address if one exists.
    :param email: the email address
    :return: a credential or None
    """
    credentials = load_credentials()

    for credential in credentials:
        if email.lower() == credential[0]:
            return credential

    return None


def authenticated(func):
    """
    A decorator to secure login-restricted routes.
    :param func: the function
    :return: the decorated function
    """
    @wraps(func)
    def decorated_function(*args, **kwargs):
        """
        Checks if the request is authenticated.
        :param args: arguments
        :param kwargs: keyword arguments
        :return: redirect or the original function
        """
        if session.get('email') is None:
            return redirect(url_for('login', next=request.url))
        return func(*args, **kwargs)
    return decorated_function


def get_current_datetime():
    """
    Returns a String of the current Date and Time.
    :return: string of the current Date and Time
    """
    date_time = datetime.now()
    date_time = date_time.strftime("%b %d, %Y %I:%M %p")
    return date_time


@app.route('/register', methods=['GET'])
def register():
    """
    Renders the Register Page.
    :return: the register template
    """
    return render_template(
        'register.html', active='register', title=TITLE, date=get_current_datetime()
    )


@app.route('/update-password', methods=['GET'])
def update_password():
    """
    Renders the Update Password Page.
    :return: the update password template
    """
    return render_template(
        'update-password.html', active='update_password', title=TITLE, date=get_current_datetime(),
        authed=True
    )


@app.route('/update-password', methods=['POST'])
def update_password_submit():
    """
    Handles the Update Password Form Submission.
    :return: update password template or redirect
    """
    password = request.form.get('password', None)
    confirm_password = request.form.get('confirmPassword', None)

    error = None

    if password is None or len(password) == 0:
        error = 'Please provide a Password.'
    elif password != confirm_password:
        error = 'Confirm Password does not match Password.'
    else:
        success, error = validate_password(password)

        if success is True:
            update_credential(session.get('email'), password)
            flash("Your password has been successfully updated.")

    return render_template(
        'update-password.html', active='update-password', title=TITLE, date=get_current_datetime(),
        error=error, password=password, confirm_password=confirm_password, authed=True
    )


def email_exists(email):
    """
    Checks if the given email address exists in the credentials file.
    :param email: the email address
    :return: True or False
    """
    credential = get_credential(email)
    return credential is not None


def check_for_common_passwords(password):
    """
    Checks the given password against common passwords.
    :param password: the password
    :return: True or False and the Common Password or None
    """
    common_passwords = load_common_passwords()

    for common_password in common_passwords:
        if common_password.lower() in password.lower():
            return True, common_password

    return False, None


def validate_password(password):
    """
    Validates that the password has at least 12 characters, at least 1 uppercase character,
    at least 1 lowercase character, at least 1 number, and at least 1 special character.
    :param password: the password to validate
    :return: a tuple containing the status and messages
    """
    has_upper = re.compile(r'[A-Z]+')
    has_lower = re.compile(r'[a-z]+')
    has_digit = re.compile(r'\d+')
    has_special = re.compile(r'\W+')

    valid = True
    message = None

    if len(password) < 12:
        message = 'Password must include at least 12 characters.'
    elif has_upper.search(password) is None:
        message = 'Password must include at least 1 uppercase character.'
    elif has_lower.search(password) is None:
        message = 'Password must include at least 1 lowercase character.'
    elif has_digit.search(password) is None:
        message = 'Password must include at least 1 number.'
    elif has_special.search(password) is None:
        message = 'Password must include at least 1 special character.'
    else:
        has_common_password, common_password = check_for_common_passwords(password)

        if has_common_password:
            message = 'Password cannot contain the secret %s.' % common_password

    if message is not None:
        valid = False

    return valid, message


@app.route('/register', methods=['POST'])
def register_submit():
    """
    Handles the Register Form Submission.
    :return: register template or redirect
    """
    email = request.form.get('email', None)
    password = request.form.get('password', None)

    error = None

    if email is None or len(email) == 0:
        error = 'Please provide an Email Address.'
    elif password is None or len(password) == 0:
        error = 'Please provide a Password.'
    elif email_exists(email):
        error = 'An account already exists for this Email..'
    else:
        success, error = validate_password(password)

        if success is True:
            flash("Thank you for registering. You may login below.")
            add_credential(email, password)
            return redirect(url_for('login'))

    return render_template(
        'register.html', active='register', title=TITLE, date=get_current_datetime(), error=error,
        email=email, password=password, authed=False
    )


@app.route('/login', methods=['GET'])
def login():
    """
    Renders the Login Page.
    :return: login template
    """
    return render_template(
        'login.html', active='login', title=TITLE, date=get_current_datetime(), authed=False
    )


@app.route('/login', methods=['POST'])
def login_submit():
    """
    Handles the Login Form Submission.
    :return: login template or redirect
    """
    email = request.form.get('email', None)
    password = request.form.get('password', None)

    error = None

    if email is None or len(email) == 0:
        error = 'Please provide an Email Address.'
    elif password is None or len(password) == 0:
        error = 'Please provide a Password.'
    else:
        credential = get_credential(email)

        if credential is None:
            error = 'Invalid Email Address.'
        elif not sha256_crypt.verify(password, credential[1]):
            error = 'Invalid Password.'
        else:
            session['email'] = email
            flash("Your login is successful! You may now browse the website.")
            return redirect(url_for('index'))

    if error is not None:
        add_login_failure(request.remote_addr)

    return render_template(
        'login.html', active='login', title=TITLE, date=get_current_datetime(), error=error,
        authed=False
    )


@app.route('/logout')
@authenticated
def logout():
    """
    Clears the Requester's Session and redirects to Login.
    :return: redirect to Login
    """
    session.clear()
    flash("Your session has been cleared. Thanks for visiting!")
    return redirect(url_for('login'))


@app.route('/')
@authenticated
def index():
    """
    Renders the Index/Home Page.
    :return: the rendered HTML Template
    """
    return render_template(
        'index.html', active='home', title=TITLE, date=get_current_datetime(), authed=True
    )


@app.route('/vehicles/x3-m-competition')
@authenticated
def x3_m_competition():
    """
    Renders the X3MC Vehicle Page.
    :return: the rendered HTML Template
    """
    return render_template(
        'x3-m-competition.html', active='x3_m_competition', title=TITLE,
        date=get_current_datetime(), subtitle='X3 M Competition', authed=True
    )


@app.route('/vehicles/c63-s-amg')
@authenticated
def c63_s_amg():
    """
    Renders the C63 S AMG Page.
    :return: the rendered HTML Template
    """
    return render_template(
        'c63-s-amg.html', title=TITLE, active='c63_s_amg', date=get_current_datetime(),
        subtitle='C63 S AMG', authed=True
    )


@app.route('/vehicles/corvette')
@authenticated
def corvette():
    """
    Renders the Corvette Page.
    :return: the rendered HTML Template
    """
    return render_template(
        'corvette.html', title=TITLE, active='corvette', date=get_current_datetime(),
        subtitle='Corvette', authed=True
    )


@app.route('/compare')
@authenticated
def compare():
    """
    Renders the Compare Page.
    :return: the rendered HTML Template
    """
    return render_template(
        'compare.html', title=TITLE, active='compare', date=get_current_datetime(),
        subtitle='Compare', authed=True
    )
