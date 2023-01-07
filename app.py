import hashlib
import json
import os
import secrets

from flask import Flask, render_template, request, redirect, url_for, session
from fuzzywuzzy import fuzz

SECRET_KEY = secrets.token_hex(16)
print(SECRET_KEY)

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY') or SECRET_KEY


def get_all_students():
    # Read students from JSON file
    with open('students.json') as f:
        students = json.load(f)
    return students


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/admin')
def admin():
    #  check if logged in
    if not session.get('logged_in'):
        return redirect('/')
    students = get_all_students()
    return render_template('admin.html', students=students)


@app.route('/teacher')
def teacher():
    #  check if logged in
    if not session.get('logged_in'):
        return redirect('/')
    all_students = get_all_students()
    return render_template("teacher.html", students=all_students, selected_class="all")


@app.route('/menu')
def menu():
    #  check if logged in
    if not session.get('logged_in'):
        return redirect('/')
    return render_template("menu.html")


@app.post('/login')
def login_post():
    # read login data from JSON file
    with open('teachers.json') as f:
        login = json.load(f)
    # read login data from form
    username = request.form.get("username")
    password = request.form.get("password")
    # store login data in session

    # Hash password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # check if login data from form is in login data from JSON file
    for teacher_login in login:
        if username == teacher_login['username'] and hashed_password == teacher_login['password']:
            session['logged_in'] = True
            session['username'] = username
            session['password'] = password
            return redirect(url_for('menu'))
    return redirect('/')


@app.get('/class_select')
def class_select():
    #  check if logged in
    if not session.get('logged_in'):
        return redirect('/')
    # return students in selected class
    all_students = get_all_students()
    selected_class = request.args.get("class")
    students_in_class = []
    for student in all_students:
        if student['class'] == selected_class:
            students_in_class.append(student)
    if selected_class == "all":
        return redirect(url_for('teacher'))
    return render_template("teacher.html", students=students_in_class, selected_class=selected_class)


@app.get('/update_call_status/<student_id>')
def update_call_status(student_id=None):
    #  check if logged in
    if not session.get('logged_in'):
        return redirect('/')
    # update call status for student
    all_students = get_all_students()
    for student in all_students:
        if student['id'] == student_id:
            student['call_status'] = "1"
    with open('students.json', 'w') as f:
        json.dump(all_students, f, indent=4)
    return redirect(url_for('caller'))


@app.route('/caller')
def caller():
    #  check if logged in
    if not session.get('logged_in'):
        return redirect('/')
    return render_template('caller.html')


@app.post('/search')
def search():
    all_students = get_all_students()
    search_term = request.form.get("search")
    students = []
    #  fuzzy  search and  sort by   highest rating
    for student in all_students:
        full_name = student['first_name'] + " " + student['last_name']
        if fuzz.ratio(search_term, full_name) > 20 or fuzz.ratio(search_term, student['number_plate']) > 20:
            students.append(student)
    students.sort(key=lambda x: fuzz.ratio(search_term, x['first_name'] + " " + x['last_name']), reverse=True)
    return render_template("caller.html", search_results=students)


@app.route('/add_teacher')
def add_teacher():
    return render_template('add_teacher.html')


@app.post('/add_teacher')
def add_teacher_post():
    # read login data from JSON file
    with open('teachers.json') as f:
        login = json.load(f)
    # read login data from form
    username = request.form.get("username")
    password = request.form.get("password")
    # store login data in session
    # encode password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # save new teacher to JSON file
    new_teacher = {
        "username": username,
        "password": hashed_password
    }
    login.append(new_teacher)
    with open('teachers.json', 'w') as f:
        json.dump(login, f, indent=4)
    return redirect(url_for('add_teacher'))


if __name__ == '__main__':
    app.run()
