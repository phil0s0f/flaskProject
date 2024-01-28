from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        return 'Вы вошли в систему!'
    else:
        return render_template(login.html)

@app.route('/')
def hello_world():  # put application's code here
    return 'Hello World!'


if __name__ == '__main__':
    app.run()
