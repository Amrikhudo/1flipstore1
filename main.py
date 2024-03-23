from flask import Flask, request, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

app = Flask(__name__, template_folder='template')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret_key'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

with app.app_context():
    db.create_all()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    data = request.form
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return 'Отсутствуют обязательные поля', 400

    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return 'Имя пользователя или адрес электронной почты уже существует', 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    data = request.form
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return 'Неправильное имя пользователя или пароль', 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, app.config['SECRET_KEY'])

    session['token'] = token
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('index'))

@app.route('/')
def index():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('index.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    return render_template('index.html')



@app.route('/garantiya')
def garantiya():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('garantiya.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    return render_template('garantiya.html')

@app.route('/help')
def help():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('help.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    return render_template('help.html')

@app.route('/geo')
def geo():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('geo.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    return render_template('geo.html')

@app.route('/card2')
def index3():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('index3.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)
            
    return render_template('index3.html')

@app.route('/card3')
def index4():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('index4.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)
            
    return render_template('index4.html')

@app.route('/card4')
def index5():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('index5.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)
            
    return render_template('index5.html')

@app.route('/card5')
def index6():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('index6.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)
            
    return render_template('index6.html')

@app.route('/card6')
def index7():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('index7.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)
            
    return render_template('index7.html')

@app.route('/card7')
def index8():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('index8.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)
            
    return render_template('index8.html')

@app.route('/card8')
def index9():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('index9.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)
            
    return render_template('index9.html')

@app.route('/card9')
def index10():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('index10.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)
            
    return render_template('index10.html')

@app.route('/card10')
def index11():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('index11.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)
            
    return render_template('index11.html')

@app.route('/card11')
def index12():
    token = session.get('token')

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            return render_template('index12.html', user=user)
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)
            
    return render_template('index12.html')


if __name__ == '__main__':
    app.run(debug=True)