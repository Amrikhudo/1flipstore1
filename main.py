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
    cart = db.relationship('Cart', backref='user', lazy='select', uselist=False)

    def __repr__(self):
        return f'<User {self.username}>'
    
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.relationship('CartItem', backref='cart', lazy='dynamic')

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    currency = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, default=1)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product = db.Column(db.String(80), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    user = db.relationship('User', backref='reviews')

with app.app_context():
    db.create_all()

prices = {
    'Легенды аниме': 699,
    'Крест-накрест': 649,
    'Призрачные легенды': 499,
    'Технолига': 499,
    'Вечная мерзлота': 649,
    'Подписка fornite crew': 699,
    'Золотые руки': 619,
    'Ледяные легенды': 649,
    'Потустороние легенды': 599,
}

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

    cart = Cart(user_id=new_user.id)
    db.session.add(cart)
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


@app.route('/add_review/<product>', methods=['POST'])
def add_review(product):
    if 'token' not in session:
        return redirect(url_for('login'))

    try:
        data = jwt.decode(session['token'], app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
    except jwt.ExpiredSignatureError:
        session.pop('token', None)
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        session.pop('token', None)
        return redirect(url_for('login'))

    if user is None:
        return redirect(url_for('login'))

    rating = request.form.get('rating')
    comment = request.form.get('comment')

    if not rating or not comment:
        return 'Отсутствуют обязательные поля', 400

    review = Review(user_id=user.id, product=product, rating=rating, comment=comment)
    db.session.add(review)
    db.session.commit()

    if product == 'Легенды аниме':
        return redirect(url_for('index3'))
    elif product == 'Крест-накрест':
        return redirect(url_for('index4'))
    elif product == 'Призрачные легенды':
        return redirect(url_for('index5'))
    elif product == 'Технолига':
        return redirect(url_for('index6'))
    elif product == 'Вечная мерзлота':
        return redirect(url_for('index7'))
    elif product == 'Подписка fornite crew':
        return redirect(url_for('index8'))
    elif product == 'Золотые руки':
        return redirect(url_for('index9'))
    elif product == 'Ледяные легенды':
        return redirect(url_for('index10'))
    elif product == 'Потустороние легенды':
        return redirect(url_for('index11'))



@app.route('/add_to_cart/<currency>', methods=['POST'])
def add_to_cart(currency):
    if 'token' not in session:
        return redirect(url_for('login'))

    try:
        data = jwt.decode(session['token'], app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
    except jwt.ExpiredSignatureError:
        session.pop('token', None)
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        session.pop('token', None)
        return redirect(url_for('login'))

    if user is None:
        return redirect(url_for('login'))

    cart = user.cart
    if cart is None:
        cart = Cart(user_id=user.id)
        db.session.add(cart)
        db.session.commit()

    item = CartItem.query.filter_by(cart_id=cart.id, currency=currency).first()
    if item:
        item.quantity += 1
    else:
        price = prices.get(currency, 0)
        item = CartItem(cart_id=cart.id, currency=currency, price=price)
        cart.items.append(item)
    db.session.commit()

    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    if 'token' not in session:
        return redirect(url_for('login'))

    try:
        data = jwt.decode(session['token'], app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
    except jwt.ExpiredSignatureError:
        session.pop('token', None)
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        session.pop('token', None)
        return redirect(url_for('login'))

    if user is None:
        return redirect(url_for('login'))

    cart = user.cart
    if cart is None:
        cart = Cart(user_id=user.id)
        db.session.add(cart)
        db.session.commit()

    total = sum(item.price * item.quantity for item in cart.items)
    return render_template('cart.html', cart=cart, total=total)

@app.route('/update_cart/<int:item_id>/<action>', methods=['POST'])
def update_cart(item_id, action):
    if 'token' not in session:
        return redirect(url_for('login'))

    try:
        data = jwt.decode(session['token'], app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
    except jwt.ExpiredSignatureError:
        session.pop('token', None)
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        session.pop('token', None)
        return redirect(url_for('login'))

    if user is None:
        return redirect(url_for('login'))

    cart = user.cart
    item = CartItem.query.get(item_id)

    if action == 'increase':
        item.quantity += 1
    elif action == 'decrease':
        item.quantity -= 1
        if item.quantity <= 0:
            db.session.delete(item)

    db.session.commit()
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
def remove_from_cart(item_id):
    if 'token' not in session:
        return redirect(url_for('login'))

    try:
        data = jwt.decode(session['token'], app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
    except jwt.ExpiredSignatureError:
        session.pop('token', None)
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        session.pop('token', None)
        return redirect(url_for('login'))

    if user is None:
        return redirect(url_for('login'))

    cart = user.cart
    item = CartItem.query.get(item_id)

    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('cart'))





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

    return render_template('index.html', top_element="main")



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
    user = None
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    reviews = Review.query.filter_by(product='Легенды аниме').order_by(Review.created_at.desc()).all()
    return render_template('index3.html', user=user, reviews=reviews)


@app.route('/card3')
def index4():
    token = session.get('token')
    user = None
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    reviews = Review.query.filter_by(product='Крест-накрест').order_by(Review.created_at.desc()).all()
    return render_template('index4.html', user=user, reviews=reviews)

@app.route('/card4')
def index5():
    token = session.get('token')
    user = None
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    reviews = Review.query.filter_by(product='Призрачные легенды').order_by(Review.created_at.desc()).all()
    return render_template('index5.html', user=user, reviews=reviews)

@app.route('/card5')
def index6():
    token = session.get('token')
    user = None
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    reviews = Review.query.filter_by(product='Технолига').order_by(Review.created_at.desc()).all()
    return render_template('index6.html', user=user, reviews=reviews)

@app.route('/card6')
def index7():
    token = session.get('token')
    user = None
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    reviews = Review.query.filter_by(product='Вечная мерзлота').order_by(Review.created_at.desc()).all()
    return render_template('index7.html', user=user, reviews=reviews)

@app.route('/card7')
def index8():
    token = session.get('token')
    user = None
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    reviews = Review.query.filter_by(product='Подписка fornite crew').order_by(Review.created_at.desc()).all()
    return render_template('index8.html', user=user, reviews=reviews)

@app.route('/card8')
def index9():
    token = session.get('token')
    user = None
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    reviews = Review.query.filter_by(product='Золотые руки').order_by(Review.created_at.desc()).all()
    return render_template('index9.html', user=user, reviews=reviews)

@app.route('/card9')
def index10():
    token = session.get('token')
    user = None
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    reviews = Review.query.filter_by(product='Ледяные легенды').order_by(Review.created_at.desc()).all()
    return render_template('index10.html', user=user, reviews=reviews)

@app.route('/card10')
def index11():
    token = session.get('token')
    user = None
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
        except jwt.InvalidTokenError:
            session.pop('token', None)

    reviews = Review.query.filter_by(product='Потустороние легенды').order_by(Review.created_at.desc()).all()
    return render_template('index11.html', user=user, reviews=reviews)



if __name__ == '__main__':
    app.run(debug=True)
