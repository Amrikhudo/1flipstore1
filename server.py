from flask import Flask, request, session, render_template, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import re
import os
import uuid

app = Flask(__name__, template_folder='template')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret_key'
db = SQLAlchemy(app)

messages = []
UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def get_unique_filename(filename):
    _, ext = os.path.splitext(filename)
    unique_filename = f"{uuid.uuid4().hex}{ext}"
    return unique_filename


# Словарь с вопросами и соответствующими ответами
questions_and_answers = {
    r'привет|здравствуй|hello|hi': 'Здравствуйте! Чем я могу Вам помочь?',
    r'как дела|как жизнь': 'Спасибо, у меня все хорошо!',
    r'что ты умеешь': 'Я могу отвечать на различные вопросы, касающиеся нашего сайта и услуг. Попробуйте задать мне вопрос, и я постараюсь помочь!',
    r'где вы находитесь|ваш адрес': 'К сожалению, у нас нет физического офиса. Мы онлайн-магазин и работаем исключительно через интернет.',
    r'время работы|график работы': 'Наш сайт и служба поддержки работают круглосуточно, без выходных.',
    r'доставка|стоимость доставки': 'Стоимость доставки зависит от региона и рассчитывается при оформлении заказа. Подробную информацию вы можете найти на нашем сайте в разделе "Доставка".',
    r'оплата|способы оплаты': 'Мы принимаем оплату банковскими картами, электронными кошельками, а также наличными при доставке курьером. Более подробную информацию вы можете найти на нашем сайте в разделе "Оплата".',
    r'гарантия|возврат': 'У нас действует гарантия на все товары. Если вы обнаружили брак или товар не соответствует заявленному качеству, вы можете вернуть его в течение 14 дней с момента получения. Подробнее о гарантии и возврате вы можете узнать на нашем сайте в соответствующем разделе.',
}


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


class ReviewImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review_id = db.Column(db.Integer, db.ForeignKey('review.id'))
    image = db.Column(db.LargeBinary)
    filename = db.Column(db.String(100))
    mimetype = db.Column(db.String(100))

    review = db.relationship('Review', backref=db.backref('images', lazy='dynamic'))


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


# REST API
@app.route('/api/products', methods=['GET'])
def get_products():
    products = [
        {'id': 1, 'name': 'Легенды аниме', 'price': 699.99},
        {'id': 2, 'name': 'Крест-накрест', 'price': 649.99},
        {'id': 3, 'name': 'Призрачные легенды', 'price': 499.99},
        {'id': 4, 'name': 'Технолига', 'price': 499.99},
        {'id': 5, 'name': 'Вечная мерзлота', 'price': 649.99},
        {'id': 6, 'name': 'Подписка fornite crew', 'price': 699.99},
        {'id': 7, 'name': 'Золотые руки', 'price': 619.99},
        {'id': 8, 'name': 'Ледяные легенды', 'price': 649.99},
        {'id': 9, 'name': 'Потустороние легенды', 'price': 599.99}
    ]
    return jsonify(products)


@app.route('/api/cart', methods=['GET'])
def get_cart():
    if 'token' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        data = jwt.decode(session['token'], app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
    except jwt.ExpiredSignatureError:
        session.pop('token', None)
        return jsonify({'error': 'Unauthorized'}), 401
    except jwt.InvalidTokenError:
        session.pop('token', None)
        return jsonify({'error': 'Unauthorized'}), 401

    if user is None:
        return jsonify({'error': 'Unauthorized'}), 401

    cart = user.cart
    if cart is None:
        return jsonify([])
    cart_items = [{'id': item.id, 'name': item.currency, 'price': item.price, 'quantity': item.quantity} for item in
                  cart.items]
    return jsonify(cart_items)


@app.route('/api/cart/add', methods=['POST'])
def add_to_cart_api():
    if 'token' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = jwt.decode(session['token'], app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
    except jwt.ExpiredSignatureError:
        session.pop('token', None)
        return jsonify({'error': 'Unauthorized'}), 401
    except jwt.InvalidTokenError:
        session.pop('token', None)
        return jsonify({'error': 'Unauthorized'}), 401

    if user is None:
        return jsonify({'error': 'Unauthorized'}), 401

    cart = user.cart
    if cart is None:
        cart = Cart(user_id=user.id)
        db.session.add(cart)
        db.session.commit()

    product_name = request.json.get('name')
    price = prices.get(product_name, 0)

    item = CartItem.query.filter_by(cart_id=cart.id, currency=product_name).first()
    if item:
        item.quantity += 1
    else:
        item = CartItem(cart_id=cart.id, currency=product_name, price=price)
        cart.items.append(item)
    db.session.commit()

    return jsonify({'message': 'Product added to cart'}), 200


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    data = request.form
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return render_template('register.html', error='Пожалуйста, заполните все поля.', error_color='red')

    if User.query.filter_by(username=username).first():
        return render_template('register.html', error='Это имя пользователя уже занято. Пожалуйста, выберите другое.',
                               error_color='red')

    if User.query.filter_by(email=email).first():
        return render_template('register.html',
                               error='Этот адрес электронной почты уже зарегистрирован. Пожалуйста, используйте другой адрес.',
                               error_color='red')

    if len(password) < 8 or not any(char.isdigit() for char in password) or not any(
            char.isupper() for char in password):
        return render_template('register.html',
                               error='Пароль должен содержать не менее 8 символов, включая хотя бы одну цифру и одну заглавную букву.',
                               error_color='red')

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

    if not user:
        return render_template('login.html',
                               error='Неверное имя пользователя или пароль. Пожалуйста, попробуйте снова.',
                               error_color='red')

    if not check_password_hash(user.password, password):
        return render_template('login.html',
                               error='Неверное имя пользователя или пароль. Пожалуйста, попробуйте снова.',
                               error_color='red')

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

    images = request.files.getlist('images')

    review = Review(user_id=user.id, product=product, rating=rating, comment=comment)
    db.session.add(review)
    db.session.commit()

    for image in images:
        if image.filename:
            filename = get_unique_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)

            review_image = ReviewImage(review_id=review.id, filename=filename, mimetype=image.mimetype)
            db.session.add(review_image)

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


@app.route('/delete_review/<int:review_id>', methods=['POST'])
def delete_review(review_id):
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

    review = Review.query.get(review_id)

    if review.user_id != user.id:
        return 'Вы не можете удалить чужой отзыв', 403

    db.session.delete(review)
    db.session.commit()

    if review.product == 'Легенды аниме':
        return redirect(url_for('index3'))
    elif review.product == 'Крест-накрест':
        return redirect(url_for('index4'))
    elif review.product == 'Призрачные легенды':
        return redirect(url_for('index5'))
    elif review.product == 'Технолига':
        return redirect(url_for('index6'))
    elif review.product == 'Вечная мерзлота':
        return redirect(url_for('index7'))
    elif review.product == 'Подписка fornite crew':
        return redirect(url_for('index8'))
    elif review.product == 'Золотые руки':
        return redirect(url_for('index9'))
    elif review.product == 'Ледяные легенды':
        return redirect(url_for('index10'))
    elif review.product == 'Потустороние легенды':
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


@app.route('/send_message', methods=['POST'])
def send_message():
    message = request.form['message']
    messages.append(('user', message))

    # проверяем соответствует ли сообщение одному из вопросов в словаре
    for question_pattern, answer in questions_and_answers.items():
        if re.search(question_pattern, message, re.IGNORECASE):
            bot_response = answer
            break
    else:
        bot_response = f"Извините, я не смог распознать ваш запрос. Пожалуйста, сформулируйте его более конкретно."

    messages.append(('bot', bot_response))

    return jsonify({'success': True, 'messages': messages})


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
    average_rating = sum(review.rating for review in reviews) / len(reviews) if reviews else 0
    return render_template('index3.html', user=user, reviews=reviews, average_rating=average_rating)


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
    average_rating = sum(review.rating for review in reviews) / len(reviews) if reviews else 0
    return render_template('index4.html', user=user, reviews=reviews, average_rating=average_rating)


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
    average_rating = sum(review.rating for review in reviews) / len(reviews) if reviews else 0
    return render_template('index5.html', user=user, reviews=reviews, average_rating=average_rating)


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
    average_rating = sum(review.rating for review in reviews) / len(reviews) if reviews else 0
    return render_template('index6.html', user=user, reviews=reviews, average_rating=average_rating)


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
    average_rating = sum(review.rating for review in reviews) / len(reviews) if reviews else 0
    return render_template('index7.html', user=user, reviews=reviews, average_rating=average_rating)


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
    average_rating = sum(review.rating for review in reviews) / len(reviews) if reviews else 0
    return render_template('index8.html', user=user, reviews=reviews, average_rating=average_rating)


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
    average_rating = sum(review.rating for review in reviews) / len(reviews) if reviews else 0
    return render_template('index9.html', user=user, reviews=reviews, average_rating=average_rating)


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
    average_rating = sum(review.rating for review in reviews) / len(reviews) if reviews else 0
    return render_template('index10.html', user=user, reviews=reviews, average_rating=average_rating)


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
    average_rating = sum(review.rating for review in reviews) / len(reviews) if reviews else 0
    return render_template('index11.html', user=user, reviews=reviews, average_rating=average_rating)


if __name__ == '__main__':
    app.run(debug=True)
