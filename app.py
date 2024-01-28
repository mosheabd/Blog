from flask import Flask, request, redirect, url_for, session, render_template, flash
from flask_sqlalchemy import SQLAlchemy
import hashlib
from datetime import datetime
import pytz
import yfinance as yf
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os



# create flask instance
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False') == 'True'
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')



# # create DB instance
db = SQLAlchemy(app)
mail = Mail(app)


# Generate a token
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirmation-salt')


# Confirm a token
def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt='email-confirmation-salt',
            max_age=expiration
        )
    except:
        return False
    return email


# define tables structure as classes
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    nickname = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    profile_photo_url = db.Column(db.String(255))
    posts = db.relationship('Post', backref='author', lazy=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

class Post(db.Model):
    def get_current_time():
        utc_now = datetime.utcnow()
        utc_now = utc_now.replace(tzinfo=pytz.utc)  # make the datetime object timezone aware
        gmt_plus_2_now = utc_now.astimezone(pytz.timezone('Etc/GMT-2'))
        return gmt_plus_2_now

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    time_created = db.Column(db.DateTime, nullable=False, default=get_current_time)
    last_updated = db.Column(db.DateTime, nullable=False, default=get_current_time, onupdate=get_current_time)
    ticker_symbol = db.Column(db.String(10))


def get_stock_data():
    # Define a list of stock symbols you're interested in
    stocks = ["AAPL", "MSFT", "GOOGL", "AMZN", "TSLA", "META", "BRK-A", "JPM", "V", "JNJ"]

    # Fetch information for each stock
    stock_info = []
    for stock in stocks:
        ticker = yf.Ticker(stock)
        info = ticker.info
        stock_info.append({
            "symbol": stock,
            "name": info.get("shortName", "N/A")
        })

    return stock_info


@app.route("/")
def index():
    if 'username' in session:
        return redirect(url_for('home'))
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/admin')
def admin():
    if 'username' in session:
        user = Users.query.get(username=session['username'].first())
        if user and user.is_admin:
            posts = Post.query.all()
            return render_template('admin.html', posts=posts)
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')

        existing_user = Users.query.filter_by(username=username).first()

        if existing_user:
            # Handle the case where a user with this username already exists
            return render_template('register.html', message=f'User {username} already exists!')

        if len(username) < 3 or len(username) > 20:
            return render_template('register.html', message=f'Username must be between 3 and 20 characters')

        # Continue with your user creation logic if the username is unique
        email = request.form.get('email')
        existing_email = Users.query.filter_by(email=email).first()

        if existing_email:
            return render_template('register.html', message=f'E-mail {email} already exist!')

        nickname = request.form.get('nickname')

        existing_nickname = Users.query.filter_by(email=nickname).first()

        if existing_nickname:
            return render_template('login.html', message=f'Nickname {nickname} already exist!')

        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            return render_template('register.html',
                                   match_passwords=True, message='Passwords dont match!')

        # in order to insert the hash password to DB.
        password = hashlib.sha256(password.encode()).hexdigest()
        new_user = Users(username=username, password_hash=password, email=email, nickname=nickname)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        # Send welcome email
        msg = Message("Welcome to Our Blog!",
                      recipients=[email])
        msg.body = f"Hello {username}, welcome to our blog! Visit our site: www.wallst.co.il"
        mail.send(msg)

        return redirect(url_for('home'))

    return render_template('register.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = Users.query.filter_by(email=email).first()
        if user:
            token = generate_confirmation_token(user.email)
            reset_url = url_for('reset_password_token', token=token, _external=True)
            msg = Message("Password Reset Request",
                          recipients=[user.email])
            msg.body = f"To reset your password, visit the following link: {reset_url}"
            mail.send(msg)
            # Inform the user to check their email
        return render_template('notify_reset.html')  # Create this template to notify the user
    return render_template('reset_password_request.html')  # Create this template for requesting password reset


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    email = confirm_token(token)
    if not email:
        return "The reset link is invalid or has expired.", 400
    user = Users.query.filter_by(email=email).first()
    if request.method == 'POST':
        new_password = request.form['password']
        user.password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('reset_password_form.html', token=token)  # Create this template for password reset form


@app.route('/login', methods=["GET", "POST"])
def login():
    if 'username' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password_input = request.form.get('password', '')  # Provide a default empty string
        password_hash = hashlib.sha256(password_input.encode()).hexdigest()

        user = Users.query.filter_by(username=username).first()

        if user and user.password_hash == password_hash:
            session['username'] = user.username  # Store the username
            session['nickname'] = user.nickname  # Store the username
            session['is_admin'] = user.is_admin  # Store admin status

            return redirect(url_for('index'))  # Redirect to the home page after login
        else:
            # In case of login failure, you can flash a message or return an error
            return render_template('login.html', message="Wrong Login!")

    # Render the login template if it's a GET request
    return render_template('login.html')


# @app.route('/posts', methods=['GET'])
# def get_posts():
#     posts = Post.query.all()
#     return jsonify([{'title': post.title, 'content': post.content, 'author': post.author.username} for post in posts])


@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'username' in session:  # Check if user_id, not username, is in the session
        if request.method == 'POST':
            title = request.form.get('title')
            content = request.form.get('content')
            stock_symbol = request.form.get('stock')

            user = Users.query.filter_by(username=session['username']).first()
            if user:
                # Create a new post
                new_post = Post(title=title, content=content, user_id=user.id, ticker_symbol=stock_symbol)
                db.session.add(new_post)
                db.session.commit()

                return redirect(url_for('index'))  # Redirect after successful post creation

            else:
                return redirect(url_for('login'))

        stocks = get_stock_data()
        return render_template('create_post.html', stocks=stocks)

    return redirect(url_for('login'))  # Redirect to login if the user is not in session


@app.route('/edit_post/<int:post_id>', methods=['GET'])
def edit_post(post_id):
    try:
        if 'username' not in session:
            flash('You need to log in to edit posts.', 'info')
            return redirect(url_for('login'))

        post = Post.query.get_or_404(post_id)
        user = Users.query.filter_by(username=session['username']).first()

        if post.author.id != user.id:
            flash('You do not have permission to edit this post.', 'warning')
            return redirect(url_for('index'))

        return render_template('edit_post.html', post=post)

    except SQLAlchemyError as e:
        # Log this error to a file or error tracking service
        print(f"Database error occurred: {e}")
        flash('An error occurred while accessing the database.', 'error')
        return redirect(url_for('index'))

    except Exception as e:
        # Log this error to a file or error tracking service
        print(f"An unexpected error occurred: {e}")
        flash('An unexpected error occurred.', 'error')
        return redirect(url_for('index'))


@app.route('/update_post/<int:post_id>', methods=['POST'])
def update_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    post = Post.query.get_or_404(post_id)
    user = Users.query.filter_by(username=session['username']).first()
    if post.author.id != user.id:
        return redirect(url_for('index'))

    # Update the title and content
    post.title = request.form['title']
    post.content = request.form['content']

    # No need to manually update `last_updated`, SQLAlchemy will do it automatically
    db.session.commit()

    return redirect(url_for('home'))


@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    # Check if the user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))

    post = Post.query.get_or_404(post_id)
    user = Users.query.filter_by(username=session['username']).first()

    # Check if the logged-in user is the author of the post
    if post.author.id != user.id and not user.is_admin:
        return redirect(url_for('index'))  # or return a 403 Forbidden error

    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    user_filter = request.args.get('user_filter')
    ticker_filter = request.args.get('ticker_filter')
    per_page = 4

    # Start with a base query
    query = Post.query.order_by(Post.time_created.desc())

    # Apply user filter if provided
    if user_filter:
        user = Users.query.filter_by(username=user_filter).first()
        if user:
            query = query.filter_by(user_id=user.id)

    # Apply ticker filter if provided
    if ticker_filter:
        query = query.filter(Post.ticker_symbol == ticker_filter)

    posts_pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    stocks = get_stock_data()  # Get the stock data
    all_users = Users.query.all()  # Get all users

    try:
        for post in posts_pagination.items:
            if post.ticker_symbol:
                ticker = yf.Ticker(post.ticker_symbol)
                hist = ticker.history(period="ytd")
                if not hist.empty:
                    last_close = hist['Close'].iloc[-1]
                    first_open = hist['Open'].iloc[0]
                    ytd_change = ((last_close - first_open) / first_open) * 100

                    post.last_close = round(last_close, 2)
                    post.ytd_change = round(ytd_change, 2)
                else:
                    post.last_close = None
                    post.ytd_change = None
    except Exception as e:
        print(f"An error occurred: {e}")

    # Fetch all users for the filter dropdown
    all_users = Users.query.all()

    return render_template('home.html', posts=posts_pagination, all_users=all_users, stocks=stocks)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
