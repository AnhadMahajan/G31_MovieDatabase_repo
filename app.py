from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import os

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "movies.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "YourSecretKey"
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static/uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(300), nullable=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)  
    user = db.relationship('User', backref=db.backref('cart', lazy=True))
    book = db.relationship('Book', backref=db.backref('cart', lazy=True))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    status = db.Column(db.String(50), default='Pending')
    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    book = db.relationship('Book', backref=db.backref('orders', lazy=True))



class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Float, nullable=False)

class Watchlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, nullable=False)




class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')



@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard' if current_user.role != 'admin' else 'admin_dashboard'))

    reg_form = RegistrationForm(prefix="reg")
    login_form = LoginForm(prefix="log")

    if request.method == "POST":
        if "reg-submit" in request.form and reg_form.validate_on_submit():
            if User.query.filter_by(email=reg_form.email.data).first():
                flash("Email already exists!", "danger")
                return redirect(url_for("signup"))

            new_user = User(
                name=reg_form.name.data,
                email=reg_form.email.data,
                role="user"
            )
            new_user.set_password(reg_form.password.data)  # Hash password
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('signup'))

        elif "log-submit" in request.form and login_form.validate_on_submit():
            user = User.query.filter_by(email=login_form.email.data).first()
            if user and user.check_password(login_form.password.data):  # Verify hashed password
                login_user(user)
                return redirect(url_for('user_dashboard' if user.role != 'admin' else 'admin_dashboard'))

            flash("Login unsuccessful. Please check your credentials.", "danger")

    return render_template("signup.html", reg_form=reg_form, login_form=login_form)

@app.route('/my_wishlist')
def my_wishlist():
    return render_template('my_wishlist.html')



@app.route('/movie')
def movie_index():
    books = Book.query.all()
    conn = sqlite3.connect('movies.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, rating, image_url FROM movies")
    movies = cursor.fetchall()
    conn.close()
    return render_template('index.html', movies=movies,books = books)

@app.route('/movie/<int:movie_id>', methods=['GET', 'POST'])
def movie_details(movie_id):
    conn = sqlite3.connect('movies.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM movies WHERE id = ?", (movie_id,))
    movie = cursor.fetchone()
    
    if request.method == 'POST':
        if 'comment' in request.form and 'rating' in request.form:
            comment = request.form['comment']
            rating = float(request.form['rating'])
            new_review = Review(movie_id=movie_id, comment=comment, rating=rating)
            db.session.add(new_review)
            db.session.commit()
        elif 'watchlist' in request.form:
            if not Watchlist.query.filter_by(movie_id=movie_id).first():
                new_watchlist = Watchlist(movie_id=movie_id)
                db.session.add(new_watchlist)
                db.session.commit()
    
    reviews = Review.query.filter_by(movie_id=movie_id).all()
    watchlisted = Watchlist.query.filter_by(movie_id=movie_id).first() is not None
    
    cursor.execute("SELECT name FROM genres WHERE id IN (SELECT genre_id FROM movie_genre WHERE movie_id = ?)", (movie_id,))
    genres = [row[0] for row in cursor.fetchall()]
    
    cursor.execute("SELECT actor_name, character_name, profile_path FROM cast WHERE movie_id = ? ORDER BY `order` ASC", (movie_id,))
    cast = cursor.fetchall()
    
    conn.close()
    
    return render_template('movie_details.html', movie=movie, genres=genres, cast=cast, reviews=reviews, watchlisted=watchlisted)

@app.route('/add_to_watchlist/<int:movie_id>')
def add_to_watchlist(movie_id):
    if not Watchlist.query.filter_by(movie_id=movie_id).first():
        new_watchlist = Watchlist(movie_id=movie_id)
        db.session.add(new_watchlist)
        db.session.commit()
    return redirect(url_for('movie_details', movie_id=movie_id))



@app.route('/watchlist')
def watchlist():
    watchlist_movies = db.session.query(Watchlist.movie_id, sqlite3.connect('movies.db').execute("SELECT name, image_url FROM movies WHERE id IN (SELECT movie_id FROM watchlist)")).fetchall()
    return render_template('watchlist.html', watchlist_movies=watchlist_movies)




@app.route("/user_dashboard")
@login_required
def user_dashboard():
    return render_template("user_dashboard.html", user=current_user)

@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    return render_template("admin_dashboard.html", user=current_user)



@app.route('/contactus')
def contactus():
    return render_template('contactus.html')

@app.route('/about_us')
def about_us():
    return render_template("about_us.html")




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    books = Book.query.all()
    return render_template('landing.html', books=books)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):  
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("index"))

        flash("Invalid email or password!", "danger")

    return render_template("login.html")






@app.route('/add_movie', methods=['GET', 'POST'])
@login_required
def add_movie():
    if current_user.role != 'admin':  
        flash("Access denied!", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        price = request.form['price']
        image = request.files['image']

        filename = secure_filename(image.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(image_path)

        new_book = Book(title=title, author=author, price=price, image=filename, uploaded_by=current_user.id)
        db.session.add(new_book)
        db.session.commit()
        flash("Book added successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('add_movie.html')

@app.route('/edit_book/<int:book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    if current_user.role != 'admin':
        flash("Access denied!", "danger")
        return redirect(url_for('dashboard'))

    book = Book.query.get_or_404(book_id)

    if request.method == 'POST':
        book.title = request.form['title']
        book.author = request.form['author']
        book.price = float(request.form['price'])

        if 'image' in request.files and request.files['image'].filename:
            image = request.files['image']
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)
            book.image = filename 

        db.session.commit()
        flash("Book updated successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('edit_movie.html', book=book)


@app.route('/delete_book/<int:book_id>', methods=['POST','GET'])
@login_required
def delete_book(book_id):
    if current_user.role != 'admin':
        flash("Access denied!", "danger")
        return redirect(url_for('dashboard'))

    book = Book.query.get_or_404(book_id)

    Cart.query.filter_by(book_id=book.id).delete()
    db.session.commit()


    db.session.delete(book)
    db.session.commit()
    
    flash("Book deleted successfully!", "success")
    return redirect(url_for('dashboard'))




@app.route('/update_order/<int:order_id>/<string:status>')
@login_required
def update_order(order_id, status):
    if current_user.role != 'admin':
        flash("Access denied!", "danger")
        return redirect(url_for('index'))
    
    order = Order.query.get_or_404(order_id)
    order.status = status
    db.session.commit()
    flash(f"Order {status}!", "success")
    return redirect(url_for('orders'))

@app.route('/track_orders')
@login_required
def track_orders():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('track_orders.html', orders=orders)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form.get("role", "user")

        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))

        new_user = User(name=name, email=email, role=role)
        new_user.set_password(password)  # Hash password
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")




@app.route('/add_to_cart/<int:book_id>')
@login_required
def add_to_cart(book_id):
    book = Book.query.get(book_id)
    if not book:
        flash("Book not found!", "danger")
        return redirect(url_for('index'))
    

    existing_item = Cart.query.filter_by(user_id=current_user.id, book_id=book_id).first()
    if existing_item:
        flash("Book is already in your cart!", "warning")
        return redirect(url_for('cart'))

    cart_item = Cart(user_id=current_user.id, book_id=book_id)
    db.session.add(cart_item)
    db.session.commit()
    flash("Book added to cart!", "success")
    return redirect(url_for('cart'))

@app.route('/add_to_cart/<int:book_id>')
@login_required
def add_to_wishlist(book_id):
    cart_item = Cart(user_id=current_user.id, book_id=book_id)
    db.session.add(cart_item)
    db.session.commit()
    flash("Book added to cart!", "success")
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:book_id>')
@login_required
def remove_from_cart(book_id):
    cart_item = Cart.query.filter_by(user_id=current_user.id, book_id=book_id).first()
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
        flash("Book removed from cart!", "success")
    return redirect(url_for('cart'))

@app.route('/cart')
@login_required
def cart():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    total_price = sum(item.book.price for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)

@app.route('/place_order')
@login_required
def place_order():
    if current_user.role == 'admin':  
        flash("Admins cannot place orders!", "danger")
        return redirect(url_for('index'))

    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    if not cart_items:
        flash("Your cart is empty!", "warning")
        return redirect(url_for('cart'))
    
    for item in cart_items:
        new_order = Order(user_id=current_user.id, book_id=item.book_id, status='Pending')
        db.session.add(new_order)
        db.session.delete(item)  
    db.session.commit()
    
    flash("Order placed successfully!", "success")
    return redirect(url_for('orders'))


@app.route('/orders')
@login_required
def orders():
    if current_user.role != 'admin':
        flash("Access denied!", "danger")
        return redirect(url_for('index'))
    orders = Order.query.all()
    return render_template('orders.html', orders=orders)

@app.route('/custom_details/<int:book_id>')
def custom_details(book_id):
    book = Book.query.get_or_404(book_id)
    return render_template('custom_movies.html', book=book)

@app.route('/book/<int:book_id>')
def book_details(book_id):
    book = Book.query.get_or_404(book_id)
    return render_template('book_details.html', book=book)

@app.route('/dashboard')
@login_required
def dashboard():
    books = Book.query.all() if current_user.role == 'admin' else []
    return render_template('dashboard.html', books=books)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5900)