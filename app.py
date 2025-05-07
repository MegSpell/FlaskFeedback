from flask import Flask, render_template, redirect, session, flash, url_for, request
from flask_debugtoolbar import DebugToolbarExtension
from flask_bcrypt import Bcrypt

# Import your WTForms forms and your SQLAlchemy models
from forms import RegisterForm, LoginForm, FeedbackForm
from models import db, connect_db, User, Feedback

# ───────────────────────────────────────────────────────────────────────────────
# App Setup
# ───────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)  

# Tell Flask what database to use
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///flask_feedback'
# Turn off the Flask-SQLAlchemy event system (not needed here)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Echo SQL statements to console for debugging
app.config['SQLALCHEMY_ECHO'] = True
# Secret key for session & CSRF protection
app.config['SECRET_KEY'] = 'shhh-its-a-secret'

app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

# Wrap our app in Bcrypt so we can hash passwords
bcrypt = Bcrypt(app)

# Connect Flask → SQLAlchemy
connect_db(app)
# Create tables if they don’t exist yet
with app.app_context():
    db.create_all()

# Optional: Enable the debug toolbar (must come after app is configured)
toolbar = DebugToolbarExtension(app)


# ───────────────────────────────────────────────────────────────────────────────
# Helpers
# ───────────────────────────────────────────────────────────────────────────────

def check_logged_in(username):
    """Return True if the given username matches the one in session."""
    return 'username' in session and session['username'] == username


# ───────────────────────────────────────────────────────────────────────────────
# Routes
# ───────────────────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    """Redirect to registration page as our “home”."""
    return redirect('/register')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Show & handle the registration form.
    - GET: display blank form
    - POST: validate, hash password, create user, log them in, redirect to profile
    """
    form = RegisterForm()

    if form.validate_on_submit():
        # Hash the plaintext password
        hashed = bcrypt.generate_password_hash(form.password.data).decode('utf8')
        # Build User object
        user = User(
            username=form.username.data,
            password=hashed,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data
        )
        # Save to database
        db.session.add(user)
        db.session.commit()

        # Log them in by storing username in session
        session['username'] = user.username

        # Redirect to their profile page
        return redirect(f"/users/{user.username}")

    # If GET or validation fails, re-render template with form & errors
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Show & handle the login form.
    - GET: display blank form
    - POST: validate, check credentials, log in or flash error
    """
    form = LoginForm()

    if form.validate_on_submit():
        # Look up user by username
        user = User.query.filter_by(username=form.username.data).first()

        # If user exists and password matches
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['username'] = user.username
            return redirect(f"/users/{user.username}")
        else:
            # Invalid login attempt
            flash('Invalid credentials', 'danger')

    return render_template('login.html', form=form)


@app.route('/secret')
def secret():
    """
    A protected route that only logged-in users should see.
    If not logged in, flash & redirect to login.
    """
    if 'username' not in session:
        flash("You must be logged in to view that page.", 'danger')
        return redirect('/login')
    return "You made it!"


@app.route('/users/<username>')
def show_user(username):
    """
    Show a user’s profile & feedback.
    Only the logged-in user may view their own page.
    """
    if not check_logged_in(username):
        flash("Unauthorized access.", "danger")
        return redirect('/')

    # Fetch the user or 404 if not found
    user = User.query.get_or_404(username)
    return render_template('user_detail.html', user=user)


@app.route('/users/<username>/delete', methods=["POST"])
def delete_user(username):
    """
    Delete a user and all their feedback.
    Only the logged-in user may delete their own account.
    """
    if not check_logged_in(username):
        flash("Unauthorized.", "danger")
        return redirect('/')

    user = User.query.get_or_404(username)
    db.session.delete(user)
    db.session.commit()

    # Clear session so they’re logged out
    session.pop("username", None)
    flash("Account deleted.", "danger")
    return redirect('/')


@app.route('/users/<username>/feedback/add')
def show_feedback_form(username):
    """
    Show form to add feedback for the logged-in user.
    """
    if not check_logged_in(username):
        flash("Unauthorized.", "danger")
        return redirect('/')

    form = FeedbackForm()
    return render_template('add_feedback.html', form=form)


@app.route('/users/<username>/feedback/add', methods=["POST"])
def add_feedback(username):
    """
    Handle submission of new feedback.
    Only the logged-in user may add feedback for themselves.
    """
    if not check_logged_in(username):
        flash("Unauthorized.", "danger")
        return redirect('/')

    form = FeedbackForm()
    if form.validate_on_submit():
        # Create Feedback linked to this user
        new_fb = Feedback(
            title=form.title.data,
            content=form.content.data,
            username=username
        )
        db.session.add(new_fb)
        db.session.commit()

        flash("Feedback added!", "success")
        return redirect(f'/users/{username}')

    # If validation fails, re-render form with error messages
    return render_template('add_feedback.html', form=form)


@app.route('/feedback/<int:feedback_id>/update')
def show_edit_form(feedback_id):
    """
    Show form to edit an existing feedback.
    Only the feedback’s author may view this page.
    """
    fb = Feedback.query.get_or_404(feedback_id)
    if not check_logged_in(fb.username):
        flash("Unauthorized.", "danger")
        return redirect('/')

    # Pre-fill form with current feedback data
    form = FeedbackForm(obj=fb)
    return render_template('edit_feedback.html', form=form, feedback=fb)


@app.route('/feedback/<int:feedback_id>/update', methods=["POST"])
def update_feedback(feedback_id):
    """
    Handle submission of edited feedback.
    Only the feedback’s author may submit updates.
    """
    fb = Feedback.query.get_or_404(feedback_id)
    if not check_logged_in(fb.username):
        flash("Unauthorized.", "danger")
        return redirect('/')

    form = FeedbackForm()
    if form.validate_on_submit():
        # Update the fields
        fb.title = form.title.data
        fb.content = form.content.data
        db.session.commit()

        flash("Feedback updated.", "success")
        return redirect(f'/users/{fb.username}')

    return render_template('edit_feedback.html', form=form, feedback=fb)


@app.route('/feedback/<int:feedback_id>/delete', methods=["POST"])
def delete_feedback(feedback_id):
    """
    Delete a piece of feedback.
    Only the feedback’s author may delete it.
    """
    fb = Feedback.query.get_or_404(feedback_id)
    if not check_logged_in(fb.username):
        flash("Unauthorized.", "danger")
        return redirect('/')

    db.session.delete(fb)
    db.session.commit()

    flash("Feedback deleted.", "danger")
    return redirect(f'/users/{fb.username}')


@app.route('/logout')
def logout():
    """
    Log the user out by clearing the session, then redirect to login.
    """
    session.clear()  
    flash("You have been logged out.", "info")
    return redirect("/login")
