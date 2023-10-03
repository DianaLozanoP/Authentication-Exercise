from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import UserForm, UserLogIn, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///authentication_ex"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

app.app_context().push()

connect_db(app)
db.create_all()

toolbar = DebugToolbarExtension(app)


@app.route('/')
def home_page():
    return redirect('/register')


@app.route('/register', methods=["GET", "POST"])
def register_user():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        new_user = User.register(username=username, password=password,
                                 email=email, first_name=first_name, last_name=last_name)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append(
                'Username taken. Please create another one.')
            return render_template('register.html', form=form)
        session['username'] = new_user.username
        flash('Welcome! Successfully Created Your Account!', 'success')
        return redirect(f'/users/{new_user.username}')
    else:
        return render_template('register.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login_user():
    form = UserLogIn()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f'Hey, welcome back, {user.first_name}!', 'primary')
            session['username'] = user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors = [
                'Invalid username or password. Please try again.']
    return render_template('login.html', form=form)


@app.route('/users/<username>')
def display_user_info(username):
    """Display all the personal information about user if loggedin"""
    if "username" not in session:
        flash('Please login first', 'danger')
        return redirect('/login')
    user = User.query.get_or_404(username)
    return render_template('userinfo.html', user=user)


@app.route('/users/<username>/delete', methods=["POST"])
def delete_user(username):
    """Delete user and feedback created by that user"""
    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
    user = User.query.get_or_404(username)
    all_feedback = Feedback.query.filter_by(username=user.username).all()
    if username == session["username"]:
        # need to loop thrpugh all the feedbacks
        for feedback in all_feedback:
            db.session.delete(feedback)
        # then delete user
        db.session.delete(user)
        # commit changes
        db.session.commit()
        session.pop('username')
        flash("User deleted", "info")
        return redirect('/')
    flash('You do not have permission to do that', 'danger')
    return redirect('/')


@app.route('/users/<username>/feedback/add', methods=["GET", "POST"])
def add_feedback(username):
    """Display a form to ad feed back. Then add info once posted and submitted"""
    if username == session["username"]:
        form = FeedbackForm()
        if form.validate_on_submit():
            title = form.title.data
            content = form.content.data
            new_feedback = Feedback(
                title=title, content=content, username=username)
            db.session.add(new_feedback)
            db.session.commit()
            flash('Added new feedback', 'success')
            return redirect(f'/users/{username}')
        return render_template('feedback_form.html', form=form)
    flash('You do not have permission to do that', 'danger')
    return redirect('/')


@app.route('/feedback/<feedback_id>/update', methods=["GET", "POST"])
def update_feedback(feedback_id):
    """Display a form when is a GET request. 
    Submit the info when is a POST request.
    Check for the username for permisions"""
    feedback = Feedback.query.get_or_404(feedback_id)
    form = FeedbackForm()
    if feedback.username == session["username"]:
        if form.validate_on_submit():
            feedback.title = form.title.data
            feedback.content = form.content.data
            db.session.add(feedback)
            db.session.commit()
            flash('Feedback has been updated', 'success')
            return redirect(f'/users/{feedback.username}')
        form.title.data = feedback.title
        form.content.data = feedback.content
        return render_template('edit_feedback.html', form=form)
    flash('You do not have permission to do that', 'danger')
    return redirect('/')


@app.route('/feedback/<feedback_id>/delete', methods=["POST"])
def delete_feedback(feedback_id):
    """Delete the feedback from database."""
    feedback = Feedback.query.get_or_404(feedback_id)
    if feedback.username == session["username"]:
        db.session.delete(feedback)
        db.session.commit()
        flash('Feedback was deleted', 'info')
        return redirect(f'/users/{feedback.username}')
    flash('You do not have permission to do that', 'danger')
    return redirect('/')


@app.route('/secret')
def display_secret():
    if "username" not in session:
        flash('Please login first', 'danger')
        return redirect('/login')
    return ("<h1>You made it</h1>")


@app.route('/logout')
def logout_user():
    session.pop('username')
    flash('Goodbye!', 'info')
    return redirect('/')
