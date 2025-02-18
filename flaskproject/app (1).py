from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from flask_login import login_user, login_required, logout_user, UserMixin, LoginManager, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length ,EqualTo, Email, DataRequired, ValidationError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"connect_args": {"check_same_thread": False}}
app.secret_key = "supersecretkey"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager=LoginManager(app)
login_manager.login_view='login_page'
login_manager.login_message_category='info'


# Models
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__="users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email_address = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(60), nullable=False)
    tasks = db.relationship('Task', lazy=True, backref="user")

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute.")
    
    @password.setter
    def password(self, plain_text_password):
        self.password_hash=bcrypt.generate_password_hash(plain_text_password).decode('utf-8')
        
    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)
        
    def __repr__(self):
        return f'User {self.username}'

class Task(db.Model):
    __tablename__="tasks"
    id = db.Column(db.Integer, primary_key=True)
    task_title = db.Column(db.String(200), nullable=False)
    task_description = db.Column(db.String(1500))
    task_date = db.Column(db.Date, default=date.today)
    task_prior = db.Column(db.Boolean, default=False, nullable=False)
    task_important = db.Column(db.Boolean, default=False, nullable=False)
    task_complete = db.Column(db.Boolean, default=False, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def __repr__(self):
        return f'Task {self.task_title} (Important: {self.task_important})'
      
# Forms
class RegisterForm(FlaskForm):
    
    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')
    
    def validate_email_address(self, email_address_to_check):
        email_address=User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('Email Address already exists! Please try a different Email Address')
    
    username = StringField(label='Username', validators=[DataRequired(), Length(min=2, max=30)])
    email = StringField(label='Email', validators=[DataRequired(), Email()])
    password1 = PasswordField(label='Password', validators=[DataRequired()])
    password2 = PasswordField(label='Confirm Password', validators=[DataRequired(), EqualTo('password1')])
    submit = SubmitField(label='Create Account')

class LoginForm(FlaskForm):
    username = StringField(label='Username:', validators=[DataRequired()])
    password = PasswordField(label='Password:', validators=[DataRequired()])
    submit = SubmitField(label='Sign in')
    
# Create Database
with app.app_context():
    db.create_all()

# Routes
@app.route('/home')
def home():
    update_task = None
    update_id = request.args.get('update_id')

    if update_id:
        update_task = Task.query.get(update_id)

    normal_tasks = Task.query.filter_by(task_important=False, user_id=current_user.id).order_by(
        db.case((Task.task_complete == False, 1), (Task.task_complete == True, 2)),
        db.case((Task.task_prior == True, 1), (Task.task_prior == False, 2))
    ).all()

    important_tasks = Task.query.filter_by(task_important=True, user_id=current_user.id).order_by(
        db.case((Task.task_complete == False, 1), (Task.task_complete == True, 2)),
        db.case((Task.task_prior == True, 1), (Task.task_prior == False, 2))
    ).all()

    # Calculate total tasks for the current user
    total_tasks = Task.query.filter_by(user_id=current_user.id).count()

    # Calculate completed tasks for the current user
    complete_task = Task.query.filter_by(task_complete=True, user_id=current_user.id).count()

    return render_template('/Home/home.html', 
                           normal_tasks=normal_tasks, 
                           important_tasks=important_tasks, 
                           total_tasks=total_tasks, 
                           complete_task=complete_task, 
                           update_task=update_task,
                           username=current_user.username)

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    if request.method == 'POST':
        task_title = request.form['task_title']
        task_date = datetime.strptime(request.form['task_date'], "%Y-%m-%d").date()
        task_description = request.form.get('task_description', '')
        task_prior = 'task_prior' in request.form
        task_important = 'task_important' in request.form
        
        new_task = Task(task_title=task_title, task_description=task_description,
                        task_prior=task_prior, task_important=task_important, task_date=task_date,
                        user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()
        flash("Task added successfully!", "success")
    return redirect(url_for('home'))

@app.route('/complete_task/<int:task_id>')
def complete_task(task_id):
    task = Task.query.filter_by(id=task_id).first()
    if task:
        task.task_complete = not task.task_complete  # Toggle completion status
        db.session.commit()
        flash("Task completion status updated!", "success")
    return redirect(request.referrer or url_for('home'))

@app.route('/important_task/<int:task_id>')
def important_task(task_id):
    task = Task.query.filter_by(id=task_id).first()
    if task:
        task.task_important = not task.task_important  # Toggle importance status
        db.session.commit()
        flash("Task importance status updated!", "success")
    return redirect(request.referrer or url_for('home'))

@app.route('/delete_task/<int:task_id>')
def delete_task(task_id):
    task = Task.query.filter_by(id=task_id).first()
    if task:
        db.session.delete(task)
        db.session.commit()
        flash("Task deleted successfully!", "success")
    return redirect(request.referrer or url_for('home'))

@app.route('/prioritize_task/<int:task_id>')
def prioritize_task(task_id):
    task = Task.query.get(task_id)
    if task:
        task.task_prior = not task.task_prior  # Toggle priority status
        db.session.commit()
        flash("Task priority updated!", "success")
    return redirect(request.referrer or url_for('home'))

@app.route('/update_task/<int:task_id>', methods=["POST"])
def update_task(task_id):
    task = Task.query.get(task_id)  # Fetch the task using primary key

    if task:
        task.task_title = request.form['task_title']
        task.task_description = request.form.get('task_description', '')
        task.task_prior = 'task_prior' in request.form
        task.task_important = 'task_important' in request.form
        task.task_date = datetime.strptime(request.form['task_date'], "%Y-%m-%d").date()

        db.session.commit()
        flash("Task updated successfully!", "success")
    else:
        flash("Task not found!", "danger")

    return redirect(url_for('home'))

@app.route('/about')
def about():
    return render_template('/About/about.html', username=current_user.username)
    
@app.route('/tasks')
def tasks():
    normal_tasks = Task.query.filter_by(task_important=False, user_id=current_user.id).order_by(
        db.case((Task.task_complete == False, 1), (Task.task_complete == True, 2)),
        db.case((Task.task_prior == True, 1), (Task.task_prior == False, 2))
    ).all()

    return render_template('/Tasks/tasks.html', normal_tasks=normal_tasks,username=current_user.username)

@app.route('/imptasks')
def imptasks():
    important_tasks = Task.query.filter_by(task_important=True,user_id=current_user.id).order_by(
        db.case((Task.task_complete == False, 1), (Task.task_complete == True, 2)),
        db.case((Task.task_prior == True, 1), (Task.task_prior == False, 2))
    ).all()

    return render_template('/Important/important.html', important_tasks=important_tasks,username=current_user.username)

@app.route('/settings')
def settings():
    return render_template('/settings/setting.html',username=current_user.username)

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form=RegisterForm()
    if form.validate_on_submit():
        user_to_create=User(username=form.username.data,
                            email_address=form.email.data,
                            password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        
        login_user(user_to_create)
        flash(f'Account created successfully! You are now logged in as {user_to_create}', category='success')
        
        return redirect(url_for('home'))
    if form.errors!= {}: #If there are no errors from the validations
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')
        
    return render_template('/login1/aasignup.html',form=form )


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form=LoginForm()
    if form.validate_on_submit():
        attempted_user=User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password_correction(
            form.password.data
        ):
            login_user(attempted_user)
            flash(f'Success! You are logged in as: {attempted_user}', category='success')
            return redirect(url_for('home'))
        else:
            flash('Username and password are not match! Please try again', category='danger')
    return render_template('/login1/aalogin.html',form=form)

@app.route('/logout')
def logout_page():
    logout_user()
    flash('You have been logged out!', category='info')
    return redirect(url_for('home'))    

@app.route('/')
@app.route('/landing')
def landing():
    return render_template('/landing/landing.html')

if __name__ == '__main__':
    app.run(debug=True)
