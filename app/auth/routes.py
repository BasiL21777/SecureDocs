from flask import Blueprint,render_template,request,redirect,url_for,flash
from flask_login import login_user ,logout_user,login_required
from app.models.user  import User
from app import db
auth_bp=Blueprint('auth',__name__,template_folder='templates/auth')

@auth_bp.route('/register',methods=['POST','GET'])
def register():
    if request.method=="POST":
        username=request.form['username']
        email=request.form['email']
        password=request.form['password']
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or Email is Already Exist !!','error')
            return redirect(url_for('auth.register'))
        user=User(username=username,email=email,role='User')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Register Successfully , You Can Login Now','success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html')

@auth_bp.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form['username']
        password=request.form['password']
        user=User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('documents.upload'))
        flash('Invalid Credentials','error')
        return redirect(url_for('auth.login'))
    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
