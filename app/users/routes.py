from flask import render_template
from . import user_bp

@user_bp.route('profile')
def profile():
    return render_template('user/profile.html')

@user_bp.route('edit-profile')
def edit_profile():
    return render_template('user/edit_profile.html')
