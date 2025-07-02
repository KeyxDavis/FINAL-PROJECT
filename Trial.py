
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mentorship.db'
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change to a secure key in production

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Roles
ROLE_ADMIN = 'admin'
ROLE_MENTOR = 'mentor'
ROLE_MENTEE = 'mentee'


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    profile = db.relationship('Profile', backref='user', uselist=False)
    availability = db.relationship('Availability', backref='mentor', lazy=True)


class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    skills = db.Column(db.String(200), nullable=True)  # Comma separated
    goals = db.Column(db.String(200), nullable=True)   # Comma separated


class MentorshipRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mentee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mentor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='PENDING')  # PENDING, ACCEPTED, REJECTED


class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mentorship_request_id = db.Column(db.Integer, db.ForeignKey('mentorship_request.id'), nullable=False)
    scheduled_time = db.Column(db.DateTime, nullable=False)
    feedback_mentee = db.Column(db.Text, nullable=True)
    feedback_mentor = db.Column(db.Text, nullable=True)
    rating = db.Column(db.Integer, nullable=True)  # 1-5 stars


class Availability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day_of_week = db.Column(db.String(10), nullable=False)  # e.g., "Monday"
    start_time = db.Column(db.String(5), nullable=False)   # e.g., "15:00"
    end_time = db.Column(db.String(5), nullable=False)     # e.g., "17:00"


# Initialize DB
with app.app_context():
    db.create_all()


# Helper: role required decorator
def role_required(*roles):
    def wrapper(fn):
        @jwt_required()
        def decorator(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if user.role not in roles:
                return jsonify({'msg': 'Access forbidden: insufficient permissions'}), 403
            return fn(*args, **kwargs)
        decorator.__name__ = fn.__name__
        return decorator
    return wrapper


# Authentication Endpoints

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    if role not in [ROLE_ADMIN, ROLE_MENTOR, ROLE_MENTEE]:
        return jsonify({'msg': 'Invalid role'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'msg': 'Email already registered'}), 400

    password_hash = generate_password_hash(password)
    user = User(email=email, password_hash=password_hash, role=role)
    db.session.add(user)
    db.session.commit()
    return jsonify({'msg': 'User registered successfully'}), 201


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'msg': 'Bad email or password'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({'access_token': access_token, 'role': user.role}), 200


@app.route('/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    # Optional: implement token revocation if needed
    return jsonify({'msg': 'Logout successful'}), 200


@app.route('/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'msg': 'User not found'}), 404
    return jsonify({
        'id': user.id,
        'email': user.email,
        'role': user.role
    })


# User Profile Endpoints

@app.route('/users/me', methods=['GET'])
@jwt_required()
def get_my_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'msg': 'User not found'}), 404
    profile = user.profile
    return jsonify({
        'email': user.email,
        'role': user.role,
        'profile': {
            'name': profile.name if profile else None,
            'bio': profile.bio if profile else None,
            'skills': profile.skills.split(',') if profile and profile.skills else [],
            'goals': profile.goals.split(',') if profile and profile.goals else []
        }
    })


@app.route('/users/me/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'msg': 'User not found'}), 404
    data = request.json
    if not user.profile:
        user.profile = Profile(user_id=user.id)
    user.profile.name = data.get('name', user.profile.name)
    user.profile.bio = data.get('bio', user.profile.bio)
    user.profile.skills = ','.join(data.get('skills', user.profile.skills.split(',') if user.profile.skills else []))
    user.profile.goals = ','.join(data.get('goals', user.profile.goals.split(',') if user.profile.goals else []))
    db.session.commit()
    return jsonify({'msg': 'Profile updated successfully'})


@app.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_profile(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'msg': 'User not found'}), 404
    profile = user.profile
    return jsonify({
        'id': user.id,
        'email': user.email,
        'role': user.role,
        'profile': {
            'name': profile.name if profile else None,
            'bio': profile.bio if profile else None,
            'skills': profile.skills.split(',') if profile and profile.skills else [],
            'goals': profile.goals.split(',') if profile and profile.goals else []
        }
    })


# Mentor Discovery and Matching

@app.route('/mentors', methods=['GET'])
@jwt_required()
def list_mentors():
    skill_filter = request.args.get('skill')
    # Optional: industry filter can be added similarly
    query = User.query.filter_by(role=ROLE_MENTOR)
    if skill_filter:
        query = query.join(Profile).filter(Profile.skills.like(f'%{skill_filter}%'))
    mentors = query.all()
    result = []
    for mentor in mentors:
        profile = mentor.profile
        result.append({
            'id': mentor.id,
            'name': profile.name if profile else None,
            'bio': profile.bio if profile else None,
            'skills': profile.skills.split(',') if profile and profile.skills else [],
            'goals': profile.goals.split(',') if profile and profile.goals else []
        })
    return jsonify(result)


@app.route('/requests', methods=['POST'])
@role_required(ROLE_MENTEE)
def send_mentorship_request():
    user_id = get_jwt_identity()
    data = request.json
    mentor_id = data.get('mentor_id')
    if not User.query.filter_by(id=mentor_id, role=ROLE_MENTOR).first():
        return jsonify({'msg': 'Mentor not found'}), 404
    existing_request = MentorshipRequest.query.filter_by(mentee_id=user_id, mentor_id=mentor_id).first()
    if existing_request:
        return jsonify({'msg': 'Request already sent'}), 400
    req = MentorshipRequest(mentee_id=user_id, mentor_id=mentor_id, status='PENDING')
    db.session.add(req)
    db.session.commit()
    return jsonify({'msg': 'Request sent successfully'}), 201


@app.route('/requests/sent', methods=['GET'])
@role_required(ROLE_MENTEE)
def get_sent_requests():
    user_id = get_jwt_identity()
    requests = MentorshipRequest.query.filter_by(mentee_id=user_id).all()
    return jsonify([{'id': r.id, 'mentor_id': r.mentor_id, 'status': r.status} for r in requests])


@app.route('/requests/received', methods=['GET'])
@role_required(ROLE_MENTOR)
def get_received_requests():
    user_id = get_jwt_identity()
    requests = MentorshipRequest.query.filter_by(mentor_id=user_id).all()
    return jsonify([{'id': r.id, 'mentee_id': r.mentee_id, 'status': r.status} for r in requests])


@app.route('/requests/<int:req_id>', methods=['PUT'])
@role_required(ROLE_MENTOR)
def update_request_status(req_id):
    user_id = get_jwt_identity()
    req = MentorshipRequest.query.get(req_id)
    if not req or req.mentor_id != user_id:
        return jsonify({'msg': 'Request not found'}), 404
    data = request.json
    status = data.get('status')
    if status not in ['ACCEPTED', 'REJECTED']:
        return jsonify({'msg': 'Invalid status'}), 400
    req.status = status
    db.session.commit()
    return jsonify({'msg': 'Request status updated'})


# Availability and Session Booking

@app.route('/availability', methods=['POST'])
@role_required(ROLE_MENTOR)
def set_availability():
    user_id = get_jwt_identity()
    data = request.json
    day_of_week = data.get('day_of_week')
    start_time = data.get('start_time')  # format "HH:MM"
    end_time = data.get('end_time')      # format "HH:MM"

    if not all([day_of_week, start_time, end_time]):
        return jsonify({'msg': 'Missing availability data'}), 400

    # Optionally validate time formats here

    availability = Availability(
        mentor_id=user_id,
        day_of_week=day_of_week,
        start_time=start_time,
        end_time=end_time
    )
    db.session.add(availability)
    db.session.commit()
    return jsonify({'msg': 'Availability set successfully'}), 201


@app.route('/availability', methods=['GET'])
@role_required(ROLE_MENTOR)
def get_availability():
    user_id = get_jwt_identity()
    slots = Availability.query.filter_by(mentor_id=user_id).all()
    return jsonify([{
        'id': slot.id,
        'day_of_week': slot.day_of_week,
        'start_time': slot.start_time,
        'end_time': slot.end_time
    } for slot in slots])


@app.route('/sessions', methods=['POST'])
@jwt_required()
def schedule_session():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.json
    req_id = data.get('mentorship_request_id')
    scheduled_time_str = data.get('scheduled_time')

    try:
        scheduled_time = datetime.fromisoformat(scheduled_time_str)
    except Exception:
        return jsonify({'msg': 'Invalid datetime format'}), 400

    req = MentorshipRequest.query.get(req_id)
    if not req or req.status != 'ACCEPTED':
        return jsonify({'msg': 'Mentorship request not accepted'}), 400

    if user.id not in [req.mentee_id, req.mentor_id]:
        return jsonify({'msg': 'Not authorized for this session'}), 403

    session = Session(mentorship_request_id=req_id, scheduled_time=scheduled_time)
    db.session.add(session)
    db.session.commit()
    return jsonify({'msg': 'Session scheduled successfully'}), 201


@app.route('/sessions/mentor', methods=['GET'])
@role_required(ROLE_MENTOR)
def get_sessions_mentor():
    user_id = get_jwt_identity()
    sessions = Session.query.join(MentorshipRequest).filter(MentorshipRequest.mentor_id == user_id).all()
    return jsonify([{
        'id': s.id,
        'scheduled_time': s.scheduled_time.isoformat(),
        'mentorship_request_id': s.mentorship_request_id,
        'feedback_mentee': s.feedback_mentee,
        'feedback_mentor': s.feedback_mentor,
        'rating': s.rating
    } for s in sessions])


@app.route('/sessions/mentee', methods=['GET'])
@role_required(ROLE_MENTEE)
def get_sessions_mentee():
    user_id = get_jwt_identity()
    sessions = Session.query.join(MentorshipRequest).filter(MentorshipRequest.mentee_id == user_id).all()
    return jsonify([{
        'id': s.id,
        'scheduled_time': s.scheduled_time.isoformat(),
        'mentorship_request_id': s.mentorship_request_id,
        'feedback_mentee': s.feedback_mentee,
        'feedback_mentor': s.feedback_mentor,
        'rating': s.rating
    } for s in sessions])


# Session Feedback

@app.route('/sessions/<int:session_id>/feedback', methods=['PUT'])
@jwt_required()
def submit_feedback(session_id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    session = Session.query.get(session_id)
    if not session:
        return jsonify({'msg': 'Session not found'}), 404
    req = MentorshipRequest.query.get(session.mentorship_request_id)
    if user.id not in [req.mentee_id, req.mentor_id]:
        return jsonify({'msg': 'Not authorized for this session'}), 403
    data = request.json
    if user.id == req.mentee_id:
        rating = data.get('rating')
        if rating is not None and (rating < 1 or rating > 5):
            return jsonify({'msg': 'Rating must be between 1 and 5'}), 400
        session.rating = rating if rating is not None else session.rating
        session.feedback_mentee = data.get('comment', session.feedback_mentee)
    elif user.id == req.mentor_id:
        session.feedback_mentor = data.get('comment', session.feedback_mentor)
    db.session.commit()
    return jsonify({'msg': 'Feedback submitted successfully'})


# Admin Dashboard Endpoints

@app.route('/admin/users', methods=['GET'])
@role_required(ROLE_ADMIN)
def admin_list_users():
    users = User.query.all()
    return jsonify([{'id': u.id, 'email': u.email, 'role': u.role} for u in users])


@app.route('/admin/users/<int:user_id>/role', methods=['PUT'])
@role_required(ROLE_ADMIN)
def admin_update_user_role(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'msg': 'User not found'}), 404
    data = request.json
    new_role = data.get('role')
    if new_role not in [ROLE_ADMIN, ROLE_MENTOR, ROLE_MENTEE]:
        return jsonify({'msg': 'Invalid role'}), 400
    user.role = new_role
    db.session.commit()
    return jsonify({'msg': 'User role updated successfully'})


@app.route('/admin/matches', methods=['GET'])
@role_required(ROLE_ADMIN)
def admin_view_matches():
    matches = MentorshipRequest.query.all()
    return jsonify([{
        'id': m.id,
        'mentee_id': m.mentee_id,
        'mentor_id': m.mentor_id,
        'status': m.status
    } for m in matches])


@app.route('/admin/sessions', methods=['GET'])
@role_required(ROLE_ADMIN)
def admin_view_sessions():
    sessions = Session.query.all()
    return jsonify([{
        'id': s.id,
        'mentorship_request_id': s.mentorship_request_id,
        'scheduled_time': s.scheduled_time.isoformat(),
        'feedback_mentee': s.feedback_mentee,
        'feedback_mentor': s.feedback_mentor,
        'rating': s.rating
    } for s in sessions])

@app.route("/")
def home():
    return "Welcome to the Final Project API!"

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
# Note: In production, set debug=False and use a proper WSGI server
