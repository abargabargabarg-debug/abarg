import os
import logging
from functools import wraps
from datetime import datetime

from flask import Flask, render_template, request, redirect, session, jsonify, url_for, flash, abort
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy import func, or_, and_

# Local imports
from db import db, User, Group, GroupMember, Message, UserSetting

# ==============================================================================
# CONFIGURATION & SETUP
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler("system_logs.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AbargNetwork")

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///abarg_network.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ==============================================================================
# HELPER DECORATORS
# ==============================================================================

def god_required(f):
    """Decorator to ensure user is a GOD (Admin)."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_god:
            logger.critical(
                f"God access attempt by User ID: {current_user.id if current_user.is_authenticated else 'Anonymous'}")
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


# ==============================================================================
# PUBLIC ROUTES
# ==============================================================================

@app.route('/')
def welcome():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('welcome.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        if not username or not email or not password:
            flash('All fields are required')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('signup'))

        # Create new user (pending approval)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            is_god=False,
            is_approved=False
        )

        db.session.add(new_user)
        db.session.commit()

        logger.info(f"New user registered: {username} - Pending approval")

        # Store email in session for status check (secure)
        session['pending_email'] = email
        return redirect(url_for('check_status'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            if not user.is_approved:
                # Store email in session and redirect to status
                session['pending_email'] = email
                flash('Your account is pending approval')
                return redirect(url_for('check_status'))

            login_user(user)
            logger.info(f"User logged in: {email}")
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Failed login attempt for {email}")
            flash('Invalid credentials')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/status')
def check_status():
    """Visual status page for approval tracking - email hidden from URL."""
    # Get email from session (not URL parameter)
    email = session.get('pending_email')

    if not email:
        flash("Please login or signup first", "warning")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()

    if not user:
        session.pop('pending_email', None)
        flash("No account found. Please signup.", "error")
        return redirect(url_for('signup'))

    if user.is_approved:
        session.pop('pending_email', None)
        flash("Your account is approved! Please login.", "success")
        return redirect(url_for('login'))

    return render_template(
        'status.html',
        email=email,
        sigma=user.sigma_approved,
        alpha=user.alpha_approved,
        satpura=user.satpura_approved
    )


@app.route('/finalize_account', methods=['POST'])
def finalize_account():
    """Final step: Activate fully approved account."""
    email = session.get('pending_email')

    if not email:
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()

    if user and user.sigma_approved and user.alpha_approved and user.satpura_approved:
        user.is_approved = True
        db.session.commit()

        logger.info(f"Account activated: {user.username}")
        session.pop('pending_email', None)
        flash("Account activated! You can now login.", "success")
        return redirect(url_for('login'))

    return "Error: Account not ready", 400


@app.route('/logout')
@login_required
def logout():
    logger.info(f"User logged out: {current_user.username}")
    logout_user()
    return redirect(url_for('login'))


# ==============================================================================
# DASHBOARD & CHAT
# ==============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """Main chat interface."""
    # Get all approved users except current user
    users = User.query.filter(
        User.id != current_user.id,
        User.is_approved == True
    ).all()

    # Get groups where current user is a member
    groups = db.session.query(
        Group.id,
        Group.name,
        func.count(GroupMember.id).label('member_count')
    ).join(GroupMember, GroupMember.group_id == Group.id) \
        .filter(GroupMember.user_id == current_user.id) \
        .group_by(Group.id, Group.name).all()

    groups_list = [{
        'id': g.id,
        'name': g.name,
        'member_count': g.member_count
    } for g in groups]

    # God mode data
    pending_users = []
    total_users = 0
    total_groups = 0

    if current_user.is_god:
        pending_users = User.query.filter_by(is_approved=False).all()
        total_users = User.query.filter_by(is_approved=True).count()
        total_groups = Group.query.count()

    return render_template(
        'dashboard.html',
        username=current_user.username,
        users=users,
        groups=groups_list,
        is_god=current_user.is_god,
        god_role=current_user.god_role,
        pending_users=pending_users,
        total_users=total_users,
        total_groups=total_groups
    )


# ==============================================================================
# GOD MODE (ADMIN) ROUTES
# ==============================================================================

@app.route('/approve/<int:user_id>')
@login_required
@god_required
def approve_user(user_id):
    """Approve a pending user based on god role."""
    user = User.query.get(user_id)
    if not user:
        flash('User not found')
        return redirect(url_for('dashboard'))

    # Set approval based on god role
    if current_user.god_role == 'SIGMA':
        user.sigma_approved = True
    elif current_user.god_role == 'ALPHA':
        user.alpha_approved = True
    elif current_user.god_role == 'SATPURA':
        user.satpura_approved = True

    # Check if all approvals are done
    if user.sigma_approved and user.alpha_approved and user.satpura_approved:
        user.is_approved = True

    db.session.commit()
    logger.info(f"{current_user.god_role} approved user {user.username}")
    flash(f'User {user.username} approved')
    return redirect(url_for('dashboard'))


@app.route('/create_group', methods=['POST'])
@login_required
@god_required
def create_group():
    """Create a new group with multiple members - creator is auto-included."""
    try:
        group_name = request.form.get('group_name', '').strip()
        member_ids_str = request.form.get('member_ids', '').strip()

        if not group_name:
            return jsonify({'success': False, 'message': 'Group name required'}), 400

        # Create the group
        new_group = Group(name=group_name, created_by=current_user.id)
        db.session.add(new_group)
        db.session.flush()  # Get the group ID

        # ALWAYS add the creator as a member first
        creator_member = GroupMember(group_id=new_group.id, user_id=current_user.id)
        db.session.add(creator_member)

        # Add additional members (if any)
        added_members = [current_user.id]  # Track to avoid duplicates

        if member_ids_str:
            for user_id_str in member_ids_str.split(','):
                user_id_str = user_id_str.strip()
                if user_id_str:
                    try:
                        user_id = int(user_id_str)
                        # Don't add creator again
                        if user_id not in added_members:
                            member = GroupMember(group_id=new_group.id, user_id=user_id)
                            db.session.add(member)
                            added_members.append(user_id)
                    except ValueError:
                        logger.warning(f"Invalid user ID: {user_id_str}")

        db.session.commit()
        logger.info(f"Group '{group_name}' created by {current_user.username} with {len(added_members)} members")

        return jsonify({
            'success': True,
            'message': f'Group created with {len(added_members)} members',
            'reload': True
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating group: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/add_members', methods=['POST'])
@login_required
@god_required
def add_members():
    """Add multiple members to existing group - prevents duplicates."""
    try:
        group_id_str = request.form.get('group_id', '').strip()
        member_ids_str = request.form.get('member_ids', '').strip()

        if not group_id_str or not member_ids_str:
            return jsonify({'success': False, 'message': 'Missing parameters'}), 400

        group_id = int(group_id_str)

        # Verify group exists
        group = Group.query.get(group_id)
        if not group:
            return jsonify({'success': False, 'message': 'Group not found'}), 404

        # Get existing members
        existing_member_ids = {
            m.user_id for m in GroupMember.query.filter_by(group_id=group_id).all()
        }

        # Add new members
        added_count = 0
        skipped_count = 0

        for user_id_str in member_ids_str.split(','):
            user_id_str = user_id_str.strip()
            if user_id_str:
                try:
                    user_id = int(user_id_str)

                    # Check if already a member
                    if user_id in existing_member_ids:
                        skipped_count += 1
                        logger.info(f"User {user_id} already in group {group_id}, skipping")
                        continue

                    # Verify user exists
                    user = User.query.get(user_id)
                    if not user:
                        logger.warning(f"User {user_id} not found, skipping")
                        continue

                    # Add member
                    member = GroupMember(group_id=group_id, user_id=user_id)
                    db.session.add(member)
                    existing_member_ids.add(user_id)  # Update tracking set
                    added_count += 1

                except ValueError:
                    logger.warning(f"Invalid user ID: {user_id_str}")

        db.session.commit()

        message = f'Added {added_count} member(s)'
        if skipped_count > 0:
            message += f', skipped {skipped_count} (already members)'

        logger.info(f"Members added to group {group_id}: {added_count} added, {skipped_count} skipped")

        return jsonify({
            'success': True,
            'message': message,
            'reload': True
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding members: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


@app.route('/get_group_members/<int:group_id>')
@login_required
def get_group_members(group_id):
    """Get all members of a group - only if user is member or god."""
    try:
        # Check if user has access to this group
        is_member = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()

        if not is_member and not current_user.is_god:
            return jsonify({'error': 'Unauthorized'}), 403

        # Get all members
        members = db.session.query(User).join(
            GroupMember, GroupMember.user_id == User.id
        ).filter(GroupMember.group_id == group_id).all()

        return jsonify({
            'members': [{'id': m.id, 'username': m.username} for m in members],
            'count': len(members)
        })

    except Exception as e:
        logger.error(f"Error getting group members: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/get_available_users/<int:group_id>')
@login_required
@god_required
def get_available_users(group_id):
    """Get users NOT in the group - for adding members."""
    try:
        # Get existing member IDs
        existing_member_ids = {
            m.user_id for m in GroupMember.query.filter_by(group_id=group_id).all()
        }

        # Get all approved users not in the group
        available_users = User.query.filter(
            User.is_approved == True,
            ~User.id.in_(existing_member_ids)
        ).all()

        return jsonify({
            'users': [{'id': u.id, 'username': u.username} for u in available_users]
        })

    except Exception as e:
        logger.error(f"Error getting available users: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/get_messages/<chat_type>/<int:chat_id>')
@login_required
def get_messages(chat_type, chat_id):
    """Load previous messages for a chat."""
    try:
        if chat_type == 'user':
            # Direct messages between two users
            messages = Message.query.filter(
                or_(
                    and_(Message.sender_id == current_user.id, Message.recipient_id == chat_id),
                    and_(Message.sender_id == chat_id, Message.recipient_id == current_user.id)
                ),
                Message.group_id == None
            ).order_by(Message.timestamp.asc()).all()

        elif chat_type == 'group':
            # Verify user is member of this group
            is_member = GroupMember.query.filter_by(
                group_id=chat_id,
                user_id=current_user.id
            ).first()

            if not is_member:
                return jsonify({'error': 'You are not a member of this group'}), 403

            # Get all group messages
            messages = Message.query.filter_by(
                group_id=chat_id,
                recipient_id=None
            ).order_by(Message.timestamp.asc()).all()

        else:
            return jsonify({'error': 'Invalid chat type'}), 400

        return jsonify({
            'messages': [{
                'sender': msg.sender.username,
                'content': msg.content,
                'timestamp': msg.timestamp.strftime('%H:%M'),
                'is_me': msg.sender_id == current_user.id
            } for msg in messages]
        })

    except Exception as e:
        logger.error(f"Error loading messages: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to load messages'}), 500


# ==============================================================================
# SETTINGS ROUTES
# ==============================================================================

@app.route('/update_setting', methods=['POST'])
@login_required
def update_setting():
    """Update user settings."""
    data = request.get_json()
    key = data.get('key')
    value = data.get('value')

    setting = UserSetting.query.filter_by(
        user_id=current_user.id,
        key=key
    ).first()

    if setting:
        setting.value = str(value)
    else:
        setting = UserSetting(user_id=current_user.id, key=key, value=str(value))
        db.session.add(setting)

    db.session.commit()
    return jsonify({'success': True})


@app.route('/get_settings')
@login_required
def get_settings():
    """Get all user settings."""
    settings = UserSetting.query.filter_by(user_id=current_user.id).all()
    return jsonify({s.key: s.value == 'True' for s in settings})


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user password."""
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not bcrypt.check_password_hash(current_user.password_hash, current_password):
        return jsonify({'success': False, 'message': 'Current password incorrect'})

    current_user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.session.commit()

    logger.info(f"Password changed for user: {current_user.username}")
    return jsonify({'success': True})


# ==============================================================================
# SOCKET.IO EVENTS
# ==============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle socket connection."""
    if current_user.is_authenticated:
        logger.info(f"Socket connected: {current_user.username}")


@socketio.on('join_chat')
def handle_join(data):
    """User joins a chat room."""
    try:
        chat_type = data.get('type')
        chat_id = data.get('id')

        # Security check for group chats
        if chat_type == 'group':
            is_member = GroupMember.query.filter_by(
                group_id=chat_id,
                user_id=current_user.id
            ).first()

            if not is_member:
                emit('error', {'message': 'You are not a member of this group'})
                logger.warning(f"{current_user.username} attempted to join group {chat_id} without membership")
                return

        room = f"{chat_type}_{chat_id}"
        join_room(room)
        logger.info(f"{current_user.username} joined {room}")

    except Exception as e:
        logger.error(f"Error joining chat: {str(e)}", exc_info=True)
        emit('error', {'message': 'Failed to join chat'})


@socketio.on('send_message')
def handle_message(data):
    """Handle incoming message and broadcast."""
    try:
        msg = data.get('msg', '').strip()
        group_id = data.get('group_id')
        recipient_id = data.get('recipient_id')

        if not msg:
            return

        # Security check for group messages
        if group_id:
            is_member = GroupMember.query.filter_by(
                group_id=group_id,
                user_id=current_user.id
            ).first()

            if not is_member:
                emit('error', {'message': 'Unauthorized'})
                logger.warning(
                    f"{current_user.username} attempted to send message to group {group_id} without membership")
                return

        # Save to database
        new_message = Message(
            sender_id=current_user.id,
            content=msg,
            group_id=group_id if group_id else None,
            recipient_id=recipient_id if recipient_id else None
        )
        db.session.add(new_message)
        db.session.commit()

        # Determine room
        if group_id:
            room = f"group_{group_id}"
        else:
            room = f"user_{recipient_id}"

        # Broadcast message to room (including sender)
        emit('receive_message', {
            'sender': current_user.username,
            'msg': msg,
            'timestamp': datetime.now().strftime('%H:%M')
        }, room=room, include_self=True)

        logger.info(f"Message sent by {current_user.username} to {room}")

    except Exception as e:
        logger.error(f"Error sending message: {str(e)}", exc_info=True)
        emit('error', {'message': 'Failed to send message'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle socket disconnection."""
    if current_user.is_authenticated:
        logger.info(f"Socket disconnected: {current_user.username}")


# ==============================================================================
# INITIALIZATION
# ==============================================================================

with app.app_context():
    db.create_all()

    # Create god users if they don't exist
    gods = [
        {'username': 'sigma', 'email': 'sigma@abarg.com', 'role': 'SIGMA'},
        {'username': 'alpha', 'email': 'alpha@abarg.com', 'role': 'ALPHA'},
        {'username': 'satpura', 'email': 'satpura@abarg.com', 'role': 'SATPURA'}
    ]

    for god in gods:
        if not User.query.filter_by(username=god['username']).first():
            hashed_pw = bcrypt.generate_password_hash('admin123').decode('utf-8')
            god_user = User(
                username=god['username'],
                email=god['email'],
                password_hash=hashed_pw,
                is_god=True,
                god_role=god['role'],
                is_approved=True,
                sigma_approved=True,
                alpha_approved=True,
                satpura_approved=True
            )
            db.session.add(god_user)

    db.session.commit()
    logger.info("Database initialized successfully")

if __name__ == '__main__':
    print("=== ABARG NETWORK INITIALIZING ===")
    print("=== God Accounts: sigma, alpha, satpura (password: admin123) ===")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
