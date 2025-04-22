from flask import Flask, render_template, session, request, redirect
from datetime import datetime
import os
import secrets
from werkzeug.utils import secure_filename
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = 'static/images/projects'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

#app.config['UPLOAD_FOLDER'] = 'path/to/your/upload/directory'
#app.config['STATIC_FOLDER'] = 'path/to/your/static/directory'
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'devsearch_db'
}


def get_db_connection():
    db_host = os.environ.get('CLOUD_SQL_HOST')
    db_user = os.environ.get('CLOUD_SQL_USER')
    db_password = os.environ.get('CLOUD_SQL_PASSWORD')
    db_name = os.environ.get('CLOUD_SQL_DATABASE')

    try:
        conn = mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None




def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


@app.before_request
def csrf_protect():
    if request.method == 'POST':
        token = session.pop('csrf_token', None)
        if not token or token != request.form.get('csrf_token'):
            return 'CSRF token is missing or invalid.', 400


@app.route('/')
def home():
    query = request.args.get('q')
    db_conn = get_db_connection()
    projects = []
    if db_conn:
        cursor = db_conn.cursor(dictionary=True)
        try:
            if query:
                search_term = f"%{query}%"
                cursor.execute("""
                        SELECT  p.project_id, p.title, p.description, p.demo_link, p.source_link, p.featured_image, u.username
                        FROM Projects p 
                        JOIN Profiles prof ON p.developer_id = prof.profile_id
                        JOIN Users u ON prof.user_id = u.user_id
                        WHERE
                        p.title LIKE %s OR
                        p.description LIKE %s OR
                        u.username LIKE %s OR
                        p.project_id IN (SELECT pt.project_id FROM ProjectTags pt JOIN Tags t ON pt.tag_id = t.tag_id WHERE t.name LIKE %s)
                        ORDER BY p.created_at DESC
                    """, (search_term, search_term, search_term, search_term))
                projects = cursor.fetchall()
            else:
                cursor.execute("""
                        SELECT p.project_id, p.title, p.description, p.demo_link, p.source_link, p.featured_image, u.username
                        FROM Projects p
                        JOIN Profiles prof ON p.developer_id = prof.profile_id
                        JOIN Users u ON prof.user_id = u.user_id
                        ORDER BY p.created_at DESC
                    """)
                projects = cursor.fetchall()
            for project in projects:
                # Fetch tags
                cursor.execute("""
                                   SELECT t.name
                                   FROM Tags t
                                   JOIN ProjectTags pt ON t.tag_id = pt.tag_id
                                   WHERE pt.project_id = %s
                               """, (project['project_id'],))
                project['tags'] = cursor.fetchall()
            cursor.close()
            db_conn.close()
        except mysql.connector.Error as err:
            print(f"MySQL Error fetching projects: {err}")
    return render_template('devsearch_home.html', latest_projects=projects, query=query)


@app.route('/search')
def search_projects():
    query = request.args.get('q')
    results = []
    if query:
        db_conn = get_db_connection()
        if db_conn:
            cursor = db_conn.cursor(dictionary=True)
            try:
                search_term = f"%{query}%"
                cursor.execute("""
                    SELECT p.project_id, p.title, p.description, p.demo_link, p.source_link, p.featured_image, u.username
                    FROM Projects p
                    JOIN Profiles prof ON p.developer_id = prof.profile_id
                    JOIN Users u ON prof.user_id = u.user_id
                    WHERE p.title LIKE %s OR p.description LIKE %s OR u.username LIKE %s
                    ORDER BY p.created_at DESC
                """, (search_term, search_term, search_term))
                results = cursor.fetchall()
                cursor.close()
                db_conn.close()
            except mysql.connector.Error as err:
                print(f"MySQL Error during search: {err}")
        return render_template('search_results.html', query=query, results=results)
    else:
        return redirect('/')


def is_logged_in():
    """Checks if a user is currently logged in based on the session."""
    return 'user_id' in session


@app.route('/login', methods=['GET', 'POST'])
def login():
    csrf_token = generate_csrf_token()
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db_conn = get_db_connection()
        if db_conn:
            cursor = db_conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT user_id, username, password_hash FROM Users WHERE username = %s", (username,))
                user = cursor.fetchone()
                cursor.close()
                db_conn.close()

                if user and check_password_hash(user['password_hash'], password):
                    session['user_id'] = user['user_id']
                    session['username'] = user['username']
                    return redirect('/')  # Redirect to homepage on successful login
                else:
                    error = "Invalid username or password."
            except mysql.connector.Error as err:
                print(f"MySQL Error: {err}")
                error = "Login failed. Please try again later."
                if db_conn.is_connected():
                    cursor.close()
                    db_conn.close()

    return render_template('login.html', error=error, csrf_token=csrf_token)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    csrf_token = generate_csrf_token()
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            error = "All fields are required."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif len(password) < 6:
            error = "Password must be at least 6 characters long."
        elif not '@' in email:
            error = "Invalid email format."
        else:
            db_conn = get_db_connection()
            if db_conn:
                cursor = db_conn.cursor()
                try:
                    # Check if username or email already exists
                    cursor.execute("SELECT user_id FROM Users WHERE username = %s OR email = %s", (username, email))
                    existing_user = cursor.fetchone()
                    if existing_user:
                        error = "Username or email already exists."
                    else:
                        # Hash the password
                        hashed_password = generate_password_hash(password)

                        # Insert into Users table
                        cursor.execute("INSERT INTO Users (username, email, password_hash) VALUES (%s, %s, %s)",
                                       (username, email, hashed_password))
                        user_id = cursor.lastrowid

                        # Insert into Profiles table
                        cursor.execute("INSERT INTO Profiles (user_id) VALUES (%s)", (user_id,))

                        db_conn.commit()
                        cursor.close()
                        db_conn.close()

                        session['user_id'] = user_id
                        session['username'] = username
                        return redirect('/')  # Redirect to homepage after successful registration
                except mysql.connector.Error as err:
                    print(f"MySQL Error: {err}")
                    error = "Registration failed. Please try again later."
                    db_conn.rollback()
                finally:
                    if db_conn.is_connected():
                        cursor.close()
                        db_conn.close()

    return render_template('signup.html', error=error, csrf_token=csrf_token)


@app.route('/signout')
def signout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect('/')

@app.route('/profile')
def profile():
    if 'user_id' in session:
        user_id = session['user_id']
        db_conn = get_db_connection()
        if db_conn:
            cursor = db_conn.cursor(dictionary=True)
            try:
                # Fetch user information
                cursor.execute("""
                    SELECT u.username, u.email, p.bio, p.location
                    FROM Users u
                    LEFT JOIN Profiles p ON u.user_id = p.user_id
                    WHERE u.user_id = %s
                """, (user_id,))
                user_data = cursor.fetchone()
                # Ensure you've read the result
                if not user_data:
                    user_data = {}  # Handle case where no user data is found

                # Fetch the user's skills
                cursor.execute("""
                    SELECT s.name
                    FROM Skills s
                    JOIN ProfileSkills ps ON s.skill_id = ps.skill_id
                    JOIN Profiles p ON ps.profile_id = p.profile_id
                    WHERE p.user_id = %s
                    ORDER BY s.name
                """, (user_id,))
                user_skills = cursor.fetchall()
                # Ensure you've read these results as well (fetchall does this)

                cursor.close()
                db_conn.close()

                if user_data:
                    return render_template('profile.html', user=user_data, user_skills=user_skills)
                else:
                    return "Error: Could not retrieve profile information.", 404
            except mysql.connector.Error as err:
                print(f"MySQL Error: {err}")
                if db_conn.is_connected():
                    cursor.close()
                    db_conn.close()
                return "Error: Could not retrieve profile information.", 500
        else:
            return "Error: Could not connect to the database.", 500
    else:
        return redirect('/login')

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    error = None
    db_conn = get_db_connection()
    available_skills = []
    user_skills = []
    profile_data = {} # Initialize profile_data
    profile_id = None

    if db_conn:
        cursor = db_conn.cursor(dictionary=True)
        try:
            # Fetch the user's profile ID
            cursor.execute("SELECT profile_id FROM Profiles WHERE user_id = %s", (user_id,))
            profile_result = cursor.fetchone()
            if profile_result:
                profile_id = profile_result['profile_id']

                # Fetch all available skills for the checkboxes
                cursor.execute("SELECT skill_id, name FROM Skills ORDER BY name")
                available_skills = cursor.fetchall()

                # Fetch the user's current skills for pre-checking
                cursor.execute("""
                    SELECT s.skill_id
                    FROM Skills s
                    JOIN ProfileSkills ps ON s.skill_id = ps.skill_id
                    WHERE ps.profile_id = %s
                """, (profile_id,))
                user_skills = [skill['skill_id'] for skill in cursor.fetchall()]

                # Fetch basic profile data (including email from Users table)
                cursor.execute("""
                    SELECT p.bio, p.location, u.email
                    FROM Profiles p
                    JOIN Users u ON p.user_id = u.user_id
                    WHERE p.user_id = %s
                """, (user_id,))
                profile_data = cursor.fetchone()
            else:
                available_skills = []
                user_skills = []
                error = "Profile not found."

        except mysql.connector.Error as err:
            print(f"MySQL Error fetching profile data or skills: {err}")
            available_skills = []
            user_skills = []
            if db_conn.is_connected():
                cursor.close()
                db_conn.close()
    else:
        available_skills = []
        user_skills = []
        error = "Could not connect to the database."

    if request.method == 'POST':
        bio = request.form.get('bio')
        location = request.form.get('location')
        email = request.form.get('email')
        selected_skills = request.form.getlist('skills') # Get list of selected skill IDs

        if db_conn and profile_id:
            cursor = db_conn.cursor()
            try:
                # Update basic profile information
                cursor.execute("""
                    UPDATE Profiles
                    SET bio = %s, location = %s
                    WHERE profile_id = %s
                """, (bio, location, profile_id))

                # Update user email
                cursor.execute("""
                    UPDATE Users
                    SET email = %s
                    WHERE user_id = %s
                """, (email, user_id))

                # Clear existing skills for the user's profile
                cursor.execute("""
                    DELETE FROM ProfileSkills
                    WHERE profile_id = %s
                """, (profile_id,))

                # Add the newly selected skills
                for skill_id in selected_skills:
                    cursor.execute("""
                        INSERT INTO ProfileSkills (profile_id, skill_id)
                        VALUES (%s, %s)
                    """, (profile_id, skill_id))

                db_conn.commit()
                cursor.close()
                db_conn.close()
                return redirect('/profile')
            except mysql.connector.Error as err:
                print(f"MySQL Error during profile update or skills update: {err}")
                error = "Error updating profile. Please try again."
                db_conn.rollback()
                if db_conn.is_connected():
                    cursor.close()
                    db_conn.close()
        elif not profile_id:
            error = "User profile not found."
        else:
            error = "Could not connect to the database."

    return render_template('edit_profile.html', profile=profile_data, error=error, available_skills=available_skills, user_skills=user_skills, csrf_token=generate_csrf_token())

@app.route('/projects')
def projects():
    if 'user_id' in session:
        user_id = session['user_id']
        db_conn = get_db_connection()
        projects = []
        if db_conn:
            cursor = db_conn.cursor(dictionary=True)
            try:
                cursor.execute("""
                    SELECT p.project_id, p.title, p.description, p.demo_link, p.source_link, p.featured_image, u.username
                    FROM Projects p
                    JOIN Profiles prof ON p.developer_id = prof.profile_id
                    JOIN Users u ON prof.user_id = u.user_id where prof.user_id = %s
                    ORDER BY p.created_at DESC
                """, (user_id,))
                projects = cursor.fetchall()
                for project in projects:
                    # Fetch tags
                    cursor.execute("""
                        SELECT t.name
                        FROM Tags t
                        JOIN ProjectTags pt ON t.tag_id = pt.tag_id
                        WHERE pt.project_id = %s
                    """, (project['project_id'],))
                    project['tags'] = cursor.fetchall()
                cursor.close()
                db_conn.close()
            except mysql.connector.Error as err:
                print(f"MySQL Error fetching projects: {err}")
        return render_template('projects.html', projects=projects, csrf_token=generate_csrf_token())
    else:
        return redirect('/login')

@app.route('/projects/add', methods=['GET', 'POST'])
def add_project():
    if not is_logged_in():
        return redirect('/login')

    user_id = session['user_id']
    error = None
    db_conn = get_db_connection()
    available_skills = []
    if db_conn:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT skill_id, name FROM Skills ORDER BY name")
            available_skills = cursor.fetchall()
        except mysql.connector.Error as err:
            print(f"MySQL Error fetching skills: {err}")

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        demo_link = request.form.get('demo_link')
        source_link = request.form.get('source_link')
        image_file = request.files.get('featured_image')
        new_tags = request.form.getlist('new_tags') # Get newly entered tags
        featured_image_name = 'images/default.jpg'

        # ... (rest of your image handling and project insertion code) ...

        if not error:
            db_conn = get_db_connection()
            if db_conn:
                cursor = db_conn.cursor()
                try:
                    cursor.execute("SELECT profile_id FROM Profiles WHERE user_id = %s", (user_id,))
                    profile_result = cursor.fetchone()
                    if profile_result:
                        profile_id = profile_result[0]
                        cursor.execute("""
                            INSERT INTO Projects (developer_id, title, description, demo_link, source_link, featured_image)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (profile_id, title, description, demo_link, source_link, featured_image_name))
                        project_id = cursor.lastrowid

                        # Handle new tags
                        for tag_name in new_tags:
                            # Check if tag exists, if not, insert it
                            cursor.execute("SELECT tag_id FROM Tags WHERE name = %s", (tag_name,))
                            existing_tag = cursor.fetchone()
                            if existing_tag:
                                tag_id = existing_tag[0]
                            else:
                                cursor.execute("INSERT INTO Tags (name) VALUES (%s)", (tag_name,))
                                tag_id = cursor.lastrowid
                            # Link tag to the project
                            cursor.execute("INSERT INTO ProjectTags (project_id, tag_id) VALUES (%s, %s)", (project_id, tag_id))

                        db_conn.commit()
                        cursor.close()
                        db_conn.close()
                        return redirect('/projects')
                    else:
                        error = "Error: Could not find your profile."
                except mysql.connector.Error as err:
                    print(f"MySQL Error during project creation or tags update: {err}")
                    error = "Error adding project. Please try again."
                    db_conn.rollback()
                    if db_conn.is_connected():
                        cursor.close()
                        db_conn.close()
            else:
                error = "Could not connect to the database."

    return render_template('add_project.html', error=error, available_skills=available_skills, csrf_token=generate_csrf_token())

import os
from werkzeug.utils import secure_filename
from flask import current_app

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/projects/edit/<int:project_id>', methods=['GET', 'POST'])
def edit_project(project_id):
    if not is_logged_in():
        return redirect('/login')

    user_id = session['user_id']
    error = None
    db_conn = get_db_connection()
    project = None
    project_tags = []

    if db_conn:
        cursor = db_conn.cursor(dictionary=True)
        try:
            # Fetch the project and ensure the logged-in user owns it
            cursor.execute("""
                SELECT p.*
                FROM Projects p
                JOIN Profiles prof ON p.developer_id = prof.profile_id
                WHERE p.project_id = %s AND prof.user_id = %s
            """, (project_id, user_id))
            project = cursor.fetchone()

            # Fetch the project's current tags for display
            cursor.execute("""
                SELECT t.tag_id, t.name
                FROM Tags t
                JOIN ProjectTags pt ON t.tag_id = pt.tag_id
                WHERE pt.project_id = %s
            """, (project_id,))
            project_tags = cursor.fetchall()
        except mysql.connector.Error as err:
            print(f"MySQL Error fetching project for edit: {err}")

        if not project:
            if db_conn.is_connected():
                cursor.close()
                db_conn.close()
            return "Project not found or you don't have permission to edit it.", 404

        if request.method == 'POST':
            title = request.form.get('title')
            description = request.form.get('description')
            demo_link = request.form.get('demo_link')
            source_link = request.form.get('source_link')
            image_file = request.files.get('featured_image')
            new_tags = request.form.getlist('new_tags')
            existing_tags = request.form.getlist('tags')
            removed_tags = request.form.getlist('removed_tags')
            featured_image_name = project.get('featured_image', 'images/default.jpg') # Default to existing or default

            if not title:
                error = "Title is required."
            elif image_file:
                if allowed_file(image_file.filename):
                    filename = secure_filename(image_file.filename)
                    os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
                    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                    image_file.save(filepath)
                    featured_image_name_windows = os.path.relpath(filepath, 'static')
                    featured_image_name = featured_image_name_windows.replace('\\', '/')
                    # Optionally delete the old image if it's not the default
                    if project.get('featured_image') and 'images/default.jpg' not in project['featured_image']:
                        old_path = os.path.join('static', project['featured_image'])
                        if os.path.exists(old_path):
                            os.remove(old_path)
                else:
                    error = "Invalid file type. Allowed types are png, jpg, jpeg, gif."

            if not error:
                try:
                    cursor = db_conn.cursor()

                    cursor.execute("""
                        UPDATE Projects
                        SET title = %s, description = %s, demo_link = %s,
                            source_link = %s, featured_image = %s, updated_at = CURRENT_TIMESTAMP
                        WHERE project_id = %s
                    """, (title, description, demo_link, source_link, featured_image_name, project_id))

                    # Remove tags
                    for tag_id_to_remove in removed_tags:
                        cursor.execute("DELETE FROM ProjectTags WHERE project_id = %s AND tag_id = %s",
                                       (project_id, tag_id_to_remove))

                    # Handle new tags
                    for tag_name in new_tags:
                        cursor.execute("SELECT tag_id FROM Tags WHERE name = %s", (tag_name,))
                        existing_tag = cursor.fetchone()
                        if existing_tag:
                            tag_id = existing_tag[0]
                        else:
                            cursor.execute("INSERT INTO Tags (name) VALUES (%s)", (tag_name,))
                            tag_id = cursor.lastrowid
                        # Check if the tag is already associated before inserting
                        cursor.execute("SELECT * FROM ProjectTags WHERE project_id = %s AND tag_id = %s", (project_id, tag_id))
                        if not cursor.fetchone():
                            cursor.execute("INSERT INTO ProjectTags (project_id, tag_id) VALUES (%s, %s)",
                                           (project_id, tag_id))

                    db_conn.commit()
                    cursor.close()
                    db_conn.close()
                    return redirect('/projects')
                except mysql.connector.Error as err:
                    print(f"MySQL Error during project update: {err}")
                    error = "Error updating project. Please try again."
                    db_conn.rollback()
                    if db_conn.is_connected():
                        cursor.close()
                        db_conn.close()

    return render_template('edit_project.html', project=project, error=error, project_tags=project_tags,
                           csrf_token=generate_csrf_token())

@app.route('/projects/delete/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    if not is_logged_in():
        return redirect('/login')

    user_id = session['user_id']
    db_conn = get_db_connection()
    if db_conn:
        cursor = db_conn.cursor()
        try:
            # Fetch the project to get the filename of the featured image
            cursor.execute("""
                SELECT p.featured_image
                FROM Projects p
                JOIN Profiles prof ON p.developer_id = prof.profile_id
                WHERE p.project_id = %s AND prof.user_id = %s
            """, (project_id, user_id))
            project_data = cursor.fetchone()

            # Delete the project from the database
            cursor.execute("""
                DELETE FROM Projects
                WHERE project_id = %s AND developer_id = (
                    SELECT profile_id FROM Profiles WHERE user_id = %s
                )
            """, (project_id, user_id))
            db_conn.commit()

            # Optionally delete the associated image file if it's not the default
            if project_data and project_data[0] and 'images/default.jpg' not in project_data[0]:
                image_path = os.path.join('static', project_data[0])
                if os.path.exists(image_path):
                    os.remove(image_path)

            cursor.close()
            db_conn.close()
            return redirect('/projects')
        except mysql.connector.Error as err:
            print(f"MySQL Error during project deletion: {err}")
            if db_conn.is_connected():
                db_conn.rollback()
                cursor.close()
                db_conn.close()
            return "Error deleting project.", 500
    else:
        return "Could not connect to the database.", 500


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    app.run(debug=True)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
