import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()


def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(
            host=os.environ.get('DB_HOST'),
            database=os.environ.get('DB_NAME'),
            user=os.environ.get('DB_USER'),
            password=os.environ.get('DB_PASSWORD'),
            port=os.environ.get('DB_PORT')
        )
        return conn
    except Exception as e:
        print(f"Error connecting to Database: {e}")
        return None


def init_db():
    """Initializes the database with the required tables."""
    conn = get_db_connection()
    if conn is None:
        return

    cur = conn.cursor()

    # 1. Users Table (Stores login info & keys)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            public_key TEXT, 
            is_admin BOOLEAN DEFAULT FALSE,
            admin_role VARCHAR(20), -- 'SIGMA', 'ALPHA', 'SATPURA'
            two_fa_secret VARCHAR(32),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # 2. Access Requests Table (The "3 Admin" Waiting Room)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS access_requests (
            id SERIAL PRIMARY KEY,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            sigma_approved BOOLEAN DEFAULT FALSE,
            alpha_approved BOOLEAN DEFAULT FALSE,
            satpura_approved BOOLEAN DEFAULT FALSE,
            status VARCHAR(20) DEFAULT 'PENDING'
        );
    """)

    # 3. Backup Codes Table (For 2FA recovery)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS backup_codes (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            code VARCHAR(10) NOT NULL,
            is_used BOOLEAN DEFAULT FALSE
        );
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("Database tables initialized successfully.")


# If this file is run directly, initialize the DB
if __name__ == '__main__':
    # PRE-REQUISITE: You must create the database 'main_abarg_db' in pgAdmin first!
    init_db()