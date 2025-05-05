from flask_sqlalchemy import SQLAlchemy

# Create a SQLAlchemy instance
db = SQLAlchemy()

# Connect the database to the app
def connect_db(app):
    """Connect to database."""
    db.app = app
    db.init_app(app)

# Define the User model
class User(db.Model):
    """User model for storing user information."""

    __tablename__ = "users"

    username = db.Column(db.String(20), primary_key=True, unique=True)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)

    feedback = db.relationship(
        'Feedback',
        backref='user',
        cascade='all, delete-orphan',
        passive_deletes=True
    )

    def __repr__(self):
        return f"<User {self.username} {self.email}>"

class Feedback(db.Model):
    """Feedback model for storing user-submitted feedback."""
    __tablename__ = "feedback"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    username = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete="CASCADE"),
        nullable=False
    )
