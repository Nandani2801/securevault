from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from app.config import Config


db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()


def create_app(test_config=None):
    app = Flask(__name__)

    if test_config:
        app.config.update(test_config)   # ✅ use SQLite for tests
    else:
        app.config.from_object(Config)   # ✅ use Postgres for normal app

    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."

    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from app.routes.auth import auth_bp
    from app.routes.vault import vault_bp
    from app.routes.admin import admin_bp
    from app.routes.profile import profile_bp
    from app.routes.fetcher import fetcher_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(fetcher_bp)

    return app
