from flask import Flask


def create_app(config_name="default"):
    app = Flask(__name__)

    from config.settings import configs
    app.config.from_object(configs[config_name])

    from app.routes.dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)

    return app
