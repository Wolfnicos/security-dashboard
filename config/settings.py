import os


class BaseConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", "security.db")


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    DEBUG = False


configs = {
    "default": DevelopmentConfig,
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
