import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    CELERY_BROKER_URL = 'postgres://postgres:VikaPidosha00@localhost/blog'
    CELERY_RESULT_BACKEND = 'rpc://'
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MS_TRANSLATOR_KEY = os.environ.get('MS_TRANSLATOR_KEY')
    POSTS_PER_PAGE = 25
