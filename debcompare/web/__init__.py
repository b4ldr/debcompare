'''main web app'''
import os
from flask import Flask
from debcompare.web import tasks


def create_app(test_config=None):
    '''main web app'''
    app = Flask(__name__, instance_relative_config=True)
    app.cli.add_command(tasks.update_packages_cve)

    if test_config is None:
        app.config.from_object('debcompare.web.config')
    else:
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    return app
