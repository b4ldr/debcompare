'''main web app'''
import os
from flask import Flask
import logging
from debcompare.web import tasks, compare
from debcompare.compare import PackagesCVE


def create_app(test_config=None):
    '''main web app'''
    app = Flask(__name__, instance_relative_config=True)
    app.cli.add_command(tasks.click_update_cves)
    app.logger.setLevel(logging.DEBUG)

    if test_config is None:
        app.config.from_object('debcompare.web.config')
    else:
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    app.register_blueprint(compare.bp)
    tasks.update_cves_file(app.config['PACKAGES_CVE_FILE'])
    app.packages_cve = PackagesCVE(app.config['PACKAGES_CVE_FILE'])

    return app
