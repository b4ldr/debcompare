'''clie tasks that affect the web app'''
import os
import json
import click
from requests import get
from flask import current_app
from flask.cli import with_appcontext
from debcompare.secinfo import SECURITY_TRACKERDATA_URL


def update_cves_file(cve_file):
    '''command to update the cve data probably run via cron'''
    if not os.path.isfile(cve_file):
        with open(cve_file, 'w') as cve_fh:
            data = get(SECURITY_TRACKERDATA_URL).json()
            json.dump(data, cve_fh)


@click.command('update-cves')
@with_appcontext
def click_update_cves():
    update_cves_file()
    return current_app.packages_cve.load_data(current_app.config['PACKAGES_CVE_FILE'])
