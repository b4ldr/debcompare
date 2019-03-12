'''clie tasks that affect the web app'''
import os
import json
import click
from requests import get
from flask import current_app, g
from flask.cli import with_appcontext
from debcompare.secinfo import SECURITY_TRACKERDATA_URL, PackagesCVE


@click.command('update-cves')
@with_appcontext
def update_packages_cve():
    '''command to update the cve data probably run via cron'''
    cve_file = current_app.config['PACKAGES_CVE_FILE']
    if not os.path.isfile(cve_file):
        with open(cve_file, 'w') as cve_fh:
            data = get(SECURITY_TRACKERDATA_URL).json()
            json.dump(data, cve_fh)
    if 'packages_cve' not in g:
        g.packages_cve = PackagesCVE(cve_file)
    else:
        g.packages_cve.load_data()
