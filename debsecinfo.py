#!/usr/bin/env python3
import json
import os
import logging
from collections import defaultdict
from requests import get
from argparse import ArgumentParser

SECURITY_TRACKERDATA_URL = 'https://security-tracker.debian.org/tracker/data/json'

class PackagesCVE(object):
    '''
    Class to hold data parsed security tracker data from
    https://security-tracker.debian.org/tracker/data/json
    '''
    def __init__(self, data_file):
        self.packages = {}
        self.data_file = data_file
        self.load_data()

    def load_data(self):
        packages = {}
        data     = None

        with open(self.data_file, 'r') as f:
            data = json.load(f)

        for package, cves in data.items():
            packages[package] = defaultdict(list)
            for cve, meta in cves.items():
                for release, data in meta['releases'].items():
                    if data['status'] == 'resolved':
                        packages[package][data['fixed_version']].append(
                                PackageCVE(cve, meta))

        # Not rally sure if this dose what i want but trying to make the 
        # operation as atomic as possible
        self.packages = packages
        packages = None
        data = None

    def get_cves(self, package, check):
        return self.packages.get(package, {}).get(check, None)


class PackageCVE(object):
    '''class to hold information about a CVE'''
    def __init__(self, cve, info):
        self.cve = cve
        self.scope = info.get('scope', 'Uknown')
        self.description = info.get('description', 'Unknown')

    def __str__(self):
        return '{}: [{}] {}'.format(self.cve, self.scope, self.description)



def get_args():
    parser = ArgumentParser(description="list CVE's fixed in a specific packag")
    parser.add_argument('-w', '--working-dir', default='/var/tmp/debcompare',
            help='A directory to store downloaded files')
    parser.add_argument('-c', '--check', required=True,
            help='the specific version to test')
    parser.add_argument('-f', '--force', action='store_true',
            help='the specific version to test')
    parser.add_argument('-v', '--verbose', action='count',
            help='Add more to increase verbosity')
    parser.add_argument('package', help='The package to compare' )
    return parser.parse_args()

def set_log_level(args_level):
    if args_level is None:
        log_level = logging.ERROR
    elif args_level == 1:
        log_level = logging.WARN
    elif args_level == 2:
        log_level = logging.INFO
    elif args_level > 2:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)

if __name__ == "__main__":

    args = get_args()
    set_log_level(args.verbose)
    data_file = os.path.join(args.working_dir, 'cve.json')
    if os.path.isfile(data_file):
        if args.force:
            os.remove(data_file)
    if not os.path.isfile(data_file):
        with open(data_file, 'w') as f:
            data = get(SECURITY_TRACKERDATA_URL).json()
            json.dump(data, f)
    packages = PackagesCVE(data_file)
    cves = packages.get_cves(args.package, args.check)
    for cve in cves:
        print(str(cve))

