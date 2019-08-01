#!/usr/bin/env python3
"""Retrive security information for a package"""
import json
import logging
import os

from argparse import ArgumentParser
from collections import defaultdict

from requests import get
from debcompare.trackerscrape import Scrape


SECURITY_TRACKERDATA_URL = 'https://security-tracker.debian.org/tracker/data/json'


class PackagesCVE():
    '''
    Class to hold data parsed security tracker data from
    https://security-tracker.debian.org/tracker/data/json
    '''
    def __init__(self, data_file):
        self.packages = {}
        self.data_file = data_file
        self.load_data()

    def load_data(self):
        """Load json data"""
        packages = {}
        data = None

        with open(self.data_file, 'r') as file_stream:
            data = json.load(file_stream)

        for package, cves in data.items():
            packages[package] = defaultdict(list)
            for cve, meta in cves.items():
                for data in meta['releases'].values():
                    if data['status'] == 'resolved':
                        packages[package][data['fixed_version']].append(
                            PackageCVE(cve, meta))

        # Not rally sure if this dose what i want but trying to make the
        # operation as atomic as possible
        self.packages = packages
        packages = None
        data = None

    def get_cves(self, package, check):
        """Return CVE's associated with a package"""
        return self.packages.get(package, {}).get(check, None)


class PackageCVE():
    '''class to hold information about a CVE'''
    def __init__(self, cve, info):
        self.cve = cve
        self.scope = info.get('scope', 'Uknown')
        self.description = info.get('description', 'Unknown')
        self._notes = None

    def __str__(self):
        return '{}: [{}] {}{}'.format(
            self.cve, self.scope, self.description, '\n * '.join(self.notes))

    @property
    def notes(self):
        """Return associated CVE notes"""
        if self._notes is None:
            scrape = Scrape(self.cve)
            self._notes = scrape.notes
        return self._notes


def get_args():
    """Argument parser"""
    parser = ArgumentParser(description="list CVE's fixed in a specific packag")
    parser.add_argument('-w', '--working-dir', default='/var/tmp/debcompare',
                        help='A directory to store downloaded files')
    parser.add_argument('-c', '--check', required=True,
                        help='the specific version to test')
    parser.add_argument('-f', '--force', action='store_true',
                        help='the specific version to test')
    parser.add_argument('-v', '--verbose', action='count',
                        help='Add more to increase verbosity')
    parser.add_argument('package', help='The package to compare')
    return parser.parse_args()


def set_log_level(args_level):
    """Manage log level"""
    if args_level is None:
        log_level = logging.ERROR
    elif args_level == 1:
        log_level = logging.WARN
    elif args_level == 2:
        log_level = logging.INFO
    elif args_level > 2:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)


def main():
    """Main entry point"""
    args = get_args()
    set_log_level(args.verbose)
    data_file = os.path.join(args.working_dir, 'cve.json')
    if os.path.isfile(data_file):
        if args.force:
            os.remove(data_file)
    if not os.path.isfile(data_file):
        with open(data_file, 'w') as file_stream:
            data = get(SECURITY_TRACKERDATA_URL).json()
            json.dump(data, file_stream)
    packages = PackagesCVE(data_file)
    cves = packages.get_cves(args.package, args.check)
    for cve in cves:
        print(str(cve))


if __name__ == "__main__":
    main()
