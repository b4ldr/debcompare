#!/usr/bin/env python3
'''
python module to compare two debian packages from a security prespective
'''
# we use python3 as xz is not supported in python2 tarfile
import logging
import os
import tarfile
import pickle
import json
from datetime import datetime
from subprocess import check_output, CalledProcessError
from argparse import ArgumentParser
from re import search
from requests import get
import debianbts as bts
from debian.changelog import Changelog
from debsecinfo import PackagesCVE, SECURITY_TRACKERDATA_URL


SNAPSHOT_URL = 'http://snapshot.debian.org'


class DownloadException(Exception):
    '''Unable to download a file from snapshot'''


class MissingFileinfoException(Exception):
    '''Unable to find filename in snapshot fileinfo'''


class MissingUrlException(Exception):
    '''Unable to determine snapshot download URL'''


class ExtentionNotFoundException(Exception):
    '''Unable to determine the extension'''


class Package():
    '''Hold information about a source package'''

    # pylint: disable=too-many-instance-attributes
    # pylint: disable=too-many-arguments

    _fileinfo = None
    _changelog = None
    _bugs = None
    _new_bugs = None
    _date = None
    _additional_files = None
    _debian_tar_path = None

    def __init__(self, name, version, bugs, force=False, working_dir='/var/tmp/debcompare'):
        self.name           = name
        self.version        = version
        self.simple_version = version.split(':', 1)[1] if ':' in version else version
        self.bugs           = bugs
        self.force          = force
        self.working_dir    = working_dir
        self.fullname       = '{}_{}'.format(self.name, self.simple_version)
        self.basename       = self.fullname.split('-')[0]
        self.logger         = logging.getLogger('debcompare.Package')

        self.fileinfo_path = os.path.join(
            self.working_dir, '{}.info'.format(self.fullname))

        if self.force:
            if os.path.isfile(self.fileinfo_path):
                os.remove(self.fileinfo_path)

        self.dsc_path  = os.path.join(self.working_dir, '{}.dsc'.format(self.fullname))

        if self.force:
            if os.path.isfile(self.dsc_path):
                os.remove(self.dsc_path)

        self.dsc_url = self._get_url('{}.dsc'.format(self.fullname))
        self._fileinfo = unpickle_file(self.fileinfo_path, self.force)

        if not os.path.isfile(self.dsc_path):
            self._download_file(self.dsc_url, self.dsc_path)

        if self.force:
            for additional_file in self.additional_files:
                path = os.path.join(self.working_dir, additional_file)
                if os.path.isfile(path):
                    os.remove(path)

        for additional_file in self.additional_files:
            path = os.path.join(self.working_dir, additional_file)
            if not os.path.isfile(path):
                url = self._get_url(additional_file)
                self._download_file(url, path)

    def _download_file(self, source, destination):
        '''download a file from source and save it in destination'''
        self.logger.info('Downloading: %s', source)
        response = get(source)
        if response.status_code != 200:
            self.logger.error('unable to download %s from %s', destination, source)
            raise DownloadException
        self.logger.info('Saving: %s', destination)
        write_file(response.content, destination)

    def _get_url(self, name):
        '''parse the snapshot meta data to generate the correct download url'''
        for sha, file_info in self.fileinfo['fileinfo'].items():
            if file_info[-1]['name'] == name:
                url = '{}/file/{}'.format(SNAPSHOT_URL, sha)
                return url
        self.logger.error('unable to find url for %s', name)
        raise MissingUrlException

    @property
    def additional_files(self):
        '''list of bugs that have been raised since this package was created'''
        if self._additional_files is None:
            self._additional_files = []
            with open(self.dsc_path, 'r') as dsc_file:
                files_section = False
                for line in dsc_file.readlines():
                    if line.strip('\n') == 'Files:':
                        files_section = True
                        continue
                    if files_section:
                        words = line.split()
                        if len(words) == 3:
                            self.logger.debug('add file: %s', words[2])
                            self._additional_files.append(words[2])
                        else:
                            files_section = False
                            break
        return self._additional_files

    @property
    def new_bugs(self):
        '''list of bugs that have been raised since this package was created'''
        if self._new_bugs is None:
            self._new_bugs = []
            for bug in self.bugs:
                if bug.date > self.date:
                    self._new_bugs.append(bug)
        return self._new_bugs

    @property
    def fileinfo(self):
        '''download the package metedata from snapshot.debian.org'''
        if self._fileinfo is None:
            url = '{url}/mr/package/{name}/{version}/srcfiles?fileinfo=1'.format(
                url=SNAPSHOT_URL, name=self.name, version=self.version)
            self.logger.info('Fetching: %s', url)
            response = get(url)
            if response.status_code != 200:
                self.logger.error('unable to get snapshot fileinfo for %s', self.fullname)
                raise MissingFileinfoException
            self._fileinfo = response.json()
            self.logger.debug(self._fileinfo)
            pickle_tofile(self._fileinfo, self.fileinfo_path)
        return self._fileinfo

    @property
    def debian_tar_path(self):
        '''try to get the debian tar file if it exists'''
        if self._debian_tar_path is None:
            for additional_file in self.additional_files:
                print(additional_file)
                if search(r'\.debian\.tar', additional_file):
                    self._debian_tar_path = os.path.join(self.working_dir, additional_file)
        return self._debian_tar_path

    @property
    def changelog(self):
        '''parse the changelog of the package and return a Changlog object'''
        if not self.debian_tar_path:
            return None
        if self._changelog is None:
            print(self.debian_tar_path)
            tar = tarfile.open(self.debian_tar_path, 'r')
            for member in tar.getmembers():
                if member.name == 'debian/changelog':
                    changelog = tar.extractfile(member)
                    self._changelog = Changelog(changelog.read())
                    break
        return self._changelog

    @property
    def date(self):
        '''
        return the date the package was updated as a datetime
        we also remove the time delta as debianbts returns
        offset-naive UTC datetimes
        '''
        if self._date is None:
            date = datetime.strptime(self.changelog.date, '%a, %d %b %Y %H:%M:%S %z')
            offset = date.utcoffset()
            date = date.replace(tzinfo=None)
            self._date = date - offset
        return self._date


class Differ():
    '''class to diff two packages'''

    # pylint: disable=too-many-instance-attributes
    # pylint: disable=too-many-arguments

    _bugs = None
    _security_bugs = None
    _diff = None

    def __init__(self, name, old_version, new_version, fixed_cves, force=False,
                 working_dir='/var/tmp/debcompare', debdiff='/usr/bin/debdiff'):
        self.name        = name
        self.old_version = old_version
        self.new_version = new_version
        self.fixed_cves  = fixed_cves
        self.force       = force
        self.working_dir = working_dir
        self.debdiff     = debdiff
        self.logger      = logging.getLogger('debcompare.Differ')

        if not os.path.exists(self.working_dir):
            os.makedirs(self.working_dir)

        self.bugs_path = os.path.join(self.working_dir, '{}.bugs'.format(self.name))
        self.security_bugs_path = os.path.join(self.working_dir, '{}.secbugs'.format(self.name))
        self.diff_path = os.path.join(
            self.working_dir,
            '{}_{}-{}.diff'.format(self.name, self.old_version, self.new_version))

        self._diff          = read_file(self.diff_path)
        self._bugs          = unpickle_file(self.bugs_path, self.force)
        self._security_bugs = unpickle_file(self.security_bugs_path, self.force)

        if os.path.isfile(self.diff_path):
            self._diff = read_file(self.diff_path)

        self.base_package = Package(
            self.name,
            self.old_version,
            self.bugs,
            self.force,
            self.working_dir)
        self.new_package     = Package(
            self.name,
            self.new_version,
            self.bugs,
            self.force,
            self.working_dir)

    @property
    def bugs(self):
        '''get a list of all open bugs for this package'''
        if self._bugs is None:
            # should we do archive=both here?
            self._bugs = bts.get_status(bts.get_bugs('package', self.name))
            pickle_tofile(self._bugs, self.bugs_path)
        return self._bugs

    @property
    def security_bugs(self):
        '''get a list of all open bugs for this package'''
        if self._security_bugs is None:
            self._security_bugs = bts.get_status(bts.get_bugs(
                'package', self.name,
                'tag', 'security',
                'archive', 'both'))
            pickle_tofile(self._security_bugs, self.security_bugs_path)
        return self._security_bugs

    @property
    def diff(self):
        '''use debdiff to get a diff of the packages'''
        if self._diff is None:
            cmd = [self.debdiff, self.base_package.dsc_path, self.new_package.dsc_path]
            try:
                # debdiff exits 0 if there are no changes
                check_output(cmd)
                self.logger.warning('No difference found')
            except CalledProcessError as error:
                # debdiff exits 1 if there are changes
                if error.returncode == 1:
                    self.logger.info(error.output)
                    self._diff = error.output
                    write_file(self._diff, self.diff_path)
                else:
                    self.logger.error('%s exited with faliures:\n%s', error.cmd, error.output)
        return self._diff

    def cli_report(self, color=True):
        '''print a nice report for cli interface'''
        # pylint: disable=too-many-branches

        if color:
            from fabulous.color import red, green, bold
        _red   = red if color else lambda string: string
        _green = green if color else lambda string: string
        _bold  = bold if color else lambda string: string

        diff_hack = False
        # i use the join here so i can use the lambda trick above
        # im sure there is a better way to do this so please send code
        print(_bold(''.join(['=' * 10, ' DebDiff Report ', '=' * 10])))
        for line in self.diff.decode().split('\n'):
            if not line:
                continue
            if line[:4] in ['+---', '----', '-+++', '++++']:
                diff_hack = True
            if line[0] != '+' and line[0] != '-':
                diff_hack = False
            if diff_hack:
                '''
                this is a hack to try and make output more readable.
                deb diff sort of double diffs sometimes
                '''
                line = line[1:]
            if line[0] == '+':
                print(_green(line))
            elif line[0] == '-':
                print(_red(line))
            else:
                print(line)

        print(_bold(''.join(['=' * 12, ' Bug Report ', '=' * 12])))
        if not self.new_package.new_bugs:
            print(_bold('No bug reports, YAY :D'))
        else:
            for bug in sorted(self.new_package.new_bugs, key=lambda x: x.bug_num):
                print(' * {}: [{}] {}'.format(
                    _bold(bug.date), _bold(bug.bug_num), bug.subject))

        print(_bold(''.join(['=' * 12, ' CVE Report ', '=' * 12])))
        if not self.fixed_cves:
            print(_bold('No CVE\'s fixed in this update'))
        else:
            for cve in self.fixed_cves:
                print(' * {}: [{}] {}'.format(_bold(cve.cve), cve.scope, cve.description))


def read_file(source):
    '''read a file and return its content'''
    if os.path.isfile(source):
        with open(source, 'rb') as source_file:
            return source_file.read()
    return None


def write_file(content, destination):
    '''write contents to file at destination'''
    with open(destination, 'wb') as destination_file:
        return destination_file.write(content)


def unpickle_file(source, force):  # pylint: disable=inconsistent-return-statements
    '''unpickle a file and return its content'''

    if os.path.isfile(source):
        if not force:
            with open(source, 'rb') as source_file:
                return pickle.load(source_file)
        os.remove(source)
        return None


def pickle_tofile(obj, destination):
    '''pickle obj and write to destination file'''
    with open(destination, 'wb') as destination_file:
        pickle.dump(obj, destination_file)


def get_args():
    '''return argparse object'''
    parser = ArgumentParser(description=__doc__)
    parser.add_argument(
        '-o', '--old-version',
        help='The old version of the package, the default is the old_version - 1')
    parser.add_argument(
        '-n', '--new-version',
        help='The new version of the package, the default is the old_version + 1')
    parser.add_argument(
        '-f', '--force', action='store_true',
        help='force a re-download of all files')
    parser.add_argument(
        '--no-color', action='store_true',
        help='force a re-download of all files')
    parser.add_argument(
        '-w', '--working-dir', default='/var/tmp/debcompare',
        help='A directory to store downloaded files')
    parser.add_argument(
        '-v', '--verbose', action='count',
        help='Add more to increase verbosity')
    parser.add_argument('package', help='The package to compare')
    return parser.parse_args()


def set_log_level(args_level):
    '''set the log level passed on the args.verbose argument'''
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
    '''the main function'''
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-branches
    # pylint: disable=too-many-statements

    args = get_args()
    set_log_level(args.verbose)
    logger = logging.getLogger('debcompare.Main')
    new_version = args.new_version
    old_version = args.old_version
    cve_data_file = os.path.join(args.working_dir, 'cve.json')

    if os.path.isfile(cve_data_file):
        if args.force:
            os.remove(cve_data_file)
    if not os.path.isfile(cve_data_file):
        with open(cve_data_file, 'w') as cve_fh:
            data = get(SECURITY_TRACKERDATA_URL).json()
            json.dump(data, cve_fh)

    if old_version is None and new_version is None:
        logger.error('You must specify old-version and/or new-version')
        SystemExit(1)
    elif old_version is None:
        _version = new_version.split('+')
        if len(_version) == 1:
            logger.error('Unable to determine old version')
            raise SystemExit(1)
        elif len(_version) == 2:
            match  = search(r'deb(\d+)u(\d+)$', _version[1])
            deb_version = match.group(1)
            deb_update = int(match.group(2))
            if deb_update == 1:
                old_deb_version = _version[0]
            else:
                old_deb_version = 'deb{}u{}'.format(deb_version, deb_update - 1)
            old_version = '{}+{}'.format(_version[0], old_deb_version)
        else:
            logger.error('unable to determine the next version as new version looks invalid')
            raise SystemExit(1)
    elif new_version is None:
        _version = old_version.split('+')
        if len(_version) == 1:
            logger.error(  # pylint: disable=logging-too-many-args
                'Unable to determine new version as we don know the debian version',
                'try -n %sdebXu1 where X = the version of debian e.g. 8, 9 or 10',
                args.package)
            raise SystemExit(1)
        elif len(_version) == 2:
            match  = search(r'deb(\d+)u(\d+)$', _version[1])
            deb_version = match.group(1)
            deb_update = int(match.group(2))
            new_deb_version = 'deb{}u{}'.format(deb_version, deb_update + 1)
            new_version = '{}+{}'.format(_version[0], new_deb_version)
        else:
            logger.error('unable to determine the next version as base version look invalid')
            raise SystemExit(1)

    packages_cve = PackagesCVE(cve_data_file)
    fixed_cves   = packages_cve.get_cves(args.package, new_version)

    try:
        differ = Differ(
            args.package,
            old_version,
            new_version,
            fixed_cves,
            args.force,
            args.working_dir)
    except DownloadException:
        # Not sure if there is a standard for exit codes?
        raise SystemExit(100)
    except MissingFileinfoException:
        raise SystemExit(101)
    except MissingUrlException:
        raise SystemExit(102)

    differ.cli_report(not args.no_color)


if __name__ == "__main__":
    main()
