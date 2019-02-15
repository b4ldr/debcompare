#!/usr/bin/env python3
# we use python3 as xz is not supported in python2 tarfile
import logging
import os
import tarfile
import pickle
import debianbts as bts
from requests import get
from debian.changelog import Changelog
from datetime import datetime
from subprocess import check_output, CalledProcessError
from argparse import ArgumentParser
from re import search, sub


SNAPSHOT_URL = 'http://snapshot.debian.org'



class DownloadException(Exception):
    '''Unable to download a file from snapshot'''
    pass


class MissingFileinfoException(Exception):
    '''Unable to find filename in snapshot fileinfo'''
    pass


class MissingUrlException(Exception):
    '''Unable to determine snapshot download URL'''
    pass


class Package(object):
    '''Hold information about a source package'''

    _fileinfo = None
    _changelog = None
    _bugs = None
    _new_bugs = None
    _date = None

    def __init__(self, name, version, bugs, force=False, working_dir='/var/tmp/debcompare'):
        self.name        = name
        self.version     = version
        self.bugs        = bugs
        self.force       = force
        self.working_dir = working_dir
        self.fullname    = '{}_{}'.format(self.name, self.version)
        self.basename    = self.fullname.split('-')[0]
        self.logger      = logging.getLogger('debcompare.Package')

        self.dsc_path  = os.path.join(self.working_dir,
                '{}.dsc'.format(self.fullname))
        self.debian_tar_path = os.path.join(self.working_dir,
                '{}.debian.tar.xz'.format(self.fullname))
        self.orig_tar_path = os.path.join(self.working_dir,
                '{}.orig.tar.gz'.format(self.basename))
        self.fileinfo_path = os.path.join(self.working_dir,
                '{}.info'.format(self.fullname))

        if self.force:
            if os.path.isfile(self.dsc_path): 
                os.remove(self.dsc_path)
            if os.path.isfile(self.debian_tar_path): 
                os.remove(self.debian_tar_path)
            if os.path.isfile(self.orig_tar_path): 
                os.remove(self.orig_tar_path)
            if os.path.isfile(self.fileinfo_path): 
                os.remove(self.fileinfo_path)

        self._fileinfo = unpickle_file(self.fileinfo_path, self.force)

        self.dsc_url = self._get_url('dsc')
        self.debian_tar_url = self._get_url('debian.tar.xz')
        try:
            self.orig_tar_url = self._get_url('orig.tar.gz', self.basename)
        except MissingUrlException:
            self.orig_tar_path = os.path.join(self.working_dir,
                    '{}.orig.tar.xz'.format(self.basename))
            self.orig_tar_url = self._get_url('orig.tar.xz', self.basename)


        if not os.path.isfile(self.dsc_path): 
            self._download_file(self.dsc_url, self.dsc_path)
        if not os.path.isfile(self.debian_tar_path): 
            self._download_file(self.debian_tar_url, self.debian_tar_path)
        if not os.path.isfile(self.orig_tar_path): 
            self._download_file(self.orig_tar_url, self.orig_tar_path)

    def _download_file(self, source, destination):
        '''download a file from source and save it in destination'''
        self.logger.info('Downloading: {}'.format(source))
        response = get(source)
        if response.status_code != 200:
            self.logger.error('unable to download {} from {}'.format(destination, source))
            raise DownloadException
        self.logger.info('Saving: {}'.format(destination))
        write_file(response.content, destination)

    def _get_url(self, extension, name=None):
        '''parse the snapshot meta data to generate the correct download url'''
        name = name if name else self.fullname
        file_name = '{}.{}'.format(name, extension)
        for sha, file_info in self.fileinfo['fileinfo'].items():
            if file_info[-1]['name'] == file_name:
                url = '{}/file/{}'.format(SNAPSHOT_URL, sha)
                return url
        self.logger.error('unable to find url for {}'.format(file_name))
        raise MissingUrlException

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
            self.logger.info('Fetching: {}'.format(url))
            response = get(url)
            if response.status_code != 200:
                self.logger.error('unable to get snapshot fileinfo for {}'.format(
                    self.fullname))
                raise MissingFileinfoException
            self._fileinfo = response.json() 
            self.logger.debug(self._fileinfo)
            pickle_tofile(self._fileinfo, self.fileinfo_path)
        return self._fileinfo

    @property
    def changelog(self):
        '''parse the changelog of the package and return a Changlog object'''
        if self._changelog is None:
            tar = tarfile.open(self.debian_tar_path, 'r:xz')
            for member in tar.getmembers():
                if member.name == 'debian/changelog':
                    f = tar.extractfile(member)
                    self._changelog = Changelog(f.read())
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


class Differ(object):
    '''class to diff two packages'''
    _bugs = None
    _security_bugs = None
    _diff = None

    def __init__(self, name, old_version, new_version, force=False,
            working_dir='/var/tmp/debcompare', debdiff='/usr/bin/debdiff'):
        self.name            = name
        self.old_version = old_version
        self.new_version     = new_version
        self.force           = force
        self.working_dir     = working_dir
        self.debdiff         = debdiff
        self.logger          = logging.getLogger('debcompare.Differ')
        
        if not os.path.exists(self.working_dir):
            os.makedirs(self.working_dir)

        self.bugs_path = os.path.join(self.working_dir, '{}.bugs'.format(self.name))
        self.security_bugs_path = os.path.join(self.working_dir, '{}.secbugs'.format(self.name))
        self.diff_path = os.path.join(self.working_dir,
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
            self._bugs = bts.get_status(bts.get_bugs('package',self.name))
            pickle_tofile(self._bugs, self.bugs_path)
        return self._bugs

    @property
    def security_bugs(self):
        '''get a list of all open bugs for this package'''
        if self._security_bugs is None:
            self._security_bugs = bts.get_status(bts.get_bugs(
                'package',self.name,
                'tag','security',
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
            except CalledProcessError as e:
                # debdiff exits 1 if there are changes
                if e.returncode == 1:
                    self.logger.info(e.output)
                    self._diff = e.output
                    write_file(self._diff, self.diff_path)
                else:
                    self.logger.error('{} exited with faliures:\n{}'.format(e.cmd, e.output))
        return self._diff

    def cli_report(self, color=True):
        '''print a nice report for cli interface'''
        if color:
            from fabulous.color import red, green, bold
        _red   =  red if color else lambda string : string
        _green = green if color else lambda string : string
        _bold  = bold if color else lambda string : string

        # i use the join here so i can use the lambda trick above
        # im sure there is a better way to do this so please send code
        print(_bold(''.join(['=' * 10, ' DebDiff Report ', '=' * 10])))
        for line in differ.diff.decode().split('\n'):
            if len(line) == 0:
                continue
            if len(line.split()) > 1 and not line.split()[1].endswith('debian/patches/series'):
                '''
                this is a hack to try and make output more readable.
                deb diff sort of double diffs so everything accept the series file
                has surpurfulous +/-
                '''
                line = line[1:]
            if line[0] == '+':
                print(_green(line))
            elif line[0] == '-':
                print(_red(line))
            else:
                print(line)

        print(_bold(''.join(['=' * 12, ' Bug Report ', '=' * 12])))
        if len(self.new_package.new_bugs) == 0:
            print(_bold('No bug reports, YAY :D'))
        else:
            for bug in sorted(self.new_package.new_bugs, key = lambda x: x.bug_num):
                print(' * {}: [{}] {}'.format(
                    _bold(bug.date), _bold(bug.bug_num), bug.subject))


def read_file(source):
    if os.path.isfile(source):
        with open(source, 'rb') as f:
            return f.read()
    return None

def write_file(content, destination):
    with open(destination, 'wb') as f:
        return f.write(content)

def unpickle_file(source, force):
    if os.path.isfile(source):
        if not force:
            with open(source, 'rb') as f:
                return pickle.load(f)
        os.remove(source)
        return None

def pickle_tofile(obj, destination):
    with open(destination, 'wb') as f:
        pickle.dump(obj, f)

def get_args():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('-o', '--old-version',
            help='The old version of the package, the default is the old_version - 1' )
    parser.add_argument('-n', '--new-version',
            help='The new version of the package, the default is the old_version + 1' )
    parser.add_argument('-f', '--force', action='store_true',
            help='force a re-download of all files')
    parser.add_argument('--no-color', action='store_true',
            help='force a re-download of all files')
    parser.add_argument('-w', '--working-dir', default='/var/tmp/debcompare',
            help='A directory to store downloaded files')
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

    new_version = args.new_version
    old_version = args.old_version

    if old_version is None and new_version is None:
        logger.error('You must specify old-version and/or new-version')
        SystemExit(1)
    elif old_version is None:
        _version = new_version.split('+')
        if len(_version) == 1:
            logger.error('Unable to determine old version')
            raise SystemExit(1)
        elif len(_version) == 2:
            match  = search('deb(\d+)u(\d+)$', _version[1])
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
            logger.error('Unable to determine new version as we don know the debian version',
                    'try -n {}debXu1 where X = the version of debian e.g. 8, 9 or 10'.format(
                        args.package))
            raise SystemExit(1)
        elif len(_version) == 2:
            match  = search('deb(\d+)u(\d+)$', _version[1])
            deb_version = match.group(1)
            deb_update = int(match.group(2))
            new_deb_version = 'deb{}u{}'.format(deb_version, deb_update + 1)
            new_version = '{}+{}'.format(_version[0], new_deb_version)
        else:
            logger.error('unable to determine the next version as base version look invalid')
            raise SystemExit(1)

    try:
        differ = Differ(
                args.package,
                old_version,
                new_version,
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

