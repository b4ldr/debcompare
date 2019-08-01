#!/usr/bin/env python3
"""module to scrape notes from debian security tracker"""

from argparse import ArgumentParser

from bs4 import BeautifulSoup
from requests import get


TRACKER_URI = 'https://security-tracker.debian.org/tracker/{bug}'


class ScrapValueError(ValueError):
    """exception to raise if we try to parse a none CVE page"""


class Scrape():
    """class to crape the notes from https://security-tracker.debian.org/tracker/$bug"""
    def __init__(self, cve_id):
        if not cve_id.startswith('CVE-'):
            raise ScrapValueError("cve_id ({}): dosn't match CVE-$YEAR-$ID".format(cve_id))
        self.cve_id = cve_id
        self.uri = TRACKER_URI.format(bug=self.cve_id)
        self._content = None
        self._notes = None

    @property
    def content(self):
        """return the raw page content"""
        if self._content is None:
            self._content = get(self.uri).text
        return self._content

    @property
    def notes(self):
        """return the notes from a given page"""
        if self._notes is None:
            parsed = BeautifulSoup(self.content, 'html.parser')
            notes = parsed.find('h2', text='Notes')
            if notes:
                self._notes = [link.get('href') for link in notes.next_sibling.find_all('a')]
            else:
                self._notes = []
        return self._notes


def get_args():
    '''Arg parser'''
    parser = ArgumentParser(description="Return the CVE notes from debian security tracker")
    parser.add_argument('cve_id', help='the CVE ID')
    return parser.parse_args()


def main():
    '''Main entry point'''
    args = get_args()
    scrape = Scrape(args.cve_id)
    for note in scrape.notes:
        print(note)


if __name__ == "__main__":
    main()
