## dependencies
  - [python-debianbts](https://github.com/venthur/python-debianbts)
  - [fabulous](https://pypi.org/project/fabulous/)
  - python3
  - debdiff

if you dont want to install faboulus you can can run the program with `--no-color`

## setup

`mkdir -p /var/tmp/debcompare/`

## debian
`apt-get install python3-fabulous python3-debianbts python3-bs4 devscripts`

## none debian
`pip install fabulous python-debian python-debianbts bs4`

## examples
```
$ python3 -m debcompare.compare -o 7.38.0-4+deb8u1  -n 7.38.0-4+deb8u11 -v -f curl
$ python3 -m debcompare.compare -o 7.38.0-4+deb8u13 -v -f curl
$ python3 -m debcompare.compare -n 7.38.0-4+deb8u14 -v -f curl
$ python3 -m debcompare.compare -o 7.38.0-4+deb8u1  -n 7.38.0-4+deb8u11 -v -f --no-color curl
$ python3 -m debcompare.compare -vvvv -o 7.38.0-4+deb8u1  -n 7.38.0-4+deb8u11 -v -f --no-color curl
```
