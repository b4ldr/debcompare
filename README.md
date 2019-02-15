## dependencies
  - [python-debianbts](https://github.com/venthur/python-debianbts)
  - [fabulous](https://pypi.org/project/fabulous/)
  - python3
  - debdiff

if you dont want to install faboulus you can can run the program with `--no-color`

## setup

## debian
`apt-get install python3-fabulous python-debianbts devscripts`

## none debian
`pip install python3-fabulous python-debian python-debianbts`

## examples
```
$ ./debcompare.py -o 7.38.0-4+deb8u1  -n 7.38.0-4+deb8u11 -v -f curl
$ ./debcompare.py -o 7.38.0-4+deb8u13 -v -f curl
$ ./debcompare.py -n 7.38.0-4+deb8u14 -v -f curl
$ ./debcompare.py -o 7.38.0-4+deb8u1  -n 7.38.0-4+deb8u11 -v -f --no-color curl 
$ ./debcompare.py -vvvv -o 7.38.0-4+deb8u1  -n 7.38.0-4+deb8u11 -v -f --no-color curl 
```
