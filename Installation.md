# Introduction #

This page describes how to install the blkmon application.


# Details #

The application was developed using the python Twisted application on ubuntu linux.

## Install the pre-requisite packages ##

As root:
```
sudo apt-get install python-twisted python-twisted-names
sudo apt-get install python-wokkel
```

Download and install Google’s ipaddr.py See: http://code.google.com/p/ipaddr-py/

```
tar xvzf ipaddr-2.1.10.tar.gz
cd ipaddr-2.1.10/
python setup.py build

(as root)
python setup.py install
```


## Install the blkmon application ##

Download the latest tarball version of the application source code.

Install it in a convenient directory.

The application itself can run with normal user privilege. It does not need to be root to execute.

Before running the application for the 1st time, it needs to be configured. This is described in ConfiguringApp .