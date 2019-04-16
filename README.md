# wpAnalyzer


A basic malware analyzer written in Python 3 with YARA integration and WPVULNDB among other functionalities. wpAnalyzer can bring to us information about malware code in Wordpress installation.

## Before starting

It's needed a installation of Yara in the host to make work wpAnalyzer yara rules functionalities; these are some simple instructions to install Yara:

Go to https://github.com/virustotal/yara/releases and clone or download the latest release of Yara:

	wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
	tar -zxvf v3.4.0.tar.gz
	cd yara-3.4.0/
	
Once in the main folder, install it:

	./bootstrap.sh
	./configure
	make
	sudo make install
	
Now we have a fresh install of Yara in the host, in addition we need the yara-python module.

To reach this requirement is recommended install this extension from the source, like we did with Yara so:

In the main folder of downloaded project:

	cd yara-python
	python setup.py build
	sudo python3 setup.py install
	
Extrated from Yara documentation (needed in Debian-Like):

*If you get an error like this:*

	yara: error while loading shared libraries: libyara.so.2: cannot open shared object file: No such file or directory

*It means that the loader is not finding the libyara library which is located in /usr/local/lib. In some Linux flavors the loader doesn’t look for libraries in this path by default, we must instruct him to do so by adding /usr/local/lib to the loader configuration file /etc/ld.so.conf:*

	sudo echo "/usr/local/lib" >> /etc/ld.so.conf
	sudo ldconfig


## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

## Deployment

It is required that wpAnalyzer be in the main directory of the target site for analisis.