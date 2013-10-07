
Contents: 
	REQUIREMENTS
	INSTALLATION
		libdns
		examples
		drill
	INFORMATION FOR SPECIFIC OPERATING SYSTEMS
		Mac OS X
		Solaris

Project page:
http://www.nlnetlabs.nl/ldns/
On that page you can also subscribe to the ldns mailing list.

* Development 
ldns is mainly developed on Linux and FreeBSD. It is regularly tested to
compile on other systems like Solaris and Mac OS X.

REQUIREMENTS
- OpenSSL (Optional, but needed for features like DNSSEC)
- libpcap (Optional, but needed for examples/ldns-dpa)
- (GNU) libtool (in OSX, that's glibtool, not libtool)
- GNU make

INSTALLATION
1. Unpack the tarball
2. cd ldns-<VERSION>
3. ./configure
4. gmake (it needs gnu make to compile, on systems where GNU make is the
   default you can just use 'make')
5. sudo gmake install
6. Optional. (cd examples; ./configure; gmake), make example programs included.
7. Optional. (cd drill; ./configure; gmake; gmake install), to build drill.

You can configure and compile it in a separate build directory.

* Examples
There are some examples and dns related tools in the examples/ directory.
These can be built with:
1. cd examples/
2. ./configure [--with-ldns=<path to ldns installation or build>]
3. gmake

* Drill
Drill can be built with:
1. cd drill/
2. ./configure [--with-ldns=<path to ldns installation or build>]
3. gmake

Note that you need to set LD_LIBRARY_PATH if you want to run the binaries
and you have not installed the library to a system directory. You can use
the make target all-static for the examples to run them if you don't want to
install the library.


* Building from subversion repository

If you are building from the repository you will need to have (gnu)
autotools like libtool and autoreconf installed. A list of all the commands
needed to build everything can be found in README.svn. Note that the actual
commands may be a little bit different on your machine. Most notable, you'll need to run libtoolize (or glibtoolize), if you skip this step, you'll get an error about missing config.sub.

* Developers
ldns is developed by the ldns team at NLnet Labs. This team currently
consists of:
  o Jelte Jansen
  o Wouter Wijngaards

Former main developers:
  o Miek Gieben

* Credits
We have received patches from the following people, thanks!
  o Erik Rozendaal
  o Håkan Olsson
  o Jakob Schlyter
  o Paul Wouters
  o Simon Vallet
  o Ondřej Surý


IFORMATION FOR SPECIFIC OPERATING SYSTEMS

MAC OS X

For MACOSX 10.4 and later, it seems that you have to set the
MACOSX_DEPLOYMENT_TARGET environment variable to 10.4 before running
make. Apparently it defaults to 10.1.

This appears to be a known problem in 10.2 to 10.4, see:
http://developer.apple.com/qa/qa2001/qa1233.html
for more information.


SOLARIS

In Solaris multi-architecture systems (that have both 32-bit and
64-bit support), it can be a bit taxing to convince the system to
compile in 64-bit mode. Jakob Schlyter has kindly contributed a build
script that sets the right build and link options. You can find it in
contrib/build-solaris.sh

