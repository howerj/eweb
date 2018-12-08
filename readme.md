# eweb

This is an embeddable webserver, originally from
<https://github.com/davidsblog/dweb/>. Modifications have been made to it,
mostly for portability reasons. Modifications are released under the same
license as the original, the MIT license.

This project is a work in progress.

## To Do

* [ ] Cleanup project
  * [ ] API changes (callbacks, error codes)
  * [x] Change logo
  * [x] Change favicon
  * [x] Change project references
* [x] Remove gnu99 features
* [ ] Separate out operating system dependencies
  * [x] Create callback mechanism
  * [x] Make a Unix file, containing operating system specific components
  * [ ] Port to Windows
* [ ] Lint the code
* [ ] Make a version that communicates via standard in/standard out to
  facilitate fuzzing
* [ ] Allow multiple web servers to run at the same time
* [ ] More assertions
* [ ] Make code const correct
* [ ] Error codes should be used throughout, and errors caught instead of
  ignored.
* [ ] Integrate <https://github.com/howerj/pickle> for CGI applications.
* [ ] Add a custom block allocator, for embedded use.
* [ ] Integrate with <https://cr.yp.to/cdb.html>
* [ ] Demonstration code should restore terminal settings, or not mess them
  up on failure
* [ ] Add getopt
* [ ] Add manual page
* [ ] Add basic authentication
* [ ] Add optional HTTPS support
* [ ] Turn into a library
* [ ] Make the web server robust in the face of an Out Of Memory condition,
  it should release any memory and indicate failure.

# The Original README.md file

There original *readme.md* follows.

## dweb

A lightweight webserver for C programs, *with no dependencies* which
should work on Linux, Unix, Mac OS, etc.  I'm planning to use it as
a very small Web API, most likely hosted on a Raspberry Pi or a cheap
router running OpenWrt, probably both :-).  I'm just trying to implement
enough of the HTTP protocol to work with the main browsers, so if you're
looking for a complete implementation of the HTTP protocol, then dweb
is not what you want...

The idea is to be able to serve dynamic web content from simple C
programs, without having to write much extra code.  In fact, *dweb* is a
single **C** source file, which is all you need to add to your project.
So the trivial example (serving a static page) looks like this:

	void test_response(struct hitArgs*, char*, char*, http_verb);

	int main(int argc, char **argv)
	{
		if (argc != 2 || !strcmp(argv[1], "-?"))
		{
			printf("hint: dweb [port number]\n");
			exit(0);
		}
		// start the server:
		dwebserver(atoi(argv[1]), &test_response, NULL);
	}

	// send the same response to any request
	void test_response(struct hitArgs *args, char *path, char *request_body, http_verb type)
	{
		ok_200(args, "\nContent-Type: text/html",
			"<html><head><title>Test Page</title></head>"
			"<body><h1>Testing...</h1>This is a test response.</body>"
			"</html>", path);
	}

I owe a lot to nweb:
http://www.ibm.com/developerworks/systems/library/es-nweb/index.html
which was my starting point.  But I am allowing extra things like HTTP
POSTs and serving dynamic content.  Unlike nweb, this code does not run
as a daemon, and logging goes to the console by default, although you
can override the logging function and do something else if you like.


## Building

To build the example program, which uses jQuery, allows HTML Form values
to be posted back, and gives dynamic responses, just type *make*
and you can then run *dweb* from the command line (you need to
specify the port number as the first parameter).

Alternatively, to just build the *trivial* example (as shown above)
you can type *make simple* and then run *simple* from the
command line.

## Request Size

The maximum bytes read from the incoming request is set using the
*#define* parameter *MAX_INCOMING_REQUEST* and this value
*includes* the HTTP headers.  The default is **4096** bytes.  If you need
to have requests bigger than this you will need to increase that value.

## License

See <https:github.com/howerj/eweb/LICENSE>.

