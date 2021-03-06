# Encrypted Network Shell
A multi-process telnet-like server and client.
## Getting Started
Please make sure the following dependencies have been installed before compiling.
### Dependencies
* [MCrypt](http://mcrypt.sourceforge.net/) - A thread-safe encryption algorithms library.
### Installing
For example, on Fedora, you can install MCrypt library by using this command:
```
$ sudo dnf install libmcrypt-devel
```
## Usage
You can compile the code by simply running:
```
$ make
```
and delete the executable programs by using:
```
$ make clean
```
### Options
**server**
* --encrypt=filename
* --port=# (Mandatory option)

**client**
* --encrypt=filename
* --log=filename
* --port=# (Mandatory option)

For the key file, you can write any string in a plain text file. Also, the port number must be greater than 1024.
### Running
Assume the port number is 8000. First, you should run the server by using this command:
```
$ ./server --port=8000
```
Then run the client by using this command:
```
$ ./client --port=8000
```
Finally, type any command in the client and see what happens. :)

You can type Ctrl+D to shutdown the server and Ctrl+C to send a SIGINT to the server.
### Notice
* The key file names and the port numbers must match.
* If you specify both --encrypt and --log options, the log file will store encrypted unreadable info.
* Since the client is running with non-canonical input mode, the "escape" or "delete" key will be treated as a character.
## Acknowledgments
This code demo was modified based on my course project 1B: Encrypted Network Communication of CS 111: Operating Systems Principles at University of California, Los Angeles. You can check out the [spec](https://lasr.cs.ucla.edu/classes/cs111_summer2017/projects/p1/P1B.html) if you are interested in.