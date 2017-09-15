#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <mcrypt.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

/* Size of the read buffer */
#define READ_BUFFER_SIZE 4096

/* The original terminal attributes */
static struct termios saved_attributes;

/* File descriptor of the network sock */
static int sockfd;

/* File descriptor of the log file */
static int ofd;

/* Secure key used for both encryption and decryption */
static char *key;

static MCRYPT td;
static char *IV;

void reset_input_mode()
{
  tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes);
}

void set_input_mode()
{
  struct termios tattr;

  /* Make sure stdin is a terminal */
  if (!isatty(STDIN_FILENO))
    {
      fprintf(stderr, "Error: stdin is not a terminal: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

  /* Save the terminal attributes so we can restore them later */
  tcgetattr(STDIN_FILENO, &saved_attributes);
  atexit(reset_input_mode);

  /* Set the terminal modes */
  tcgetattr(STDIN_FILENO, &tattr);
  tattr.c_iflag = ISTRIP;
  tattr.c_oflag = 0;
  tattr.c_lflag = 0;
  tcsetattr(STDIN_FILENO, TCSANOW, &tattr);
}

/* Convert integer to string and return the number of digits */
size_t int_to_string(char *str, ssize_t integer)
{
  char *p = str;
  ssize_t temp = integer;

  do
    {
      *p++ = '0' + temp % 10;
      temp /= 10;
    } while(temp);

  size_t ret = p - str;

  while(str < --p)
    {
      char temp = *str;
      *str++ = *p;
      *p = temp;
    }

  return ret;
}

/* Used to catch the SIGPIPE signal after the server has been shutdown */
void sig_handler(int signo)
{
  if(signo == SIGPIPE)
    {
      if(key != NULL)
	{
	  /* Deinitialize encryption and decryption */
	  mcrypt_generic_deinit(td);
	  mcrypt_module_close(td);
	  free(key);
	  free(IV);
	}
	
      exit(EXIT_SUCCESS);
    }
}

void *read_from_sock(void *arg)
{
  char read_buffer[READ_BUFFER_SIZE];
  ssize_t bytes_read;
  
  while((bytes_read = read(sockfd, read_buffer, READ_BUFFER_SIZE)) > 0)
    {
      /* Write to the log file */
      if(ofd != 0)
	{
	  char *bytes = malloc(3);
	  size_t size = int_to_string(bytes, bytes_read);
	  
	  write(ofd, "RECEIVED: ", 10);
	  write(ofd, bytes, size);
	  write(ofd, " bytes: ", 8);
	  write(ofd, read_buffer, bytes_read);
	  write(ofd, "\n", 1);

	  free(bytes);
	}

      /* Write to standard output */
      for(int i = 0; i < bytes_read; i++)
	{
	  char ic = read_buffer[i];
	  if(key != NULL)
	    {
	      mdecrypt_generic(td, &ic, 1);
	    }
	  if(ic == '\n')
	    {
	      write(STDOUT_FILENO, "\r\n", 2);
	    }
	  else
	    {
	      write(STDOUT_FILENO, &ic, 1);
	    }
	}
    }
  
  return NULL;
}

int main(int argc, char **argv)
{
  signal(SIGPIPE, sig_handler);

  /* Read options */
  static struct option long_options[] =
    {
      {"port",    required_argument, 0, 'p'},
      {"log",     required_argument, 0, 'l'},
      {"encrypt", required_argument, 0, 'e'},
      {0, 0, 0, 0}
    };

  int opt;
  uint16_t port_number = 0;
  char *filename = NULL, *keyfile = NULL;

  while((opt = getopt_long(argc, argv, "p:l:", long_options, NULL)) != -1)
    {
      switch(opt)
	{
	case 'p':
	  port_number = atoi(optarg);
	  if(port_number <= 1024) {
	    fprintf(stderr, "Error: port numbers below 1024 are reserved\n");
	    exit(EXIT_FAILURE);
	  }
	  break;
	case 'l':
	  filename = optarg;
	  break;
	case 'e':
	  keyfile = optarg;
	  break;
	case '?':
	default:
	  exit(EXIT_FAILURE);
	}
    }

  if(!port_number)
    {
      fprintf(stderr,
	      "Error: the program requires a mandatory '--port' argument\n");
      exit(EXIT_FAILURE);
    }
  
  if(filename != NULL)
    {
      if((ofd = creat(filename, 0666)) == -1)
	{
	  fprintf(stderr, "Error occurred while creating a file: %s\n",
		  strerror(errno));
	  exit(EXIT_FAILURE);
	}
    }

  if(keyfile != NULL)
    {
      /* Open the key file */
      int ifd = open(keyfile, O_RDONLY);

      if(ifd == -1)
	{
	  fprintf(stderr, "Error occurred while opening the key file: %s\n",
		  strerror(errno));
	  exit(EXIT_FAILURE);
	}

      /* Read the key file */
      struct stat st;
      stat(keyfile, &st);
      char *keybuf = malloc(st.st_size);
      
      if(read(ifd, keybuf, st.st_size) == -1)
	{
	  fprintf(stderr, "Error occurred while reading the key file: %s\n",
		  strerror(errno));
	  exit(EXIT_FAILURE);
	}

      key = keybuf;

      /* Initialize encryption and decryption */
      td = mcrypt_module_open("twofish", NULL, "cfb", NULL);
      IV = malloc(mcrypt_enc_get_iv_size(td));
      memset(IV, 0, sizeof(char) * mcrypt_enc_get_iv_size(td));
      mcrypt_generic_init(td, (void *)key, sizeof(key), (void *)IV);
    }

  /* Setup of the network socket */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if(sockfd == -1)
    {
      fprintf(stderr, "Error occurred while creating a socket: %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }

  struct hostent *server = gethostbyname("localhost");

  if(server == NULL)
    {
      fprintf(stderr, "Error: no such host\n");
      exit(EXIT_FAILURE);
    }

  struct sockaddr_in serv_addr;

  bzero((char *)&serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port_number);
  bcopy((char *)server->h_addr,
	(char *)&serv_addr.sin_addr.s_addr, server->h_length);

  /* Connect to the server */
  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
      fprintf(stderr, "Error occurred while connecting to the server: %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }

  /* Setup of non-canonical input mode */
  set_input_mode();

  /* Create a thread that reads from the network sock */
  pthread_t tid;
  pthread_create(&tid, NULL, read_from_sock, NULL);

  char read_buffer[READ_BUFFER_SIZE];
  ssize_t bytes_read;

  while((bytes_read = read(STDIN_FILENO, read_buffer, READ_BUFFER_SIZE)) > 0)
    {
      /* Write to the log file */
      if(ofd != 0)
	{
	  char *bytes = malloc(3);
	  size_t size = int_to_string(bytes, bytes_read);
	  
	  write(ofd, "SENT ", 5);
	  write(ofd, bytes, size);
	  write(ofd, " bytes: ", 8);

	  free(bytes);
	}

      /* Write to the network sock and also forward to standard output */
      for(int i = 0; i < bytes_read; i++)
	{
	  char ic = read_buffer[i];
	  if(ic == '\r' || ic == '\n')
	    {
	      write(STDOUT_FILENO, "\r\n", 2);
	      char temp_ic = '\n';
	      if(keyfile != NULL)
		{
		  mcrypt_generic(td, &temp_ic, 1);
		}
	      write(sockfd, &temp_ic, 1);
	      if(ofd != 0)
		{
		  write(ofd, &temp_ic, 1);
		}
	    }
	  else
	    {
	      if(ic != '\003' && ic != '\004')
		{
		  write(STDOUT_FILENO, &ic, 1);
		}
	      if(key != NULL)
		{
		  mcrypt_generic(td, &ic, 1);
		}
	      write(sockfd, &ic, 1);
	      if(ofd != 0)
		{
		  write(ofd, &ic, 1);
		}
	    }
	}
      
      if(ofd != 0)
	{
	  write(ofd, "\n", 1);
	}
    }
}
