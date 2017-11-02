/**
* Encrypted Network Shell
*
* Copyright (C) 2017 Yimin Yuan
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <mcrypt.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* Size of the read buffer */
#define READ_BUFFER_SIZE 4096

/* File descriptor of the network sock */
static int newsockfd;

/* Process ID */
static pid_t pid;

/* Secure key used for both encryption and decryption */
static char *key;

static MCRYPT td;
static char* IV;

void exit_handler(int exit_status)
{
  int status, shell_exit_status = 0;
      
  if(waitpid(pid, &status, 0) == -1)
    {
      fprintf(stderr, "Error occurred while waiting for process: %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }

  if(WIFEXITED(status))
    {
      shell_exit_status = WEXITSTATUS(status);
    }
  else if(WIFSIGNALED(status))
    {
      shell_exit_status = WTERMSIG(status);
    }

  fprintf(stderr, "SHELL EXIT SIGNAL=%d STATUS=%d\n",
	  0x7f & shell_exit_status, (0xff00 & shell_exit_status) >> 8);

  /* Deinitialize encryption and decryption */
  if(key != NULL)
    {
      mcrypt_generic_deinit(td);
      mcrypt_module_close(td);
      free(key);
      free(IV);
    }

  exit(exit_status);
}

void sig_handler(int signo)
{
  if(signo == SIGPIPE)
    {
      exit_handler(EXIT_SUCCESS);
    }
}

void *read_from_pipe(void *read_fd)
{
  int fd = *(int *)read_fd;
  char read_buffer[READ_BUFFER_SIZE];
  ssize_t bytes_read;
  
  while((bytes_read = read(fd, read_buffer, READ_BUFFER_SIZE)) > 0)
    {
      for(int i = 0; i < bytes_read; i++)
	{
	  char ic = read_buffer[i];
	  if(key != NULL)
	    {
	      mcrypt_generic(td, &ic, 1);
	    }
	  write(newsockfd, &ic, 1);
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
      {"encrypt", required_argument, 0, 'e'},
      {0, 0, 0, 0}
    };

  int opt;
  uint16_t port_number = 0;
  char *keyfile = NULL;

  while((opt = getopt_long(argc, argv, "p:e:", long_options, NULL)) != -1)
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
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if(sockfd == -1)
    {
      fprintf(stderr, "Error occurred while creating a socket: %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }

  struct sockaddr_in serv_addr, cli_addr;

  bzero((char *)&serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(port_number);

  if(bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
      fprintf(stderr, "Error occurred while binding a name to a socket: %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }

  if(listen(sockfd, 5) == -1)
    {
      fprintf(stderr,
	      "Error occurred while listening for socket connections: %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }

  socklen_t clilen = sizeof(cli_addr);
  newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);

  if(newsockfd == -1)
    {
      fprintf(stderr, "Error occurred while accepting a new connection: %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }

  /* pipe1: From terminal to shell */
  /* pipe2: From shell to terminal */
  int pipe1[2], pipe2[2];  

  /* Setup of two pipes */
  if(pipe(pipe1) == -1 || pipe(pipe2) == -1)
    {
      fprintf(stderr, "Error occurred while creating a pipe: %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }

  /* Create a child process that executes the commands */
  pid = fork();

  if(pid == -1)
    {
      fprintf(stderr, "Error occurred while creating a process: %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }

  if(pid == 0)
    {
      /* I/O redirection */
      dup2(pipe1[0], STDIN_FILENO);
      dup2(pipe2[1], STDOUT_FILENO);
      dup2(pipe2[1], STDERR_FILENO);

      /* Close unused file descriptors */
      close(pipe1[0]);
      close(pipe1[1]);
      close(pipe2[0]);
      close(pipe2[1]);
      close(sockfd);

      execlp("/bin/bash", "/bin/bash", NULL);
    }
  else
    {
      /* Close unused file descriptors */
      close(pipe1[0]);
      close(pipe2[1]);
      close(sockfd);
      
      /* Create a thread that reads from the pipe */
      pthread_t tid;
      pthread_create(&tid, NULL, read_from_pipe, &pipe2[0]);
    }

  char read_buffer[READ_BUFFER_SIZE];
  ssize_t bytes_read;

  /* Read from stdin and write to stdout/pipe */
  while((bytes_read = read(newsockfd, read_buffer, READ_BUFFER_SIZE)) > 0)
    {
      for(int i = 0; i < bytes_read; i++)
	{
	  char ic = read_buffer[i];
	  if(key != NULL)
	    {
	      mdecrypt_generic(td, &ic, 1);
	    }
	  if(ic == '\003')
	    {
	      kill(pid, SIGINT);
	    }
	  else if(ic == '\004')
	    {
	      close(pipe1[1]);
	      kill(pid, SIGHUP);
	      exit_handler(EXIT_SUCCESS);
	    }
	  else
	    {
	      write(pipe1[1], &ic, 1);
	    }
	}
    }  
}
