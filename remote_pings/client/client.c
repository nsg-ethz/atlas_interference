/**
 * @author	Thomas Holterbach
 * @email	thomasholterbach@gmail.com
 **/

/**
 * The client aims at starting ping measurements with different flow-id and towards 
 * several destinations using Scamper. Results, in warts format, will then
 * be redirected through pipes and sent to the server through a TCP connexion.
 **/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <endian.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1048576
#define PARAM_LENGTH1 12
#define PARAM_LENGTH2 128

/**
 * @brief	These macro print colored text
 **/
#define PRINT_INFO(...) fprintf(stderr, "[\033[0;34mINFO\033[0;m] " __VA_ARGS__)
#define PRINT_ERROR(...) fprintf(stderr, "[\033[0;31mERROR\033[0;m] " __VA_ARGS__)
#define PRINT_WARNING(...) fprintf(stderr, "[\033[0;33mWARNING\033[0;m] " __VA_ARGS__)

void parent_handler (int signum);
void child_handler (int signum);
void exit_properly (void);
void usage(void);
void print_debug (FILE * debug_fd, char * text);


int sockfd;					/* Socket use to communicate with the server */
long int nb_flow_id = 2;	/* Number of different flow id */
int ** pfd = NULL;			/* Pipes ends between parent and children */
unsigned int flow_id = 0;	/* Flow id processed by the current child */
pid_t * pid_tab;			/* Store children pid */
FILE * debug_fd = NULL;	    /* Debug file descriptor */

/* Structure containing the client parameters to send to the server */
struct client_info
{
	uint64_t nb_flow_id_n;		/* 64 bits big endian */
	char waiting_time[PARAM_LENGTH1];
	char nb_ping[PARAM_LENGTH1];
	char dst_filename[PARAM_LENGTH2];
	char debug_name[PARAM_LENGTH2];
	char server_inet_addr[PARAM_LENGTH2];
	uint64_t tv_sec;
	uint64_t tv_usec;
};


int main (int argc, char **argv)
{
	char * debug_name = "client.dbg";	/* Debug file name */
	char *waiting_time = "2";			/* Time between two pings with the same flow id */
	char *nb_ping = "20";				/* Number of ping to execute for a flow id */
	int server_port = 6700;				/* Server listening port */
	char *server_inet_addr = NULL;		/* Server IP address */
	int dst_fd;							/* Destination file descriptor */
	char *dst_filename = "dst_file";	/* Destination file name */
	struct sigaction sigact;			/* Sigaction structure */
	pid_t pid = -1;
	pid_t pid_scamper;					/* Scamper pid (sarted by children) */
	int c;
	ssize_t data_size;
	char buf[BUFFER_SIZE];


	while ((c = getopt (argc, argv, "f:w:n:s:p:d:b:")) != -1)
		switch (c)
		{
			case 'f':
				nb_flow_id = strtol(optarg, NULL, 10);
				break;
			case 'w':
				waiting_time = optarg;
				break;	
			case 'n':
				nb_ping = optarg;
				break;
			case 's':
				server_inet_addr = optarg;
				break;
			case 'p':
				server_port = strtol(optarg, NULL, 10);
				break;
			case 'd':
				dst_filename = optarg;
				break;
			case 'b':
				debug_name = optarg;
				break;
			default:
				usage();
				exit(EXIT_FAILURE);
		}

	/* Open (create if not) the debug file */
	if ((debug_fd = fopen (debug_name, "w")) == NULL)
	{
		PRINT_INFO ("Error when openning file client.dgb");
		exit (EXIT_FAILURE);
	}
	print_debug (debug_fd, "Starting client");

	if (server_inet_addr == NULL)
	{
		usage();
		exit(EXIT_FAILURE);
	}

	/* Create pipe between the parent and children */
	pfd = (int **) malloc (sizeof(int *) * nb_flow_id);
	for (long int i = 0; i < nb_flow_id; i++)
	{
		pfd[i] = (int *) malloc (sizeof(int) * 2);
		if (pipe(pfd[i]) == -1)
		{
			perror("pipe");
			exit(EXIT_FAILURE);
		}
		if (fcntl (pfd[i][1], F_SETPIPE_SZ, BUFFER_SIZE) == -1)
		{
			perror ("fcntl");
			exit (EXIT_FAILURE);
		}
	}

	/* Create array which will contain children pid */
	pid_tab = (pid_t *) malloc (sizeof(pid_t) * nb_flow_id);

	/* Start children. One child per flow id */	
	for (long int i = 0; i < nb_flow_id; i++)
	{
		if ((pid = fork()) < 0)
		{
			perror("fork");
			exit(EXIT_FAILURE);
		}
		else if (pid == 0)
		{
			flow_id = i;
			break;
		}
		else
			pid_tab[i] = pid;	/* Store children pid */
	}

	/** 
	 * Child part.
	 * Children run multiple instances of Scamper for ping several flow-id.
     * One scamper process per flow-id
	 * Scamper outputs are redirect to the parent in order to be sent to the server 
	 **/
	if (pid == 0)
	{
		/* Signal management for child */
		sigact.sa_handler = &child_handler;
		sigact.sa_flags = SA_RESTART;
		sigemptyset (&sigact.sa_mask);
		sigaction (SIGINT, &sigact, 0);

		/* Wait for the parent to receive the destination list */
		sigset_t mask_tmp;
		sigset_t orig_mask;
		struct timespec timeout;

		sigemptyset (&mask_tmp);
		sigaddset (&mask_tmp, SIGUSR1);

		if (sigprocmask (SIG_BLOCK, &mask_tmp, &orig_mask) < 0)
		{
			PRINT_ERROR ("sigprocmask : %s\n", strerror(errno));
			exit (EXIT_FAILURE);
		}

		/* Set the timer up to 5 seconds max */
		timeout.tv_sec = 5;
		timeout.tv_nsec = 0;
		
		/* Wait for a signal. The parent should send a SIGUSR1 if it has received the destinations list */
		if (sigtimedwait (&mask_tmp, NULL, &timeout) < 0)
		{
			if (errno == EAGAIN)
			{
				PRINT_ERROR ("Timeout : no destinations received. Stop.\n");
				kill (getppid(), SIGINT);
			}
			else if (errno == EINVAL)
			{
				PRINT_ERROR ("sigtimedwait : %s\n", strerror(errno));
				exit (EXIT_FAILURE);
			}
		}

		char ping_cmd[100];
		int sc_pipe[2];

		/* Dealing with pipe ends */
		close (pfd[flow_id][0]);	

		/* Create scamper command with the appropriate flow id */
		if (sprintf (ping_cmd, "ping -i %s -c %s -C %d", \
				waiting_time, nb_ping, flow_id+1) == -1)
		{
			fprintf(stderr, "Problem with sprintf. Exiting.");
			exit(EXIT_FAILURE);
		}

		while (1)
		{
			/* Create the pipe between the scamper process and the current process */
			if (pipe (sc_pipe) == -1)
			{
				perror ("pipe");
				exit(EXIT_FAILURE);
			}
			/* Increase its size up to BUFFER_SIZE */
			if (fcntl (sc_pipe[1], F_SETPIPE_SZ, BUFFER_SIZE) == -1)
			{
				perror ("fcntl");
				exit (EXIT_FAILURE);
			}

			/* Create the process that starts Scamper */
			if ((pid_scamper = fork()) < 0)
			{
				perror ("fork");
				exit(EXIT_FAILURE);
			}
			if (pid_scamper == 0)
			{
				/**
				 * This process will start ping measurements with scamper
				 */
				close (sc_pipe[0]);
				if (dup2(sc_pipe[1], STDOUT_FILENO) == -1)
				{
					perror("dup2");
					exit(EXIT_FAILURE);
				}

				/* Start ping measurement with Scamper */
				execlp ("scamper", "scamper", "-c", ping_cmd, "-f",
				dst_filename,"-O", "dlts","-O", "warts", (char *)NULL);

				/* Normally, we should never be here .. */
				PRINT_ERROR ("Scamper process not started");
				exit (EXIT_FAILURE);
			}
			/* Parent part */
			/* Close write end of the pipe and wait for the child terminaison */			
			close (sc_pipe[1]);	
			wait(NULL);		

			if ((data_size = read (sc_pipe[0], &buf, BUFFER_SIZE)) == -1)
			{
				PRINT_ERROR ("read : %s\n", strerror(errno));
				exit (EXIT_FAILURE);
			}

			/* Send warts data to the main process */
			if ((write (pfd[flow_id][1], &data_size, sizeof(ssize_t))) == -1)
			{
				PRINT_ERROR ("write : %s\n", strerror(errno));
				exit (EXIT_FAILURE);
			}
			if ((write (pfd[flow_id][1], &buf, data_size)) == -1)
			{
				PRINT_ERROR ("write : %s\n", strerror(errno));
				exit (EXIT_FAILURE);
			}

			/* Close read end of the pipe */
			close (sc_pipe[0]);
		}
	}
	/* Parent */
	else if (pid > 0)
	{
		int max_fd;						/* Maximum value of file descriptors */
		ssize_t warts_size;				/* Size of warts data received by the child */
		int64_t warts_size_n;			/* Size of the warts in 64bit network format */
		struct sockaddr_in server_addr;
		fd_set children_fd;				/* Set of fd */
		struct timeval time_start;		/* Timestamp indicating when the client started */

		/* Signal management for the parent */
		bzero (&sigact, sizeof (struct sigaction));
		sigact.sa_handler = &parent_handler;
		sigact.sa_flags = SA_SIGINFO;
		sigemptyset (&sigact.sa_mask);
		sigaction (SIGINT, &sigact, 0);
		sigaction (SIGTERM, &sigact, 0);

		/* Close unused write end */
		for (long int i = 0; i < nb_flow_id; i++)
			close (pfd[i][1]);

		/* Initialization sockaddr_in structure */
		bzero (&server_addr, sizeof(struct sockaddr_in));
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons (server_port);
		if (inet_aton (server_inet_addr, &(server_addr.sin_addr)) == 0)
		{
			PRINT_ERROR ("IP adresse not valid\n");
			print_debug (debug_fd, "IP address not valid. Stop.\n");
			exit_properly ();
		}

		PRINT_INFO("Trying to connect to the server ...\n");
		print_debug (debug_fd, "Trying to connect to the server ...\n");
		/* Create the socket for the communication with the server */	
		if ((sockfd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
		{
			PRINT_ERROR ("socket : %s\n", strerror(errno));
			print_debug (debug_fd, "Socket problem. Stop.\n");
			exit_properly ();
		}

		/* Connect to the server */
		if ((connect (sockfd, (struct sockaddr *)(&server_addr), sizeof(struct sockaddr_in))) == -1)
		{
			PRINT_ERROR ("connect : %s\n", strerror(errno));
			print_debug (debug_fd, "Connect problem. Stop.");
			exit_properly ();
		}
		PRINT_INFO("Connected !\n");		
		print_debug (debug_fd, "Connected to the server");

		/* Send the parameters of this client to the server */
		if (gettimeofday (&time_start, NULL) == -1)
		{
			PRINT_ERROR ("gettimeofday : %s\n", strerror(errno));
			print_debug (debug_fd, "Gettimeofday problem. Stop.");
			exit_properly ();
		}
		struct client_info params;
		params.nb_flow_id_n = htobe64 (nb_flow_id);
		strncpy (params.waiting_time, waiting_time, PARAM_LENGTH1);
		strncpy (params.nb_ping, nb_ping, PARAM_LENGTH1);
		strncpy (params.dst_filename, dst_filename, PARAM_LENGTH2);
		strncpy (params.debug_name, debug_name, PARAM_LENGTH2);
		strncpy (params.server_inet_addr, server_inet_addr, PARAM_LENGTH2);
		params.tv_sec = htobe64 ((long int)time_start.tv_sec);
		params.tv_usec = htobe64 ((long int)time_start.tv_usec);
		if ((data_size = write (sockfd, &params, sizeof(struct client_info))) == -1)
		{
			PRINT_ERROR ("write : %s\n", strerror(errno));
			print_debug (debug_fd, "Write problem. Stop.");
			exit_properly ();
		}
		print_debug (debug_fd, "Send parameters to the server ... OK ");

		/* Create or clean the file containing all the destinations */
		if ((dst_fd = open (dst_filename, O_CREAT|O_TRUNC, 
			S_IRWXU|S_IRWXG|S_IRWXO)) == -1)
		{
			PRINT_ERROR ("open : %s\n", strerror(errno));
			print_debug (debug_fd, "Cannot open file. Stop.");
			exit_properly ();
		}
		close (dst_fd);

		/* Create fd set, and wait for scamper processes results */
		max_fd = 0;
		for (long int i = 0; i < nb_flow_id; i++)
			if (pfd[i][0] > max_fd)
				max_fd = pfd[i][0];
		if (sockfd > max_fd)
			max_fd = sockfd;

		while (1)
		{
			FD_ZERO (&children_fd);
			for (long int i = 0; i < nb_flow_id; i++)
				FD_SET (pfd[i][0], &children_fd);	
			FD_SET (sockfd, &children_fd);	/* We also add the socket fd */


			if ((select (max_fd + 1, &children_fd, NULL, NULL, NULL)) < 0)
			{
				PRINT_ERROR ("select : %s\n", strerror(errno));
				print_debug (debug_fd, "Select problem. Stop.");
				exit_properly ();	
			}

			for (long int i = 0; i < nb_flow_id; i++)
			{
				if (FD_ISSET (pfd[i][0], &children_fd))
				{
					/* Read warts data from the child process */
					if ((read (pfd[i][0], &data_size, sizeof(ssize_t))) == -1)
					{
						PRINT_ERROR ("read : %s\n", strerror(errno));
						print_debug (debug_fd, "Read pipe problem. Stop.");
						exit_properly ();
					}
					if ((warts_size = read (pfd[i][0], buf, data_size)) == -1)
					{
						PRINT_ERROR ("read : %s\n", strerror(errno));
						print_debug (debug_fd, "Read pipe problem. Stop.");
						exit_properly ();
					}

					/* Send warts data to the server */
					warts_size_n = htobe64 (warts_size);
					if ((data_size = write (sockfd, &warts_size_n, sizeof(int64_t))) == -1)
					{
						PRINT_ERROR ("write : %s\n", strerror(errno));
						print_debug (debug_fd, "write1 problem. Stop.");
						exit_properly ();
					}
					if ((data_size = write (sockfd, buf, warts_size)) == -1)
					{
						PRINT_ERROR ("write : %s\n", strerror(errno));
						print_debug (debug_fd, "Write2 problem. Stop.");
						exit_properly ();
					}
				}
			}
			if (FD_ISSET (sockfd, &children_fd))
			{
				/* Received data from the server */
				if ((data_size = read (sockfd, buf, BUFFER_SIZE)) == -1)
				{
					PRINT_ERROR ("read : %s\n", strerror(errno));
					print_debug (debug_fd, "Read socket problem. Stop.");
					exit_properly ();
				}
				if (data_size == 0)
				{
					PRINT_INFO ("Server has been deconnected. Stop.\n");
					print_debug (debug_fd, "Server has been deconnected. Stop.\n");
					exit_properly ();
				}
				else
				{
					/* Open the file and write the new destinations inside */
					if ((dst_fd = open (dst_filename, O_WRONLY|O_APPEND, 
						S_IRWXU|S_IRWXG|S_IRWXO)) == -1)
					{
						PRINT_ERROR ("open : %s\n", strerror(errno));
						print_debug (debug_fd, "Cannot open file. Stop.");
						exit_properly ();
					}
					else
					{
						print_debug (debug_fd, buf);
						/* Write the destinations IP in the dst file */
						if (write (dst_fd, buf, data_size) != data_size)
						{
						print_debug (debug_fd, "Cannot write in the file. Stop.");
							exit_properly ();
						}
						close (dst_fd);
					}	
					for (int i = 0; i < nb_flow_id; i++)
						kill (pid_tab[i], SIGUSR1);

				}
			}
		}
	}

	return 0;
}

void child_handler (int signum)
{
	if (signum == SIGINT)
	{
		/* Close pipes end */
		close(pfd[flow_id][1]);

		//wait(NULL);
		exit (EXIT_SUCCESS);
	}
}

void parent_handler (int signum)
{
	char buf_tmp[100];
	sprintf (buf_tmp, "Signal %d received", signum);
	print_debug (debug_fd, buf_tmp);

	if (signum == SIGINT || signum == SIGTERM)
	{
		print_debug (debug_fd, "Signal SIGINT or SIGTERM received. Stop.\n");

		/* Stop all the children processes by sending SIGINT to the process group ID */
		kill (-1*getpgid(0), SIGINT);

		/* Wait the terminaison of the children */
		wait(NULL);		

		close (sockfd);	
	
		/* Close pipes end */
		for (long int i = 0; i < nb_flow_id; i++)
			close (pfd[i][1]);

		exit (EXIT_SUCCESS);
	}
}

void exit_properly ()
{
	parent_handler (SIGINT);
}


void usage(void)
{
	printf ("The client aims at performing ping measurements for different flow-ID using Scamper.\n");
	printf ("Each scamper process performs ping for one flow-ID.\n");
	printf ("Scamper output is regularly sent to server, depending on the user parameter (see options).\n");
	//printf ("A scamper process performs a specific number of ping before it stops and returns the result\n");
	//printf ("When completed, scamper's output is redirected to a socket in orer to be store in a database\n");

	printf ("Maximum scamper output size is %d bytes\n", BUFFER_SIZE);
	
	printf ("Options are :\n" \
	" -s\tServer IP address\n" \
	" -p\tServer port\n" \
	" -f\tNumber of flow ids\n" \
	" -n\tUpdate frequency with the collector (in number of pings, for example 10 indicates that every 10 pings results are sent to the collector).\n" \
	" -w\tPing frequency for each flow-id (1 means 1 ping/s for each flow-id).\n" \
	" -d\tFile containing destinations IP. Destinations IP are automaticaly sent by the server when the connexion is established.\n" \
	" -b\tDebug file name (optional)\n");	
}

void print_debug (FILE * dbg_fd, char * text)
{
	time_t rawtime;
	struct tm * timeinfo;
	char buffer[100];

	time (&rawtime);
	timeinfo = localtime (&rawtime);
	strftime (buffer, 100, "%Y-%m-%d %H:%M:%S", timeinfo);

	/* Write text in the debugging file */
	fprintf (dbg_fd, "[%s] ", buffer);
	fprintf (dbg_fd, "%s", text);
	fprintf (dbg_fd, "\n");

	fflush (dbg_fd);
}
