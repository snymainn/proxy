/*
 * Tiny TCP proxy server
 *
 * Author: Krzysztof Kliś <krzysztof.klis@gmail.com>
 * Fixes and improvements: Jérôme Poulin <jeromepoulin@gmail.com>
 * IPv6 support: 04/2019 Rafael Ferrari <rafaelbf@hotmail.com>
 * Diskbuffer: 10/2020 Tommy Skagemo-Andreassen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version with the following modification:
 *
 * As a special exception, the copyright holders of this library give you
 * permission to link this library with independent modules to produce an
 * executable, regardless of the license terms of these independent modules,
 * and to copy and distribute the resulting executable under terms of your choice,
 * provided that you also meet, for each linked independent module, the terms
 * and conditions of the license of that module. An independent module is a
 * module which is not derived from or based on this library. If you modify this
 * library, you may extend this exception to your version of the library, but
 * you are not obligated to do so. If you do not wish to do so, delete this
 * exception statement from your version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#ifdef USE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#define BUF_SIZE 16384

#define READ  0
#define WRITE 1

#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define CLIENT_SOCKET_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define CLIENT_CONNECT_ERROR -7
#define CREATE_PIPE_ERROR -8
#define BROKEN_PIPE_ERROR -9
#define SYNTAX_ERROR -10

typedef enum {TRUE = 1, FALSE = 0} bool;

int check_ipversion(char * address);
int create_socket(int port);
void sigchld_handler(int signal);
void sigterm_handler(int signal);
void server_loop();
void handle_client(int client_sock, struct sockaddr_storage client_addr, int connections);
void get_data_to_file(int source_sock, char *filepath, int connection);
void forward_data_from_file(char *filepath, int destination_sock, int connection);
void forward_data(int source_sock, int destination_sock, int connection);
int create_connection();
int parse_options(int argc, char *argv[]);
void plog(int priority, const char *format, ...);

int server_sock, client_sock, remote_sock, remote_port = 0;
int connections_processed = 0;
char *bind_addr, *remote_host, *cmd_in, *cmd_out, *tmp_filepath, *buffer_filepath;
bool foreground = FALSE;
bool use_syslog = FALSE;

#define BACKLOG 20 // how many pending connections queue will hold

/* Program start */
int main(int argc, char *argv[]) {
    int local_port;
    pid_t pid;

    bind_addr = NULL;
    buffer_filepath = malloc(strlen("/tmp/proxy_buffer")+1);
    strcpy(buffer_filepath, "/tmp/proxy_buffer");

    local_port = parse_options(argc, argv);

    if (local_port < 0) {
        printf("Syntax: %s [-b bind_address] -l local_port -h remote_host -p remote_port [-f (stay in foreground)] [-s (use syslog) [-t buffer_filename(default /tmp/proxy_buffer)]\n", argv[0]);
        return local_port;
    }

    if (use_syslog)
        openlog("proxy", LOG_PID, LOG_DAEMON);

    if ((server_sock = create_socket(local_port)) < 0) { // start server
        plog(LOG_CRIT, "Cannot run server: %m");
        return server_sock;
    }

    signal(SIGCHLD, sigchld_handler); // prevent ended children from becoming zombies
    signal(SIGTERM, sigterm_handler); // handle KILL signal

    if (foreground) {
        server_loop();
    } else {
        switch(pid = fork()) {
            case 0: // deamonized child
                server_loop();
                break;
            case -1: // error
                plog(LOG_CRIT, "Cannot daemonize: %m");
                return pid;
            default: // parent
                close(server_sock);
        }
    }

    if (use_syslog)
        closelog();

    return EXIT_SUCCESS;
}

/* Parse command line options */
int parse_options(int argc, char *argv[]) {
    int c, local_port = 0;

    while ((c = getopt(argc, argv, "b:l:h:p:fst:")) != -1) {
        switch(c) {
            case 'l':
                local_port = atoi(optarg);
                break;
            case 'b':
                bind_addr = optarg;
                break;
            case 'h':
                remote_host = optarg;
                break;
            case 'p':
                remote_port = atoi(optarg);
                break;
            case 'f':
                foreground = TRUE;
                break;
            case 's':
                use_syslog = TRUE;
                break;
            case 't':
                tmp_filepath = optarg;
                buffer_filepath = (char *) realloc(buffer_filepath, strlen(tmp_filepath)+1);
                memset(buffer_filepath, '\0', sizeof(buffer_filepath));
                strcpy(buffer_filepath, tmp_filepath);
                plog(LOG_INFO, "Got temp filename from arguments : %s", buffer_filepath);
                break;
        }
    }

    if (local_port && remote_host && remote_port) {
        return local_port;
    } else {
        return SYNTAX_ERROR;
    }
}

int check_ipversion(char * address)
{
/* Check for valid IPv4 or Iv6 string. Returns AF_INET for IPv4, AF_INET6 for IPv6 */

    struct in6_addr bindaddr;

    if (inet_pton(AF_INET, address, &bindaddr) == 1) {
         return AF_INET;
    } else {
        if (inet_pton(AF_INET6, address, &bindaddr) == 1) {
            return AF_INET6;
        }
    }
    return 0;
}

/* Create server socket */
int create_socket(int port) {
    int server_sock, optval = 1;
    int validfamily=0;
    struct addrinfo hints, *res=NULL;
    char portstr[12];

    memset(&hints, 0x00, sizeof(hints));
    server_sock = -1;

    hints.ai_flags    = AI_NUMERICSERV;   /* numeric service number, not resolve */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* prepare to bind on specified numeric address */
    if (bind_addr != NULL) {
        /* check for numeric IP to specify IPv6 or IPv4 socket */
        if (validfamily = check_ipversion(bind_addr)) {
             hints.ai_family = validfamily;
             hints.ai_flags |= AI_NUMERICHOST; /* bind_addr is a valid numeric ip, skip resolve */
        }
    } else {
        /* if bind_address is NULL, will bind to IPv6 wildcard */
        hints.ai_family = AF_INET6; /* Specify IPv6 socket, also allow ipv4 clients */
        hints.ai_flags |= AI_PASSIVE; /* Wildcard address */
    }

    sprintf(portstr, "%d", port);

    /* Check if specified socket is valid. Try to resolve address if bind_address is a hostname */
    if (getaddrinfo(bind_addr, portstr, &hints, &res) != 0) {
        return CLIENT_RESOLVE_ERROR;
    }

    if ((server_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        return SERVER_SOCKET_ERROR;
    }


    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        return SERVER_SETSOCKOPT_ERROR;
    }

    if (bind(server_sock, res->ai_addr, res->ai_addrlen) == -1) {
            close(server_sock);
        return SERVER_BIND_ERROR;
    }

    if (listen(server_sock, BACKLOG) < 0) {
        return SERVER_LISTEN_ERROR;
    }

    if (res != NULL)
        freeaddrinfo(res);

    return server_sock;
}

/* Send log message to stderr or syslog */
void plog(int priority, const char *format, ...)
{
    va_list ap;
    time_t nowtime;
    struct tm logtime;
    char logtimestring[25];
    
    nowtime = time(NULL);

    gmtime_r(&nowtime, &logtime);
    strftime(logtimestring, sizeof(logtimestring)+1, "%Y-%m-%dT%H:%M:%S", &logtime);

    va_start(ap, format);

    if (use_syslog)
        vsyslog(priority, format, ap);
    else {
        if (priority == LOG_INFO) {
            printf("%s : ", logtimestring);
            vprintf(format, ap);
            printf("\n");
        } else {
            fprintf(stderr, "%s : ", logtimestring);
            vfprintf(stderr, format, ap);
            fprintf(stderr, "\n");
        }
    }

    va_end(ap);
    fflush(stderr);
    fflush(stdout);
}

/* Update systemd status with connection count */
void update_connection_count()
{
#ifdef USE_SYSTEMD
    sd_notifyf(0, "STATUS=Ready. %d connections processed.\n", connections_processed);
#endif
}

/* Handle finished child process */
void sigchld_handler(int signal) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* Handle term signal */
void sigterm_handler(int signal) {
    close(client_sock);
    close(server_sock);
    exit(0);
}

/* Main server loop */
void server_loop() {
    struct sockaddr_storage client_addr;
    socklen_t addrlen = sizeof(client_addr);

#ifdef USE_SYSTEMD
    sd_notify(0, "READY=1\n");
#endif

    while (TRUE) {
        update_connection_count();
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addrlen);
        if (fork() == 0) { // handle client connection in a separate process
            close(server_sock);
            handle_client(client_sock, client_addr, connections_processed);
            exit(0);
        } else
            connections_processed++;
        
        close(client_sock);
    }

}


/* Handle client connection */
void handle_client(int client_sock, struct sockaddr_storage client_addr, int connections)
{

    int get_pid, forward_pid, inc_pid;
    int errnum;
    char buffer_filepath_new[1024];

    if ((remote_sock = create_connection()) < 0) {
        plog(LOG_ERR, "Cannot connect to host: %m");
        goto cleanup;
    } else {
        plog(LOG_INFO, "Connected to cortex in connection : %d", connections);
    }

    snprintf(buffer_filepath_new, 1024, "%s_%d", buffer_filepath, connections);

    if (remove(buffer_filepath_new)==0) {
        plog(LOG_INFO, "File %s deleted before being used as a buffer again", buffer_filepath_new);
    } 

    if ((forward_pid = fork()) == 0) { // a process forwarding data from bufferfile to customer
        forward_data_from_file(buffer_filepath_new, client_sock, connections);
        close(client_sock); //Cleanup in case exit due to failed to write to socket
        exit(0);
    } else {
        plog(LOG_INFO, "Started process (pid=%d) that forward data from buffer to client", forward_pid);
    }

    if ((get_pid = fork()) == 0) { // a process reading from cortex and storing to file 
        get_data_to_file(remote_sock, buffer_filepath_new, connections);
        plog(LOG_INFO, "Read from Cortex/write to buffer process ended...");
        plog(LOG_INFO, "Stopping read from buffer/forward to client process(pid: %d) and prepare for new connection", forward_pid);
        kill(forward_pid, SIGHUP);
        exit(0);
    } else {
        plog(LOG_INFO, "Started process (pid=%d) that fetches data from cortex to file", get_pid);
    }

    if ((inc_pid=fork()) == 0) { // a process forwarding data from client/customer to remote socket (cortex)
        forward_data(client_sock, remote_sock, connections);
        plog(LOG_INFO, "Ended process that forward data from client to cortex");
        plog(LOG_INFO, "Will try to stop process (pid:%d) that fetch data from cortex to file", get_pid);
        kill(get_pid, SIGHUP); //Stop fetch from cortex process in case customer hangs up
        plog(LOG_INFO, "Will try to stop buffer/forward to client process(pid: %d)", forward_pid);
        kill(forward_pid, SIGHUP);
        exit(0);
    } else {
        plog(LOG_INFO, "Started process (pid=%d) that forward data from client to cortex", inc_pid);
    }

cleanup:
    plog(LOG_INFO, "Cleaning up remote(cortex) and client socket in second parent process");
    close(remote_sock);
    close(client_sock);
}


/* Get data from sockets */
void get_data_to_file(int source_sock, char *filepath, int connection) {
    ssize_t n;
    ssize_t w;

    char buffer[BUF_SIZE];
    FILE *fd;
    int errnum;
    fd_set rfds;
    time_t lastlogtime;
    double total_received, total_stored;
    
    fd = fopen(filepath, "w");
    if (fd == NULL) {
        errnum = errno;
        plog(LOG_ERR, "Failed to open file for writing %s, %s", filepath, strerror(errnum));
        exit(errnum);            
    } else {
        FD_ZERO(&rfds);
        FD_SET(fileno(fd), &rfds);
        plog(LOG_INFO, "Opened file %s for writing", filepath);
    }

    plog(LOG_INFO, "Starting to receive data from cortex in connection %d", connection);
    lastlogtime = time(NULL);
    while ((n = recv(source_sock, buffer, BUF_SIZE, 0)) > 0) { // read data from input socket
        if (n>0) {
            total_received += (double) n;
            w = write(fileno(fd), buffer, n);
            if (w < 0) {
                plog(LOG_ERR, "Failed to write to bufferfile: %m, connection %d", connection);
                close(fileno(fd));
                return;
            }
            total_stored += (double) w;
            if (time(NULL)-lastlogtime > 10) {
                lastlogtime = time(NULL);
                plog(LOG_INFO, "Every 10 sec log: received %.3g bytes from cortex, stored %.3g bytes to file, connection %d", total_received, total_stored, connection);
            }
        }
    }
    if (n < 0) {
        plog(LOG_ERR, "Failed receive from cortex: %m, %d", connection);
    }
    plog(LOG_INFO, "Stopping data reception from cortex, closing buffer file and cortex receive socket, connection %d", connection);
    shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
    close(source_sock);
    close(fileno(fd));
}


/* Forward data between sockets */
void forward_data_from_file(char *filepath, int destination_sock, int connection) {
    ssize_t n;
    ssize_t w;

    char buffer[BUF_SIZE];
    struct timeval tv;
    int retval;
    int errnum;
    FILE *fd;
    fd_set rfds;
    time_t lastlogtime;
    double total_sent = 0;
    double total_read = 0;
    

    // Open file descriptor
    int retries = 0;
    int eof_counter = 0;
    do {
        fd = fopen(filepath, "r");
        if (fd == NULL) {
            errnum = errno;
            if (retries > 3) {
                plog(LOG_ERR, "Failed to open file for reading, retry %d :  %s, %s", retries, filepath, strerror(errnum));
            }
            sleep(1);
            retries ++;
            if (retries > 10) {
                plog(LOG_ERR, "Max retries to open file %s, connection", filepath, connection);
                return;            
            }
        } else {
            retries = 0;
            plog(LOG_INFO, "Opened file for reading: %s, connection %d", filepath, connection);
            eof_counter = 0;
            lastlogtime = time(NULL);
            do {
                n = read(fileno(fd), buffer, BUF_SIZE);
                if (n < 0) {
                    plog(LOG_ERR, "Failed to read data from file: %m, connection %d", connection);
                    close(fileno(fd)); // Close file descriptor
                    return;
                } else if (n > 0) {
                    total_read += (double) n;
                    w = send(destination_sock, buffer, n, 0); // send data to output socket  
                    if (w < 0) {
                        plog(LOG_ERR, "Failed to write to client socket: %m, connection %d", connection);
                        close(fileno(fd)); // Close file descriptor
                        return;
                    }
                    eof_counter = 0;
                    total_sent += (double ) w;
                    if (time(NULL)-lastlogtime > 10) {
                        lastlogtime = time(NULL);
                        plog(LOG_INFO, "Every 10 sec log: read %.3g bytes from bufferfile, sent %.3g bytes to customer, connection %d", total_read, total_sent, connection);
                    }
                } else {
                    usleep(1000);
                    eof_counter ++;
                }
            } while (n>=0);
        }
    } while (fd == NULL && retries < 10);
    

    close(fileno(fd)); // Close file descriptor
    shutdown(destination_sock, SHUT_RDWR); // stop other processes from using socket
    close(destination_sock);
}

/* Forward data between sockets */
void forward_data(int source_sock, int destination_sock, int connection) {
    ssize_t n;

    char buffer[BUF_SIZE];

    while ((n = recv(source_sock, buffer, BUF_SIZE, 0)) > 0) { // read data from input socket
        send(destination_sock, buffer, n, 0); // send data to output socket
    }

    if (n < 0) {
        plog(LOG_ERR, "Failed to read from client incoming connection: %m, connection %d", connection);
        return;
    }

    shutdown(destination_sock, SHUT_RDWR); // stop other processes from using socket
    close(destination_sock);

    shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
    close(source_sock);
}

/* Create client connection */
int create_connection() {
    struct addrinfo hints, *res=NULL;
    int sock;
    int validfamily=0;
    char portstr[12];

    memset(&hints, 0x00, sizeof(hints));

    hints.ai_flags    = AI_NUMERICSERV; /* numeric service number, not resolve */
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    sprintf(portstr, "%d", remote_port);

    /* check for numeric IP to specify IPv6 or IPv4 socket */
    if (validfamily = check_ipversion(remote_host)) {
         hints.ai_family = validfamily;
         hints.ai_flags |= AI_NUMERICHOST;  /* remote_host is a valid numeric ip, skip resolve */
    }

    /* Check if specified host is valid. Try to resolve address if remote_host is a hostname */
    if (getaddrinfo(remote_host,portstr , &hints, &res) != 0) {
        errno = EFAULT;
        return CLIENT_RESOLVE_ERROR;
    }

    if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        return CLIENT_SOCKET_ERROR;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        return CLIENT_CONNECT_ERROR;
    }

    if (res != NULL)
      freeaddrinfo(res);

    return sock;
}
/* vim: set et ts=4 sw=4: */
