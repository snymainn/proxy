## Description

This is a simple proxy daemon that allows you to forward TCP requests hitting a specified port on the localhost to a different port on another remote host. 
On the return channel it uses a file buffer to avoid losing data when transfer back to the client making the request is slower than rate from remote host to localhost.
client->port on localhost->port on remote host->localhost->buffer file->client
This means that there are one main process accepting new connections
Each new connection will fork three new processes:
- Incoming data from client->localhost->remote host
- Data from remote host->localhost_file
- Data from localhost_file->client

This proxy is made to support transport of satellite data from a baseband modem (like Cortex CRT) on a ground station back to a satellite operator. This often involves a single request to a specific port on the modem and getting a stream of data back. 

It accepts multiple connections, each connection makes use of one file and three processes.

## Installation

Download the proxy_diskbuffer.c file and compile with "
```
gcc proxy_diskbuffer.c -o proxy_diskbuffer
```
or clone the whole repo and compile with 
``` 
make
```

## Basic usage

Command line syntax goes as follows:
```
proxy_diskbuffer -t buffer_filename -l local_port -h remote_host -p remote_port [-f (stay in foreground)]
```
Example with output to logfile:
```
proxy_diskbuffer -t /data/proxy_buffer -l 3170 -h <ip> -p 3070 > proxy_diskbuffer.log 2>&1
```
Normally, proxy forks into the background. To make it stay in the foreground (for example for debugging purposes), use "-f" switch.

Each connection will add an index to the buffer file like this for the first connection: proxy_buffer_01


