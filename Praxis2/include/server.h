#pragma once

#include <stdbool.h>
#include <sys/socket.h>

#include "packet.h"
#include "util.h"

#define CB_REMOVE_CLIENT (-1)
#define CB_OK 0

typedef enum _cstate { IDLE, HDR_RECVD, REMOVE } client_state;

typedef struct _client {
    int socket;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    client_state state;
    ring_buffer *header_buf;
    ring_buffer *pkt_buf;
    packet *pack;
    struct _client *next;
} client;

typedef struct _server {
    int socket;
    int n_clients;
    bool active;
    struct _client *clients;
    int (*packet_cb)(struct _server *srv, struct _client *c, packet *p);
} server;

void server_close_socket(server *srv, int socket);

server *server_setup(char *port);
void server_run(server *srv);
