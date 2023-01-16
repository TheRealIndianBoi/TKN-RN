//
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "neighbour.h"
#include "packet.h"

peer *peer_init(uint16_t id, const char *hostname, const char *port) {
    peer *p = (peer *)malloc(sizeof(peer));
    memset(p, 0, sizeof(peer));
    p->node_id = id;
    p->hostname = strdup(hostname);

    long int tmp = strtol(port, NULL, 10);
    if (errno != EXIT_SUCCESS || tmp > UINT16_MAX) {
        fprintf(stderr, "Unable to convert string to port number!\n");
        peer_free(p);
        return NULL;
    }

    p->port = tmp;
    p->socket = -1;
    return p;
}

void peer_free(peer *p) {
    free(p->hostname);
    free(p);
}

peer *peer_from_packet(const packet *pack) {
    peer *p = (peer *)malloc(sizeof(peer));
    memset(p, 0, sizeof(peer));

    char *fakehostname = (char *)malloc(INET_ADDRSTRLEN);

    struct in_addr pack_addr;
    memset(&pack_addr, 0, sizeof(struct in_addr));
    pack_addr.s_addr = htonl(pack->node_ip);

    inet_ntop(AF_INET, &pack_addr, fakehostname, INET_ADDRSTRLEN);

    p->hostname = fakehostname;
    p->port = pack->node_port;
    return p;
}

struct addrinfo *peer_lookup(const peer *p) {
    struct addrinfo *res;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char portstr[16];
    snprintf(portstr, 16, "%d", p->port);

    int status = getaddrinfo(p->hostname, portstr, &hints, &res);
    if (status != 0) {
        perror("getaddrinfo:");
        return NULL;
    }

    return res;
}

int peer_connect(peer *p) {
    struct addrinfo *res = peer_lookup(p);

    if (res == NULL) {
        return -1;
    }

    struct addrinfo *pa;
    bool connected = false;
    for (pa = res; pa != NULL; pa = pa->ai_next) {
        p->socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (p->socket < 0) {
            continue;
        }

        int status = connect(p->socket, res->ai_addr, res->ai_addrlen);
        if (status < 0) {
            perror("connect");
            continue;
        }
        memcpy(res->ai_addr, &(p->addr), res->ai_addrlen);
        p->addr_len = res->ai_addrlen;
        connected = true;
    }
    freeaddrinfo(res);

    if (!connected) {
        return -1;
    }

    return 0;
}

uint32_t peer_get_ip(const peer *p) {
    struct addrinfo *res = peer_lookup(p);

    if (res == NULL) {
        fprintf(stderr,
                "Unable to lookup IP of peer %s:%d! This should not happen!\n",
                p->hostname, p->port);
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    freeaddrinfo(res);
    return ip;
}

int peer_is_responsible(uint16_t pred_id, uint16_t peer_id, uint16_t hash_id) {
    if (pred_id > peer_id) { // Zero-crossing
        return hash_id > pred_id || hash_id <= peer_id;
    } else {
        return hash_id > pred_id && hash_id <= peer_id;
    }
}

void peer_disconnect(peer *p) {
    close(p->socket);
    p->socket = -1;
    memset(&(p->addr), 0, p->addr_len);
    p->addr_len = 0;
}
