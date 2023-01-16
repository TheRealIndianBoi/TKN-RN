#pragma once

#include "packet.h"
#include <netdb.h>

typedef struct _peer {
    uint16_t node_id;
    char *hostname;
    uint16_t port;
    int socket;
    struct sockaddr_storage addr;
    size_t addr_len;
} peer;

peer *peer_init(uint16_t id, const char *hostname, const char *port);

void peer_free(peer *p);

int peer_connect(peer *p);

void peer_disconnect(peer *p);

/**
 * @brief Determine whether a given peer is resposible for a given hashed key.
 *
 * @param pred_id The id of the predecessor
 * @param peer_id The id of the peer to check
 * @param hash_id The hashed key to check
 * @return int 1 if the peer is responsible, 0 otherwise
 */
int peer_is_responsible(uint16_t pred_id, uint16_t peer_id, uint16_t hash_id);

peer *peer_from_packet(const packet *pack);

uint32_t peer_get_ip(const peer *p);
