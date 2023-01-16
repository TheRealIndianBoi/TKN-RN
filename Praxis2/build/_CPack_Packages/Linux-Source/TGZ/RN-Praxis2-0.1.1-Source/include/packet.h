#pragma once

#include <stdint.h>
#include <stdlib.h>

#define PKT_FLAG_CTRL 1 << 7
#define PKT_FLAG_FNGR 1 << 6
#define PKT_FLAG_FACK 1 << 5
#define PKT_FLAG_JOIN 1 << 4
#define PKT_FLAG_NTFY 1 << 3
#define PKT_FLAG_STAB 1 << 2
#define PKT_FLAG_RPLY 1 << 1
#define PKT_FLAG_LKUP 1 << 0

#define PKT_FLAG_CTRL_POS 7
#define PKT_FLAG_FNGR_POS 6
#define PKT_FLAG_FACK_POS 5
#define PKT_FLAG_JOIN_POS 4
#define PKT_FLAG_NTFY_POS 3
#define PKT_FLAG_STAB_POS 2
#define PKT_FLAG_RPLY_POS 1
#define PKT_FLAG_LKUP_POS 0

#define PKT_FLAG_ACK 1 << 3
#define PKT_FLAG_GET 1 << 2
#define PKT_FLAG_SET 1 << 1
#define PKT_FLAG_DEL 1 << 0

#define PKT_FLAG_ACK_POS 3
#define PKT_FLAG_GET_POS 2
#define PKT_FLAG_SET_POS 1
#define PKT_FLAG_DEL_POS 0

#define PKT_HEADER_LEN 7

typedef struct _packet {
    uint8_t flags;
    uint16_t key_len;
    uint32_t value_len;
    unsigned char *key;
    unsigned char *value;

    // Control packets only
    uint16_t hash_id;
    uint16_t node_id;
    uint32_t node_ip;
    uint16_t node_port;
} packet;

packet *packet_new();

packet *packet_dup(const packet *p);

void packet_free(packet *p);

unsigned char *packet_serialize(const packet *p, size_t *buf_len);

packet *packet_decode_hdr(const unsigned char *buffer, size_t buf_len);
packet *packet_decode_body(packet *p, const unsigned char *buffer,
                           size_t buf_len);
packet *packet_decode(const unsigned char *buffer, size_t buf_len);
size_t packet_body_size(packet *p);
