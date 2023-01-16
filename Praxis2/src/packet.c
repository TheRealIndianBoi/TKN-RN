#include "packet.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

packet *packet_new() {
    packet *p = (packet *)malloc(sizeof(packet));
    p->flags = 0;
    p->key = NULL;
    p->value = NULL;
    p->key_len = 0;
    p->value_len = 0;
    p->hash_id = 0;
    p->node_id = 0;
    p->node_ip = 0;
    p->node_port = 0;
    return p;
}

packet *packet_dup(const packet *p) {
    packet *newp = packet_new();
    newp->flags = p->flags;
    newp->key_len = p->key_len;
    newp->value_len = p->value_len;
    newp->hash_id = p->hash_id;
    newp->node_id = p->node_id;
    newp->node_port = p->node_port;
    newp->node_ip = p->node_ip;

    newp->key = (unsigned char *)malloc(p->key_len);
    newp->value = (unsigned char *)malloc(p->value_len);
    memcpy(newp->key, p->key, p->key_len);
    memcpy(newp->value, p->value, p->value_len);

    return newp;
}

size_t packet_body_size(packet *p) {
    if (!(p->flags & PKT_FLAG_CTRL)) {
        return p->key_len + p->value_len;
    }
    return 4; // Control packets are always 11 bytes long
}

unsigned char *packet_serialize_data(const packet *p, size_t *buf_len) {
    size_t header_len = 7;
    size_t packet_size = header_len + p->key_len + p->value_len;
    unsigned char *buffer = (unsigned char *)malloc(packet_size);

    buffer[0] = p->flags;

    buffer[1] = (uint8_t)(p->key_len >> 8u) & 0xFFu;
    buffer[2] = (uint8_t)(p->key_len >> 0u) & 0xFFu;

    buffer[3] = (uint8_t)(p->value_len >> 24u) & 0xFFu;
    buffer[4] = (uint8_t)(p->value_len >> 16u) & 0xFFu;
    buffer[5] = (uint8_t)(p->value_len >> 8u) & 0xFFu;
    buffer[6] = (uint8_t)(p->value_len >> 0u) & 0xFFu;

    if (p->key != NULL && p->key_len != 0) {
        memcpy(buffer + 7, p->key, p->key_len);
    }

    if (p->value != NULL && p->value_len != 0) {
        memcpy(buffer + 7 + p->key_len, p->value, p->value_len);
    }

    *buf_len = packet_size;
    return buffer;
}

unsigned char *packet_serialize_ctrl(const packet *p, size_t *buf_len) {
    size_t packet_size = 11;
    unsigned char *buffer = (unsigned char *)malloc(packet_size);

    buffer[0] = p->flags;

    buffer[1] = (uint8_t)(p->hash_id >> 8u) & 0xFFu;
    buffer[2] = (uint8_t)(p->hash_id >> 0u) & 0xFFu;

    buffer[3] = (uint8_t)(p->node_id >> 8u) & 0xFFu;
    buffer[4] = (uint8_t)(p->node_id >> 0u) & 0xFFu;

    buffer[5] = (uint8_t)(p->node_ip >> 24u) & 0xFFu;
    buffer[6] = (uint8_t)(p->node_ip >> 16u) & 0xFFu;
    buffer[7] = (uint8_t)(p->node_ip >> 8u) & 0xFFu;
    buffer[8] = (uint8_t)(p->node_ip >> 0u) & 0xFFu;

    buffer[9] = (uint8_t)(p->node_port >> 8u) & 0xFFu;
    buffer[10] = (uint8_t)(p->node_port >> 0u) & 0xFFu;

    *buf_len = packet_size;
    return buffer;
}

unsigned char *packet_serialize(const packet *p, size_t *buf_len) {
    if (p->flags & PKT_FLAG_CTRL) {
        return packet_serialize_ctrl(p, buf_len);
    }
    return packet_serialize_data(p, buf_len);
}

packet *packet_decode(const unsigned char *buffer, size_t buf_len) {

    packet *p = packet_decode_hdr(buffer, buf_len);
    if (p == NULL) {
        return NULL;
    }

    p = packet_decode_body(p, buffer + PKT_HEADER_LEN, buf_len);

    return p;
}

packet *packet_decode_hdr(const unsigned char *buffer, size_t buf_len) {
    if (buf_len < PKT_HEADER_LEN) {
        fprintf(stderr, "Buffer to short (%zu bytes) to decode packet!\n",
                buf_len);
        return NULL;
    }

    packet *p = packet_new();
    p->flags = buffer[0];

    if (!(p->flags & PKT_FLAG_CTRL)) {
        p->key_len = (buffer[1] << 8u) | (buffer[2] << 0u);

        p->value_len = (buffer[3] << 24u) | (buffer[4] << 16u) |
                       (buffer[5] << 8u) | (buffer[6] << 0u);

        fprintf(stderr, "Decoded packet header: \n");
        fprintf(stderr, "\tACK: %d\n", (p->flags >> PKT_FLAG_ACK_POS) & 1);
        fprintf(stderr, "\tGET: %d\n", (p->flags >> PKT_FLAG_GET_POS) & 1);
        fprintf(stderr, "\tSET: %d\n", (p->flags >> PKT_FLAG_SET_POS) & 1);
        fprintf(stderr, "\tDEL: %d\n", (p->flags >> PKT_FLAG_DEL_POS) & 1);
        fprintf(stderr, "\tKey Length: %d Bytes\n", p->key_len);
        fprintf(stderr, "\tValue Length: %d Bytes\n", p->value_len);
    } else {
        fprintf(stderr, "Decoded control packet header: \n");
        fprintf(stderr, "\tJOIN: %d\n", (p->flags >> PKT_FLAG_JOIN_POS) & 1);
        fprintf(stderr, "\tNOTIFY: %d\n", (p->flags >> PKT_FLAG_NTFY_POS) & 1);
        fprintf(stderr, "\tSTABILIZE: %d\n",
                (p->flags >> PKT_FLAG_STAB_POS) & 1);
        fprintf(stderr, "\tLOOKUP: %d\n", (p->flags >> PKT_FLAG_LKUP_POS) & 1);
        fprintf(stderr, "\tREPLY: %d\n", (p->flags >> PKT_FLAG_RPLY_POS) & 1);

        p->hash_id = (buffer[1] << 8u) | (buffer[2] << 0u);
        p->node_id = (buffer[3] << 8u) | (buffer[4] << 0u);
        p->node_ip =
            (buffer[5] << 24u) |
            (buffer[6]
             << 16u); // Upper part of IP only -> the rest is in the 'body'
    }

    return p;
}

packet *packet_decode_body(packet *p, const unsigned char *buffer,
                           size_t buf_len) {
    if (p->flags & PKT_FLAG_CTRL) {
        p->node_ip |=
            (buffer[0] << 8u) |
            (buffer[1]
             << 0u); // Lower part of IP only -> the rest is in the 'header'
        p->node_port = (buffer[2] << 8u) | (buffer[3] << 0u);
        return p;
    }

    size_t pkt_size = p->key_len + p->value_len;

    if (buf_len < pkt_size) {
        fprintf(stderr,
                "Buffer shorter than expected from header! (Expected: %zu Got: "
                "%zu)\n",
                pkt_size, buf_len);
        packet_free(p);
        return NULL;
    }

    if (p->key_len > 0) {
        p->key = (unsigned char *)malloc(p->key_len);
        memcpy(p->key, buffer, p->key_len);
    }

    // NOTE: We should check for ENOMEM because values can be up to 2^32 Bytes
    // long...
    if (p->value_len > 0) {
        p->value = (unsigned char *)malloc(p->value_len);
        memcpy(p->value, buffer + p->key_len, p->value_len);
    }
    return p;
}

void packet_free(packet *p) {
    if (p != NULL) {
        free(p->key);
        free(p->value);
        free(p);
    }
}
