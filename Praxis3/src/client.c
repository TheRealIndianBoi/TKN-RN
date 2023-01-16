#include "packet.h"
#include "util.h"

#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief Read data from stdin.
 *
 * @param len Length of data to read
 */
unsigned char *read_stdin(size_t *len) {
    size_t buf_size = 1024;
    unsigned char *buffer = (unsigned char *)malloc(buf_size);
    unsigned char *write_ptr = buffer;
    while (true) {

        // Double buffer if we run out of space
        // Conserve write position (may change after realloc)
        if ((buffer + buf_size - write_ptr) < 1) {
            size_t pos = write_ptr - buffer;

            buf_size = buf_size * 2;
            buffer = realloc(buffer, buf_size);

            write_ptr = buffer + pos;
        }

        size_t bytes =
            fread(write_ptr, 1, buffer + buf_size - write_ptr, stdin);

        if (bytes < 1) {
            break;
        }

        write_ptr += bytes;
    }

    *len = write_ptr - buffer;
    return buffer;
}

/**
 * @brief Connect to a peer of the chord ring.
 *
 * @param host Hostname of peer
 * @param port Port of peer
 */
int connect_socket(char *hostname, char *port) {
    struct addrinfo *res;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname, port, &hints, &res);
    if (status != 0) {
        perror("getaddrinfo:");
        return -1;
    }

    struct addrinfo *p;
    int sock = -1;
    bool connected = false;

    char ipstr[INET6_ADDRSTRLEN];

    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) {
            continue;
        }

        get_ip_str(p->ai_addr, ipstr, INET6_ADDRSTRLEN);
        fprintf(stderr, "Attempting connection to %s\n", ipstr);

        status = connect(sock, p->ai_addr, p->ai_addrlen);
        if (status < 0) {
            perror("connect");
            close(sock);
            continue;
        }
        connected = true;
        break;
    }
    freeaddrinfo(res);

    if (!connected) {
        return -1;
    }

    fprintf(stderr, "Connected to %s.\n", ipstr);

    return sock;
}

/**
 * @brief Main entry for a client to the distributed hash table.
 *
 * Requires 4 arguments:
 * 1. Hostname of the chord peer
 * 2. Port of the chord peer
 * 3. Command to execute
 * 4. Key to update
 *
 * @param argc The number of arguments.
 * @param argv The arguments.
 */
int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Not enough args!\n");
        return -1;
    }

    // Read arguments
    char *hostname = argv[1];
    char *port = argv[2];
    char *method = argv[3];
    char *key = argv[4];

    int s = connect_socket(hostname, port);
    if (s < 0) {
        fprintf(stderr, "Could not connect to host!\n");
        return -1;
    }

    packet *p = packet_new();

    // check for command type
    if (strcmp(method, "SET") == 0) {
        // SET command
        size_t data_len = 0;
        unsigned char *data = read_stdin(&data_len);

        fprintf(stderr, "%zu bytes read from stdin.\n", data_len);
        p->key = (unsigned char *)strdup(key);
        p->key_len = strlen(key);
        p->flags = PKT_FLAG_SET;
        p->value = data;
        p->value_len = data_len;

        size_t raw_size;
        unsigned char *raw_pkt = packet_serialize(p, &raw_size);
        packet_free(p); // frees data as well

        sendall(s, raw_pkt, raw_size);
    } else if (strcmp(method, "GET") == 0) {
        // GET command
        p->key = (unsigned char *)strdup(key);
        p->key_len = strlen(key);
        p->flags = PKT_FLAG_GET;

        size_t raw_size;
        unsigned char *raw_pkt = packet_serialize(p, &raw_size);
        packet_free(p);
        sendall(s, raw_pkt, raw_size);

    } else if (strcmp(method, "DELETE") == 0) {
        // DELETE command
        p->key = (unsigned char *)strdup(key);
        p->key_len = strlen(key);
        p->flags = PKT_FLAG_DEL;

        size_t raw_size;
        unsigned char *raw_pkt = packet_serialize(p, &raw_size);
        packet_free(p);
        sendall(s, raw_pkt, raw_size);

    } else {
        fprintf(stderr, "Unknown method %s!\n", method);
        packet_free(p);
        return -1;
    }

    size_t response_len;
    unsigned char *response = recvall(s, &response_len);
    packet *rsp = packet_decode(response, response_len);
    free(response);

    if (rsp == NULL) {
        return -1;
    }

    if (!(rsp->flags & PKT_FLAG_ACK)) {
        fprintf(stderr, "Server did not acknowledge operation!\n");
        return -1;
    }

    if (strcmp(method, "GET") == 0) {
        size_t written = 0;
        while (written < rsp->value_len) {
            size_t n = fwrite(rsp->value + written, 1, rsp->value_len - written,
                              stdout);
            if (n < 1) {
                fprintf(stderr, "Fwrite to stdout failed! Panic!!\n");
                packet_free(rsp);
                return -1;
            }

            written += n;
        }
    }

    return 0;
}
