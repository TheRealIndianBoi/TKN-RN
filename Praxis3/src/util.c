#include "util.h"

#include <stdio.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>

uint16_t pseudo_hash(const unsigned char *buffer, size_t buf_len) {
    uint16_t hash = 0;
    if (buf_len >= 2) {
        hash = buffer[0] << 8 | buffer[1] << 0;
    } else if (buf_len == 1) {
        hash = (uint16_t)buffer[0];
    }

    return hash;
}

int sendall(int s, unsigned char *buffer, size_t buf_size) {
    size_t sent = 0;
    while (sent < buf_size) {
        int n = send(s, buffer + sent, buf_size - sent, 0);
        if (n < 1) {
            perror("sendall");
            return -1;
        }
        sent += n;
    }
    return 0;
}

unsigned char *recvall(int s, size_t *data_len) {
    size_t buf_size = 1024;
    unsigned char *buffer = (unsigned char *)malloc(buf_size);
    unsigned char *write_ptr = buffer;
    while (1) {

        // Double buffer if we run out of space
        // Conserve write position (may change after realloc)
        if ((buffer + buf_size - write_ptr) < 1) {
            size_t pos = write_ptr - buffer;

            buf_size = buf_size * 2;
            buffer = realloc(buffer, buf_size);

            write_ptr = buffer + pos;
        }

        size_t bytes = recv(s, write_ptr, buffer + buf_size - write_ptr, 0);

        if (bytes < 1) {
            break;
        }

        write_ptr += bytes;
    }

    close(s);

    *data_len = write_ptr - buffer;
    return buffer;
}

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen) {
    switch (sa->sa_family) {
    case AF_INET:
        inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s, maxlen);
        break;

    case AF_INET6:
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), s,
                  maxlen);
        break;

    default:
        strncpy(s, "Unknown AF", maxlen);
        return NULL;
    }
    return s;
}

ring_buffer *rb_new(size_t size) {
    ring_buffer *rb = (ring_buffer *)malloc(sizeof(ring_buffer));
    rb->buffer = (unsigned char *)malloc(size + 1);
    rb->bufsize = size + 1;

    rb->wpos = 0;
    rb->rpos = 0;
    return rb;
}

size_t rb_can_read(ring_buffer *rb) {
    if (rb->rpos <= rb->wpos) {
        return rb->wpos - rb->rpos;
    } else {
        // Tail + Beginning
        return (rb->bufsize - rb->rpos) + (rb->wpos);
    }
}

size_t rb_can_write(ring_buffer *rb) {
    if (rb->wpos < rb->rpos) {
        return rb->rpos - rb->wpos - 1;
    } else {
        return (rb->bufsize - rb->wpos) + (rb->rpos - 1);
    }
}

size_t rb_write(ring_buffer *rb, const unsigned char *buffer, size_t n) {
    size_t avail = rb_can_write(rb);
    size_t i;
    for (i = 0; i < avail && i < n; i++) {
        rb->buffer[rb->wpos] = buffer[i];
        rb->wpos = (rb->wpos + 1) % rb->bufsize;
    }
    return avail;
}

size_t rb_read(ring_buffer *rb, unsigned char *buffer, size_t bufsize) {
    size_t avail = rb_can_read(rb);
    size_t i;
    for (i = 0; i < avail && i < bufsize; i++) {
        buffer[i] = rb->buffer[rb->rpos];
        rb->rpos = (rb->rpos + 1) % rb->bufsize;
    }
    return avail;
}

void rb_free(ring_buffer *rb) {
    if (rb != NULL) {
        free(rb->buffer);
        free(rb);
    }
}
