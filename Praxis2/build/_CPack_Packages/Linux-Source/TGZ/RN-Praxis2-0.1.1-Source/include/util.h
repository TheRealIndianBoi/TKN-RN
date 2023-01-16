#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

typedef struct _ring_buffer {
    unsigned char *buffer;
    size_t bufsize;
    size_t wpos;
    size_t rpos;
} ring_buffer;

ring_buffer *rb_new(size_t size);

size_t rb_can_read(ring_buffer *rb);

size_t rb_can_write(ring_buffer *rb);

size_t rb_write(ring_buffer *rb, const unsigned char *buffer, size_t n);

size_t rb_read(ring_buffer *rb, unsigned char *buffer, size_t bufsize);

void rb_free(ring_buffer *rb);

int sendall(int s, unsigned char *buffer, size_t buf_size);

unsigned char *recvall(int s, size_t *data_len);

/**
 * @brief Calculate a pseudo-hash from key.
 *
 * @param buffer The key to hash
 * @param buf_len The length of .the buffer
 * @return The hashed key
 */
uint16_t pseudo_hash(const unsigned char *buffer, size_t buf_len);

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
