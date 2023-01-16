#pragma once

#include "uthash.h"

/*
 * This is the structure that will be used to store (the data in) the hash
 * table. It is a simple structure that contains a key, a value, and their
 * respective lengths.
 */
typedef struct htable {
    unsigned char *key;
    size_t key_len;
    unsigned char *value;
    size_t value_len;
    UT_hash_handle hh; // impementation specific
} htable;

/**
 * @brief Implementation of the SET operation on our hash table.
 * Uses HASH_FIND and HASH_ADD_KEYPTR from uthash.h
 *
 * @param ht The hash table to perform the operation on
 * @param key The key to use
 * @param key_len The length of the key
 * @param value The value to store
 * @param value_len The length of the value
 */
void htable_set(htable **ht, const unsigned char *key, size_t key_len,
                const unsigned char *value, size_t value_len);

/**
 * @brief Implementation of the GET operation on our hash table.
 * Uses HASH_FIND from uthash.h
 *
 * @param ht The hash table to perform the operation on
 * @param key The key to use
 * @param key_len The length of the key
 *
 * @return htable The struct associated with the key
 */
htable *htable_get(htable **ht, const unsigned char *key, size_t key_len);

/**
 * @brief Implementation of the DELETE operation on our hash table.
 * Uses HASH_FIND from uthash.h
 *
 * @param ht The hash table to perform the operation on
 * @param key The key to use
 * @param key_len The length of the key
 */
int htable_delete(htable **ht, const unsigned char *key, size_t key_len);
