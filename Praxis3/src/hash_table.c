#include "hash_table.h"

void htable_set(htable **ht, const unsigned char *key, size_t key_len,
                const unsigned char *value, size_t value_len) {
    htable *existing;
    // from uthash.h
    HASH_FIND(hh, *ht, key, key_len, existing);
    if (existing != NULL) {
        free(existing->value);
        existing->value = (unsigned char *)malloc(value_len);
        memcpy(existing->value, value, value_len);
        existing->value_len = value_len;
    } else {
        htable *entry = malloc(sizeof(htable));
        memset(entry, 0, sizeof(htable));

        entry->key = (unsigned char *)malloc(key_len);
        entry->value = (unsigned char *)malloc(value_len);
        entry->key_len = key_len;
        entry->value_len = value_len;

        memcpy(entry->key, key, key_len);
        memcpy(entry->value, value, value_len);

        // from uthash.h
        HASH_ADD_KEYPTR(hh, *ht, entry->key, entry->key_len, entry);
    }
}

htable *htable_get(htable **ht, const unsigned char *key, size_t key_len) {
    htable *existing;
    // from uthash.h
    HASH_FIND(hh, *ht, key, key_len, existing);
    return existing;
}

int htable_delete(htable **ht, const unsigned char *key, size_t key_len) {
    htable *existing;
    // from uthash.h
    HASH_FIND(hh, *ht, key, key_len, existing);
    if (existing != NULL) {
        free(existing->key);
        free(existing->value);
        // from uthash.h
        HASH_DEL(*ht, existing);
        return 0;
    } else {
        return -1;
    }
}
