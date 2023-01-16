#include "hash_table.h"
#include <stdio.h>

void htable_set(htable **ht, const unsigned char *key, size_t key_len,
                const unsigned char *value, size_t value_len) {
    /* TODO IMPLEMENT */
    htable* table;
    HASH_FIND(hh, *ht, key, key_len, table);
    if(table != NULL){
        printf("Found existing: %s & %zu\n", table->value, table->value_len);
        free(table->key);
        free(table->value);
        HASH_DEL(*ht, table);
        free(table);
    }
    table = malloc(sizeof(htable));
    table->key = calloc(key_len,sizeof(char*));
    memcpy(table->key, key, key_len);
    table->key_len = key_len;
    table->value = calloc(value_len ,sizeof(char*));
    memcpy(table->value, value, value_len);
    table->value_len = value_len;
    HASH_ADD_KEYPTR(hh, *ht, table->key, table->key_len, table);
    //Debugging
    htable* result;
    HASH_FIND(hh, *ht, key, key_len, result);
    if( result == NULL){
        printf("Error: Hash-Get!\n");
        exit(0);
    }

}
htable *htable_get(htable **ht, const unsigned char *key, size_t key_len) {
    /* TODO IMPLEMENT */
    htable* table;
    HASH_FIND(hh, *ht, key, key_len, table);
    if(table != NULL){
        printf("Result-: %s & %zu\n %s & %zu\n", table->key, table->key_len, table->value, table->value_len);
    }else{
        printf("Table Not Found!\n");
    }
    return table;
}

int htable_delete(htable **ht, const unsigned char *key, size_t key_len) {
    /* TODO IMPLEMENT */
    htable * result;
    HASH_FIND(hh, *ht, key, key_len, result);
    if(result == NULL){
        return 0;
    }
    free(result->key);
    free(result->value);
    HASH_DEL(*ht, result);
    free(result);
    HASH_FIND(hh, *ht, key, key_len, result);
    return result == NULL;
}
