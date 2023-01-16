#include "requests.h"

void add_request(rtable **table, uint16_t hash_id, int socket,
                 const packet *packet) {
    request *r = (request *)malloc(sizeof(request));
    r->packet = packet_dup(packet);
    r->socket = socket;

    rtable *existing;
    HASH_FIND(hh, *table, &hash_id, sizeof(uint16_t), existing);
    if (existing != NULL) {
        request *re;
        for (re = existing->open_requests; re->next != NULL; re = re->next) {
            // Just loop-di-loop;
        }
        re->next = r;
        r->next = NULL;
    } else {
        rtable *entry = (rtable *)malloc(sizeof(rtable));
        entry->hash_id = hash_id;
        entry->open_requests = r;
        r->next = NULL;
        HASH_ADD(hh, *table, hash_id, sizeof(uint16_t), entry);
    }
}

request *get_requests(rtable **table, uint16_t hash_id) {
    rtable *existing;
    HASH_FIND(hh, *table, &hash_id, sizeof(uint16_t), existing);
    if (existing != NULL) {
        return existing->open_requests;
    }
    return NULL;
}

void clear_requests(rtable **table, uint16_t hash_id) {
    rtable *existing;
    HASH_FIND(hh, *table, &hash_id, sizeof(uint16_t), existing);

    if (existing != NULL) {
        request *re = existing->open_requests;

        while (re != NULL) {
            request *next = re->next;
            free(re->packet);
            free(re);
            re = next;
        }
        HASH_DEL(*table, existing);
    }
}
