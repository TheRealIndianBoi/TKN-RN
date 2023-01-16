#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hash_table.h"
#include "neighbour.h"
#include "packet.h"
#include "requests.h"
#include "server.h"
#include "util.h"

// actual underlying hash table
htable **ht = NULL;
rtable **rt = NULL;

// chord peers
peer *self = NULL;
peer *pred = NULL;
peer *succ = NULL;

/**
 * @brief Forward a packet to a peer.
 *
 * @param peer The peer to forward the request to
 * @param pack The packet to forward
 * @return int The status of the sending procedure
 */
int forward(peer *p, packet *pack) {
    /* TODO IMPLEMENT COMPLETE */ //Must be Correct - :]
    if(peer_connect(p) == -1){
        exit(EXIT_FAILURE);
    }
    size_t buf_len;
    unsigned char* seri = packet_serialize(pack, &buf_len);
    int result = sendall(p->socket, seri, buf_len);
    peer_disconnect(p);
    free(seri); //Check Valgrind
    if(result == -1){
        exit(EXIT_FAILURE);
    }
    return CB_REMOVE_CLIENT;

}

/**
 * @brief Forward a request to the successor.
 *
 * @param srv The server
 * @param csocket The socket of the client
 * @param p The packet to forward
 * @param n The peer to forward to
 * @return int The callback status
 */
int proxy_request(server *srv, int csocket, packet *p, peer *n) {
    /* TODO IMPLEMENT COMPLETE */
    if(peer_connect(n) == -1){
        exit(EXIT_FAILURE);
    }
    unsigned char * packet_key = calloc(p->key_len, sizeof(p->key));
    strncpy((char * ) packet_key, (char *)p->key, p->key_len);
    size_t buf_len;
    unsigned char* seri = packet_serialize(p, &buf_len);
    int result = sendall(n->socket, seri, buf_len);
    free(seri); //Check Valgrind
    if(result == -1){
        peer_disconnect(n);
        exit(EXIT_FAILURE);
    }

    size_t data_len;
    unsigned char * reply = recvall(n->socket, &data_len);
    peer_disconnect(n);
    printf("Got: \n");
    packet_decode(reply, data_len);
    if(srv->active == false){
        server_run(srv);
    }
    result = sendall(csocket, reply, data_len);
    server_close_socket(srv, csocket);
    free(reply);
    if(result == -1){
        exit(EXIT_FAILURE);
    }

    return CB_REMOVE_CLIENT;
}

/**
 * @brief Lookup the peer responsible for a hash_id.
 *
 * @param hash_id The hash to lookup
 * @return int The callback status
 */
int lookup_peer(uint16_t hash_id) {
    packet * cp = packet_new();
    cp->flags |= PKT_FLAG_LKUP | PKT_FLAG_CTRL;
    cp->hash_id = hash_id;
    cp->node_id = self->node_id;
    cp->node_ip = peer_get_ip(self);
    cp->node_port = self->port;
    //Only for Look-Up, so no data (key/value)
    if(peer_connect(succ) == -1){

        exit(EXIT_FAILURE);
    }
    int result = forward(succ, cp);
    packet_free(cp);
    return result;


}


void handle_GET_request(client *c, packet *p){
    printf("HANDLE GET-Request!\n");
    htable * zelle = htable_get(ht, p->key, p->key_len);
    packet *reply = packet_new();
    reply->key = p->key;
    reply->key_len = p->key_len;
    reply->value_len = 0;
    if(zelle != NULL){
        reply->value = zelle->value;
        reply->value_len = zelle->value_len;
        reply->flags |= PKT_FLAG_ACK | PKT_FLAG_GET;
    }else{
        reply->flags |= PKT_FLAG_GET;
    }
    size_t buf_len;
    unsigned char * seri = packet_serialize(reply, &buf_len);
    packet_decode(seri, buf_len);
    sendall(c->socket, seri, buf_len);
    free(reply);
    free(seri);
}

void handle_SET_request(client* c, packet * p){
    printf("HANDLE SET-Request!\n");
    htable_set(ht, p->key, p->key_len, p->value, p->value_len);
    packet *reply = packet_new();
    reply->flags |= PKT_FLAG_ACK | PKT_FLAG_SET;
    size_t buf_len;
    unsigned char * seri = packet_serialize(reply, &buf_len);
    packet_decode(seri, buf_len);
    sendall(c->socket, seri, buf_len);
    free(reply);
    free(seri);
}
void handle_DEL_request(client* c, packet *p){
    printf("HANDLE DEL-Request!\n");
    int result = htable_delete(ht, p->key, p->key_len);
    packet *reply = packet_new();
    if(result == 0){
        printf("Error: Delete not possible!");
        reply->flags |= PKT_FLAG_DEL;
    }
    else{
        reply->flags |= PKT_FLAG_ACK | PKT_FLAG_DEL;
    }
    size_t buf_len;
    unsigned char * seri = packet_serialize(reply, &buf_len);
    packet_decode(seri, buf_len);
    sendall(c->socket, seri, buf_len);
    free(reply);
    free(seri);

}
/**
 * @brief Handle a client request we are responsible for.
 *
 * @param srv The server
 * @param c The client
 * @param p The packet
 * @return int The callback status
 */
int handle_own_request(server *srv, client *c, packet *p) {
    if(((p->flags >> PKT_FLAG_GET_POS) & 1) + ((p->flags >> PKT_FLAG_SET_POS) & 1) + ((p->flags >> PKT_FLAG_DEL_POS) & 1) != 1){
        //do on Unknown
        printf("Error: Got Unknown Request!\n");
        p->flags = 0;
        p->flags |= PKT_FLAG_ACK;
        size_t buf_len;
        unsigned char * seri = packet_serialize(p, &buf_len);
        sendall(c->socket, seri, buf_len);
        free(seri);
        return CB_REMOVE_CLIENT;
    }
    //Cases
    if((p->flags >> PKT_FLAG_GET_POS) & 1){
        //do GET
        handle_GET_request(c, p);
    }else if((p->flags >> PKT_FLAG_SET_POS) & 1){
        //do SET
        handle_SET_request(c, p);
    }else if((p->flags >> PKT_FLAG_DEL_POS) & 1){
        //do DEL
        handle_DEL_request(c, p);
    }
    return CB_REMOVE_CLIENT;
}

/**
 * @brief Answer a lookup request from a peer.
 *
 * @param p The packet
 * @param n The peer
 * @return int The callback status
 */
int answer_lookup(packet *p, peer *n) {
    /* TODO IMPLEMENT COMPLETE */
    packet * reply = packet_new();
    reply->hash_id = p->hash_id;
    reply->node_id = n->node_id;
    reply->node_port = n->port;
    reply->node_ip = peer_get_ip(n);
    reply->flags |= PKT_FLAG_RPLY | PKT_FLAG_CTRL;
    peer* client = peer_from_packet(p);
    forward(client, reply);
    packet_free(reply);
    return CB_REMOVE_CLIENT;
}

/**
 * @brief Handle a key request request from a client.
 *
 * @param srv The server
 * @param c The client
 * @param p The packet
 * @return int The callback status
 */
int handle_packet_data(server *srv, client *c, packet *p) {
    // Hash the key of the <key, value> pair to use for the hash table
    uint16_t hash_id = pseudo_hash(p->key, p->key_len);
    fprintf(stderr, "Hash id: %d\n", hash_id);

    unsigned char * packet_key = calloc(p->key_len, sizeof(char*));
    strncpy((char * ) packet_key, (char *)p->key, p->key_len);
    unsigned char *packet_value = calloc(p->value_len, sizeof(char*));
    strncpy((char*)packet_value, (char*)p->value, p->value_len);
    printf("PacketInfo:\nHash_ID: %d\nNode:\nID: %d, IP: %d, Port: %d\nKey: %s with length: %d\nValue: %s with length: %d\n"
            ,p->hash_id, p->node_id, p->node_ip, p->node_port, packet_key, p->key_len, packet_value, p->value_len);
    free(packet_key);
    free(packet_value);
    // Forward the packet to the correct peer
    if (peer_is_responsible(pred->node_id, self->node_id, hash_id)) {
        // We are responsible for this key
        fprintf(stderr, "We are responsible.\n");
        return handle_own_request(srv, c, p);
    } else if (peer_is_responsible(self->node_id, succ->node_id, hash_id)) {
        // Our successor is responsible for this key
        fprintf(stderr, "Successor's business.\n");
        return proxy_request(srv, c->socket, p, succ);
    } else {
        // We need to find the peer responsible for this key
        fprintf(stderr, "No idea! Just looking it up!.\n");
        add_request(rt, hash_id, c->socket, p);
        lookup_peer(hash_id);
        return CB_OK;
    }
}

/**
 * @brief Handle a control packet from another peer.
 * Lookup vs. Proxy Reply
 *
 * @param srv The server
 * @param c The client
 * @param p The packet
 * @return int The callback status
 */
int handle_packet_ctrl(server *srv, client *c, packet *p) {

    fprintf(stderr, "Handling control packet...\n");

    if (p->flags & PKT_FLAG_LKUP) {
        // we received a lookup request
        if (peer_is_responsible(pred->node_id, self->node_id, p->hash_id)) {
            // Our business
            fprintf(stderr, "Lol! This should not happen!\n");
            return answer_lookup(p, self);
        } else if (peer_is_responsible(self->node_id, succ->node_id,
                                       p->hash_id)) {
            return answer_lookup(p, succ);
        } else {
            // Great! Somebody else's job!
            forward(succ, p);
        }
    } else if (p->flags & PKT_FLAG_RPLY) {
        // Look for open requests and proxy them
        peer *n = peer_from_packet(p);
        for (request *r = get_requests(rt, p->hash_id); r != NULL;
             r = r->next) {
            proxy_request(srv, r->socket, r->packet, n);
            server_close_socket(srv, r->socket);
        }
        clear_requests(rt, p->hash_id);
    } else {
    }
    return CB_REMOVE_CLIENT;
}

/**
 * @brief Handle a received packet.
 * This can be a key request received from a client or a control packet from
 * another peer.
 *
 * @param srv The server instance
 * @param c The client instance
 * @param p The packet instance
 * @return int The callback status
 */
int handle_packet(server *srv, client *c, packet *p) {
    if (p->flags & PKT_FLAG_CTRL) {
        return handle_packet_ctrl(srv, c, p);
    } else {
        return handle_packet_data(srv, c, p);
    }
}

/**
 * @brief Main entry for a peer of the chord ring.
 *
 * Requires 9 arguments:
 * 1. Id
 * 2. Hostname
 * 3. Port
 * 4. Id of the predecessor
 * 5. Hostname of the predecessor
 * 6. Port of the predecessor
 * 7. Id of the successor
 * 8. Hostname of the successor
 * 9. Port of the successor
 *
 * @param argc The number of arguments
 * @param argv The arguments
 * @return int The exit code
 */
int main(int argc, char **argv) {

    if (argc < 10) {
        fprintf(stderr, "Not enough args! I need ID IP PORT ID_P IP_P PORT_P "
                        "ID_S IP_S PORT_S\n");
    }

    // Read arguments for self
    uint16_t idSelf = strtoul(argv[1], NULL, 10);
    char *hostSelf = argv[2];
    char *portSelf = argv[3];

    // Read arguments for predecessor
    uint16_t idPred = strtoul(argv[4], NULL, 10);
    char *hostPred = argv[5];
    char *portPred = argv[6];

    // Read arguments for successor
    uint16_t idSucc = strtoul(argv[7], NULL, 10);
    char *hostSucc = argv[8];
    char *portSucc = argv[9];

    // Initialize all chord peers
    self = peer_init(
        idSelf, hostSelf,
        portSelf); //  Not really necessary but convenient to store us as a peer
    pred = peer_init(idPred, hostPred, portPred); //

    succ = peer_init(idSucc, hostSucc, portSucc);

    // Initialize outer server for communication with clients
    server *srv = server_setup(portSelf);
    if (srv == NULL) {
        fprintf(stderr, "Server setup failed!\n");
        return -1;
    }
    // Initialize hash table
    ht = (htable **)malloc(sizeof(htable *));
    // Initiale request table
    rt = (rtable **)malloc(sizeof(rtable *));
    *ht = NULL;
    *rt = NULL;

    srv->packet_cb = handle_packet;
    server_run(srv);
    close(srv->socket);
}
