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

typedef struct finger_table{
    uint16_t hash;
    peer * fpeer;
    struct finger_table* next;
}ftable;

client* FNGR_Client;
int potenznr = 0;
ftable* finger;

void send_STAB(void);
/**
 * @brief Forward a packet to a peer.
 *
 * @param peer The peer to forward the request to
 * @param pack The packet to forward
 * @return int The status of the sending procedure
 */
int forward(peer *p, packet *pack) {
    // check whether we can connect to the peer
    if (peer_connect(p) != 0) {
        /*fprintf(stderr, "Failed to connect to peer %s:%d\n", p->hostname,
                p->port);*/
        return -1;
    }

    size_t data_len;
    unsigned char *raw = packet_serialize(pack, &data_len);
    int status = sendall(p->socket, raw, data_len);
    free(raw);
    raw = NULL;

    peer_disconnect(p);
    return status;
}

/**
 * @brief Forward a request to the successor.
 *
 * @param srv The server
 * @param csocket The scokent of the client
 * @param p The packet to forward
 * @param n The peer to forward to
 * @return int The callback status
 */
int proxy_request(server *srv, int csocket, packet *p, peer *n) {
    // check whether we can connect to the peer
    if (peer_connect(n) != 0) {
        fprintf(stderr,
                "Could not connect to peer %s:%d to proxy request for client!",
                n->hostname, n->port);
        return CB_REMOVE_CLIENT;
    }

    size_t data_len;
    unsigned char *raw = packet_serialize(p, &data_len);
    sendall(n->socket, raw, data_len);
    free(raw);
    raw = NULL;

    size_t rsp_len = 0;
    unsigned char *rsp = recvall(n->socket, &rsp_len);

    // Just pipe everything through unfiltered. Yolo!
    sendall(csocket, rsp, rsp_len);
    free(rsp);

    return CB_REMOVE_CLIENT;
}

/**
 * @brief Lookup the peer responsible for a hash_id.
 *
 * @param hash_id The hash to lookup
 * @return int The callback status
 */
int lookup_peer(uint16_t hash_id) {
    // We could see whether we need to repeat the lookup
    if(succ == NULL){
        return -1;
    }

    // build a new packet for the lookup
    packet *lkp = packet_new();
    lkp->flags = PKT_FLAG_CTRL | PKT_FLAG_LKUP;
    lkp->hash_id = hash_id;
    lkp->node_id = self->node_id;
    lkp->node_port = self->port;
    lkp->node_ip = peer_get_ip(self);

    //send package
    if(potenznr != 16){
        //if no finger_table is set
    forward(succ, lkp);
    return 0;}
    else{
        ftable* pointer = finger;
        while(pointer->next != NULL){
            if(peer_is_responsible(pointer->fpeer->node_id, pointer->next->fpeer->node_id,hash_id)){
                forward(pointer->fpeer, lkp);
                return 0;
            }
            pointer = pointer->next;
        }
        //no matched entry in finger_table
        forward(succ, lkp);
    }
    return 0;
}

/**
 * @brief Handle a client request we are responsible for.
 *
 * @param c The client
 * @param p The packet
 * @return int The callback status
 */
int handle_own_request(server* srv, client *c, packet *p) {
    // build a new packet for the request
    packet *rsp = packet_new();

    if (p->flags & PKT_FLAG_GET) {
        // this is a GET request
        htable *entry = htable_get(ht, p->key, p->key_len);
        if (entry != NULL) {
            rsp->flags = PKT_FLAG_GET | PKT_FLAG_ACK;

            rsp->key = (unsigned char *)malloc(entry->key_len);
            rsp->key_len = entry->key_len;
            memcpy(rsp->key, entry->key, entry->key_len);

            rsp->value = (unsigned char *)malloc(entry->value_len);
            rsp->value_len = entry->value_len;
            memcpy(rsp->value, entry->value, entry->value_len);
        } else {
            rsp->flags = PKT_FLAG_GET;
            rsp->key = (unsigned char *)malloc(p->key_len);
            rsp->key_len = p->key_len;
            memcpy(rsp->key, p->key, p->key_len);
        }
    } else if (p->flags & PKT_FLAG_SET) {
        // this is a SET request
        rsp->flags = PKT_FLAG_SET | PKT_FLAG_ACK;
        htable_set(ht, p->key, p->key_len, p->value, p->value_len);
    } else if (p->flags & PKT_FLAG_DEL) {
        // this is a DELETE request
        int status = htable_delete(ht, p->key, p->key_len);

        if (status == 0) {
            rsp->flags = PKT_FLAG_DEL | PKT_FLAG_ACK;
        } else {
            rsp->flags = PKT_FLAG_DEL;
        }
    } else {
        // send some default data
        rsp->flags = p->flags | PKT_FLAG_ACK;
        rsp->key = (unsigned char *)strdup("Rick Astley");
        rsp->key_len = strlen((char *)rsp->key);
        rsp->value = (unsigned char *)strdup("Never Gonna Give You Up!\n");
        rsp->value_len = strlen((char *)rsp->value);
    }

    size_t data_len;
    unsigned char *raw = packet_serialize(rsp, &data_len);
    free(rsp);
    sendall(c->socket, raw, data_len);
    free(raw);
    raw = NULL;

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
    peer *questioner = peer_from_packet(p);

    // check whether we can connect to the peer
    if (peer_connect(questioner) != 0) {
        fprintf(stderr, "Could not connect to questioner of lookup at %s:%d\n!",
                questioner->hostname, questioner->port);
        peer_free(questioner);
        return CB_REMOVE_CLIENT;
    }

    // build a new packet for the response
    packet *rsp = packet_new();
    rsp->flags = PKT_FLAG_CTRL | PKT_FLAG_RPLY;
    rsp->hash_id = p->hash_id;
    rsp->node_id = n->node_id;
    rsp->node_port = n->port;
    rsp->node_ip = peer_get_ip(n);

    size_t data_len;
    unsigned char *raw = packet_serialize(rsp, &data_len);
    free(rsp);
    sendall(questioner->socket, raw, data_len);
    free(raw);
    raw = NULL;
    peer_disconnect(questioner);
    peer_free(questioner);
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

int notify_dht(peer* client, server* srv){

    packet *msg = packet_new();
    msg->node_ip = peer_get_ip(self);
    msg->node_port = self->port;
    msg->node_id = self->node_id;
    msg->flags |= PKT_FLAG_NTFY |PKT_FLAG_CTRL;
    int trials = 0;
    peer* temp = pred;
    pred = client;
    peer* temp2 = succ;
    if(succ == NULL){
        succ = client;
        srv->succ = succ;
    }
    while(forward(client, msg) == -1){
        trials += 1;
        if(trials == 200){
        fprintf(stderr,"Notify couldn't be send to Port: %d with ID: %d!\n",
                                                            client->port, client->node_id);
        pred = temp;
        succ = temp2;
        srv->succ = succ;
        peer_free(client);
        return EXIT_FAILURE;
        }
    }
    packet_free(msg);
    if(succ == pred){
        fprintf(stderr, "New Predecessor & Successor:\n IP: %s, Port: %d, ID: %d\n",
                                                                pred->hostname, pred->port, pred->node_id);
        send_STAB();
    }else{
        fprintf(stderr, "New Predecessor:\n IP: %s, Port: %d, ID: %d\n\nNew Successor:\n IP: %s, Port: %d, ID: %d\n",
                                                    pred->hostname, pred->port, pred->node_id,succ->hostname, succ->port, succ->node_id);
    }
    return EXIT_SUCCESS;
}

int compare_peer(peer* c1, peer* c2){
    return c1->node_id == c2->node_id && c1->port == c2->port && peer_get_ip(c1) == peer_get_ip(c2);
}
void got_packet(packet* p){

    fprintf(stderr, "Handling control packet...\n");
    print_packet_hdr(p);
}
void send_FACK(server* srv){
    packet* response = packet_new();
    response->flags |= PKT_FLAG_CTRL | PKT_FLAG_FACK;
    response->node_id = self->node_id;
    response->node_port = self->port;
    response->node_ip = peer_get_ip(self);
    size_t buf_len;
    unsigned char* resp = packet_serialize(response, &buf_len);
    packet_free(response);
    fprintf(stderr, "Sending FACK: ");
    int timer = 0;
    while(sendall(FNGR_Client->socket, resp, buf_len) != 0){
        timer += 1;
        if(timer == 200){
            fprintf(stderr, "Failed!\n");
            return;
        }
    }
    free(resp);
    fprintf(stderr, "Successfully\n");
    server_close_socket(srv, FNGR_Client->socket);
    FNGR_Client = NULL;

}

void send_STAB(void) {
    packet* stab = packet_new();
    stab->node_id = self->node_id;
    stab->node_ip = peer_get_ip(self);
    stab->node_port = self->port;
    stab->flags |= PKT_FLAG_CTRL | PKT_FLAG_STAB;
    int timer = 0;
    while(forward(succ, stab) == -1){
        timer += 1;
        if(timer == 200){
            fprintf(stderr, "Send Stabilize, not possible!\n");
        }
    }
}

int power(int base, int potenz){
    if(potenz == 0){
        return 1;
    }
    if(potenz == 1){
        return base;
    }
    int value = base;
    for (int i = 0; i < potenz; ++i) {
        value *= base;
    }
    return value;
}
void free_ftable(ftable* pointer){
    ftable* temp = pointer->next;
    fprintf(stderr, "Freeing Finger: %hu\n", pointer->hash);
    if(pointer->fpeer != NULL){
        pointer->fpeer = NULL;
    }
    pointer->hash = 0; //unnecessary but looks good
    free(pointer);
    while(temp != NULL){
        pointer = temp;
        temp = temp->next;
        fprintf(stderr, "Freeing Finger: %hu\n", pointer->hash);
        if(pointer->fpeer != NULL){
            pointer->fpeer = NULL;
        }
        pointer->hash = 0; //unnecessary but looks good
        free(pointer);
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


    if (p->flags & PKT_FLAG_LKUP) {
        got_packet(p);
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
        got_packet(p);
        peer *n = peer_from_packet(p);
        if(get_requests(rt, p->hash_id) != NULL){
            for (request *r = get_requests(rt, p->hash_id); r != NULL; r = r->next) {
                proxy_request(srv, r->socket, r->packet, n);
                server_close_socket(srv, r->socket);
                clear_requests(rt, p->hash_id);
            }
        }else{
            ftable* pointer = finger;
            printf("Index: %d\n", potenznr);
            for (int i = 0; i < potenznr; ++i) {
                pointer = pointer->next;
            }
            n->node_id = p->node_id;
            pointer->fpeer = n;
            pointer->hash = p->hash_id;
            potenznr += 1;
            if(potenznr < 16){
                packet* fill_FNGR = packet_new();
                pointer->next = calloc(1, sizeof(ftable));
                fill_FNGR->node_id = self->node_id;
                fill_FNGR->node_ip = peer_get_ip(self);
                fill_FNGR->node_port = self->port;
                fill_FNGR->hash_id = (uint16_t) (self->node_id + power(2, potenznr)) % power(2, 16);
                fill_FNGR->flags |= PKT_FLAG_LKUP | PKT_FLAG_CTRL;
                int timer = 0;
                while(forward(n, fill_FNGR) == -1){
                    timer += 1;
                    if(timer == 20){
                        fprintf(stderr,"FNGR- LOOKUP couldn't be sent!\n");
                        break;
                    }
                }
            }if(potenznr == 16){
                /** PRINT FINGER-TABLE **/
                potenznr = 0;
                ftable* print = finger;
                while(print != NULL){
                    printf("Index: %d,Pointer: %p, Hash: %d, Peer: %d, Next: %p\n", potenznr, (void*)print, print->hash, print->fpeer->node_id, (void*)print->next);
                    print = print->next;
                    potenznr += 1;
                }
                printf("Potenz: %d\n", potenznr);
                send_FACK(srv);
            }

        }

    } else if(p->flags & PKT_FLAG_NTFY) {
        if(succ == NULL || succ->node_id != p->node_id){
            got_packet(p);
            succ = peer_from_packet(p);
            succ->node_id = p->node_id;
            srv->succ = succ;
            fprintf(stderr,"New Successor:\n IP: %s, Port: %d, ID: %d\n", succ->hostname, succ->port, succ->node_id);
            send_STAB();
        }
    }else if(p->flags & PKT_FLAG_JOIN) {
        got_packet(p);
        peer *n = peer_from_packet(p);
        n->node_id = p->node_id;
        if((pred == NULL)
        ||  (n->node_id < self->node_id && ((pred->node_id < n->node_id) || (pred->node_id > self->node_id)))
        ||  (n->node_id > self->node_id && (self->node_id < pred->node_id && pred->node_id < n->node_id))
        ){
            notify_dht(n, srv);
        }else{
            printf("Node-ID: %d\n", n->node_id);
            forward(succ, p);
        }
    }else if(p->flags & PKT_FLAG_STAB){
        peer *n = peer_from_packet(p);
        n->node_id = p->node_id;
        if(pred == NULL){
            got_packet(p);
            pred = n;
            fprintf(stderr,"New Predecessor:\n IP: %s, Port: %d, ID: %d\n", pred->hostname, pred->port, pred->node_id);
            packet *change = packet_new();
            change->node_port = self->port;
            change->node_id = self->node_id;
            change->node_ip = peer_get_ip(self);
            change->flags |= PKT_FLAG_CTRL | PKT_FLAG_NTFY;
            int timer = 0;
            if(p->hash_id != 1){
                //TODO:
                size_t buffer_len;
                unsigned char* msg = packet_serialize(change, &buffer_len);
                while(sendall(c->socket, msg, buffer_len) == -1){
                    timer += 1;
                    if(timer == 200){
                        fprintf(stderr, "Notify couldn't be send! [Line: 500]\n");
                        free(msg);
                        packet_free(change);
                        return CB_REMOVE_CLIENT;
                    }
                }
            }else{
                while(forward(n, change) == -1){
                    timer += 1;
                    if(timer == 200){
                        fprintf(stderr,"Notify couldn't be send! [Line: 510]\n");
                        packet_free(change);
                        return CB_REMOVE_CLIENT;}
                }
            }
            packet_free(change);
        }else{
            if(!compare_peer(n, pred)){
                got_packet(p);
                fprintf(stderr,"Got STABILIZE: Comparing: Predecessor: Port: %hu, ID: %hu\n From Packet: Port: %hu, ID:%hu\n", pred->port, pred->node_id, n->port, n->node_id);
                //Notify
                packet *change = packet_new();
                change->node_port = pred->port;
                change->node_id = pred->node_id;
                change->node_ip = peer_get_ip(pred);
                change->flags |= PKT_FLAG_CTRL | PKT_FLAG_NTFY;

                int timer = 0;
                if(p->hash_id != 1){
                    size_t buffer_len;
                    unsigned char* msg = packet_serialize(change, &buffer_len);
                    while(sendall(c->socket, msg, buffer_len) == -1){
                        timer += 1;
                        if(timer == 200){
                            fprintf(stderr, "Notify couldn't be send![line: 537]\n");
                            free(msg);
                            packet_free(change);
                            return CB_REMOVE_CLIENT;
                        }
                    }
                }else{
                    while(forward(n, change) == -1){
                        timer += 1;
                        fprintf(stderr, "!");
                        if(timer == 200){
                            fprintf(stderr,"Notify couldn't be send! [line: 548]\n");
                            packet_free(change);
                            return CB_REMOVE_CLIENT;}
                    }
                }
                packet_free(change);
            }else{
                packet *change = packet_new();
                change->node_port = self->port;
                change->node_id = self->node_id;
                change->node_ip = peer_get_ip(self);
                change->flags |= PKT_FLAG_CTRL | PKT_FLAG_NTFY;

                int timer = 0;
                if(p->hash_id != 1){

                    size_t buffer_len;
                    unsigned char* msg = packet_serialize(change, &buffer_len);
                    while(sendall(c->socket, msg, buffer_len) == -1){
                        timer += 1;
                        if(timer == 200){
                            fprintf(stderr, "Notify couldn't be send! [line:569]\n");
                            free(msg);
                            packet_free(change);
                            return CB_REMOVE_CLIENT;
                        }
                    }
                }else{
                    while(forward(n, change) == -1){
                        timer += 1;
                        if(timer == 200){
                            fprintf(stderr,"Notify couldn't be send! [line: 580]\n");
                            packet_free(change);
                            return CB_REMOVE_CLIENT;}
                    }
                }
                packet_free(change);
            }
            peer_free(n);
        }
    }else if(p->flags & PKT_FLAG_FNGR){
        got_packet(p);
        if(FNGR_Client != NULL){
            fprintf(stderr, "Got a FNGR-Package, before previous FNGR has been accomplished!\n");
            return CB_REMOVE_CLIENT;
        }
        FNGR_Client = c;
        if(succ == NULL || pred == NULL){
            fprintf(stderr,"Error at FNGR: No Successor!\n");
            send_FACK(srv);
            return CB_REMOVE_CLIENT;
        }

        if(potenznr == 16){
            potenznr = 0;
            fprintf(stderr, "Renewing Finger-Table!\n");
        }
        free_ftable(finger);
        finger = calloc(1, sizeof(ftable));
        //printf("Pointer: %p, Hash: %hu with Peer: %p, Next: %p\n", (void*)pointer, pointer->hash, (void*)pointer->fpeer, (void*)pointer->next);
        finger->next = calloc(1,sizeof(ftable));

        /**     Potenz = 0      **/
        uint16_t value  = (uint16_t) (self->node_id + power(2, potenznr)) % power(2, 16);
        finger->hash = value;
        finger->fpeer = succ;
        fprintf(stderr, "Change of FNGR at I: %d, HASH: %d, Peer: %d\n", potenznr, value, succ->port);

        /**     Potenz > 0     **/
        potenznr += 1;
        packet* fill_FNGR = packet_new();
        fill_FNGR->node_id = self->node_id;
        fill_FNGR->node_ip = peer_get_ip(self);
        fill_FNGR->node_port = self->port;
        fill_FNGR->hash_id = (uint16_t) (self->node_id + power(2, potenznr)) % power(2, 16);
        fill_FNGR->flags |= PKT_FLAG_LKUP | PKT_FLAG_CTRL;
        int timer = 0;
        while(forward(succ, fill_FNGR) == -1){
            timer += 1;
            if(timer == 20){
                fprintf(stderr,"FNGR- LOOKUP couldn't be sent!\n");
            }
        }
        return CB_OK;


    }else if(p->flags & PKT_FLAG_FACK){
        got_packet(p);
        fprintf(stderr,"Why did i get a FACK-Packet?");
    }
        /**
         *
         * Extend handled control messages.
         * For the first task, this means that join-, stabilize-, and notify-messages should be understood.
         * For the second task, finger- and f-ack-messages need to be used as well.
         **/

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

int count(char * string, char c){
    int nr = 0;
    for (int i = 0; i < (int) strlen(string); ++i) {
        if(string[i] == c){
            nr += 1;
        }
    }
    return nr;
}

int join_dht(peer* node){ //Works
    packet *join_msg = packet_new();
    join_msg->node_ip = peer_get_ip(self);
    join_msg->node_port = self->port;
    join_msg->node_id = self->node_id;
    join_msg->flags |= PKT_FLAG_JOIN |PKT_FLAG_CTRL;
    //peer_connect(node);
    int trials = 0;
    while(forward(node, join_msg) == -1){
        trials += 1;
        if(trials == 500){
            fprintf(stderr,"Notify couldn't be send!\n");
            packet_free(join_msg);
        return EXIT_FAILURE;}
    }
    packet_free(join_msg);
    return EXIT_SUCCESS;

}

/**
 * @brief Main entry for a peer of the chord ring.
 *
 *
 * Modify usage of peer. Accept:
 * 1. Own IP and port; [Check]
 * 2. Own ID (optional, zero if not passed); [Check]
 * 3. IP and port of Node in existing DHT. This is optional: If not passed, establish new DHT, otherwise join existing.[Check]
 *
 * @param argc The number of arguments
 * @param argv The arguments
 * @return int The exit code
 */
int main(int argc, char **argv) {


    if(argc < 3 || argc > 6) {
        fprintf(stderr,
                "Amount of Arguments invalid! It should be ./peer IP PORT [ID] [Peer-IP Peer-PORT]. [ID] is not necessary.\n");
        return EXIT_FAILURE;
    }

    uint16_t idSelf = 0;
    char *hostSelf = argv[1];
    char *portSelf = argv[2];
    if(argc == 4 || argc == 6){

        char* id = calloc(strlen(argv[3]), sizeof(char));
        strncpy(id, argv[3], strlen(argv[3]));
        idSelf = strtoul(id, NULL, 10);
        char str[strlen(argv[3])];
        sprintf(str, "%d", idSelf);
        if(strlen(str) != strlen(argv[3])){
            fprintf(stderr,
                    "Invalid Arguments! It should be ./peer IP PORT [ID] [Peer-IP Peer-PORT]. [ID] is not necessary.\n");
            return EXIT_FAILURE;
        }
        free(id);
    }
    fprintf(stdout,"Self:\nHOST: %s, PORT: %s, ID: %d\n", hostSelf, portSelf, idSelf);


    // Initialize all chord peers
    self = peer_init(idSelf, hostSelf,portSelf); //  Not really necessary but convenient to store us as a peer
    pred = NULL;
    succ = NULL;

    //Set Peer to a DHT if given
    if(argc == 5 || argc == 6){
        char * peer_ip = calloc(strlen(argv[argc - 2]), sizeof(char));
        strncpy(peer_ip, argv[argc - 2], strlen(argv[argc - 2]));
        char * peer_port = calloc(strlen(argv[argc - 1]) - 1, sizeof(char));
        strncpy(peer_port, argv[argc - 1], strlen(argv[argc - 1]));
        if(strlen(peer_ip) == 0 || strlen(peer_port) == 0){
            fprintf(stderr, "Invalid Arguments! It should be ./peer IP PORT [ID] [Peer-IP Peer-PORT]. [ID] and [Peer-IP Peer-PORT] are not necessary.\n");
            return EXIT_FAILURE;
        }

        peer *dht_node = peer_init(0, peer_ip, peer_port);
        printf("Peer:\nIP: %s, Port: %hu\n",dht_node->hostname, dht_node->port);
        int result = join_dht(dht_node);
        free(peer_ip);
        free(peer_port);
        free(dht_node);
        if(result){
            printf("Unsuccessful Join!\n");
            return EXIT_FAILURE;
        }
    }

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
    finger = calloc(1, sizeof(ftable));
    finger->fpeer = NULL;
    finger->hash = 0;
    finger->next = NULL;
    *ht = NULL;
    *rt = NULL;
    srv->succ = succ;
    srv->self = self;
    srv->packet_cb = handle_packet;
    server_run(srv);
    close(srv->socket);
}
