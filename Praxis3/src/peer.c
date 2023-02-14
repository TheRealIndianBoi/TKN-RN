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
htable  **ft = NULL;

// chord peers
peer *self = NULL;
peer *pred = NULL;
peer *succ = NULL;

typedef struct finger_table{
    uint16_t hash;
    peer * fpeer;
    struct finger_table* next;
}ftable;
int fngr_socket = -5;


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

    // build a new packet for the lookup
    packet *lkp = packet_new();
    lkp->flags = PKT_FLAG_CTRL | PKT_FLAG_LKUP;
    lkp->hash_id = hash_id;
    lkp->node_id = self->node_id;
    lkp->node_port = self->port;

    lkp->node_ip = peer_get_ip(self);

    forward(succ, lkp);
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

int notify_dht(peer* client, server* srv){ //TODO:

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
    }//Voerst überschreiben, falls jemand danach versucht reinzujoinen/stabilizen
    while(forward(client, msg) == -1){
        trials += 1;
        fprintf(stderr, "!");
        if(trials == 20){
        fprintf(stderr,"Notify couldn't be send to Port: %d with ID: %d!\n", client->port, client->node_id);
        pred = temp;
        succ = temp2;
        srv->succ = succ;
        peer_free(client);
        return EXIT_FAILURE;
        }
    }
    packet_free(msg);
    if(succ == pred){
        fprintf(stderr, "New Predecessor & Successor:\n IP: %s, Port: %d, ID: %d\n", pred->hostname, pred->port, pred->node_id);
    }else{
        fprintf(stderr, "New Predecessor:\n IP: %s, Port: %d, ID: %d\n\nNew Successor:\n IP: %s, Port: %d, ID: %d\n", pred->hostname, pred->port, pred->node_id,
                                                                                                                    succ->hostname, succ->port, succ->node_id);
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
void send_FACK(){
    packet* response = packet_new();
    response->flags |= PKT_FLAG_CTRL | PKT_FLAG_FACK;
    size_t buf_len;
    unsigned char* resp = packet_serialize(response, &buf_len);
    int timer = 0;
    while(sendall(fngr_socket, resp, buf_len) == -1){
        timer += 1;
        if(timer == 20){
            fprintf(stderr, "FACK couldn't be send!");
            return;
        }
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
        // Look for open requests and proxy them
        peer *n = peer_from_packet(p);
        for (request *r = get_requests(rt, p->hash_id); r != NULL;
             r = r->next) {
            proxy_request(srv, r->socket, r->packet, n);
            server_close_socket(srv, r->socket);
        }
        clear_requests(rt, p->hash_id);
    } else if(p->flags & PKT_FLAG_NTFY) {
        if(succ == NULL || succ->node_id != p->node_id){
            got_packet(p);
            succ = peer_from_packet(p);
            succ->node_id = p->node_id;
            //succ->socket = c->socket;
            srv->succ = succ;
            fprintf(stderr,"New Successor:\n IP: %s, Port: %d, ID: %d\n", succ->hostname, succ->port, succ->node_id);
            packet* stab = packet_new();
            stab->node_id = self->node_id;
            stab->node_ip = peer_get_ip(self);
            stab->node_port = self->port;
            stab->flags |= PKT_FLAG_CTRL | PKT_FLAG_STAB;
            int timer = 0;
            while(forward(succ, stab) == -1){
                timer += 1;
                if(timer == 20){
                    fprintf(stderr, "Stabilize couldn't be send from NTFY!");
                }
            }
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
        fprintf(stderr, "Is it a Peer? %d", p->hash_id);
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

                size_t buffer_len;
                unsigned char* msg = packet_serialize(change, &buffer_len);
            while(sendall(c->socket, msg, buffer_len) == -1){
                timer += 1;
                if(timer == 20){
                    fprintf(stderr, "Notify couldn't be send!\n");
                    free(msg);
                    packet_free(change);
                    return EXIT_FAILURE;
                }
            }} //?
            else{
                while(forward(n, change) == -1){
                    timer += 1;
                    fprintf(stderr, "!");
                    if(timer == 20){
                        fprintf(stderr,"Notify couldn't be send!\n");
                        packet_free(change);
                        return EXIT_FAILURE;}
                }
            }
            /*
            }*/
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
                        if(timer == 20){
                            fprintf(stderr, "Notify couldn't be send!\n");
                            free(msg);
                            packet_free(change);
                            return EXIT_FAILURE;
                        }
                    }} //?
                else{
                    while(forward(n, change) == -1){
                        timer += 1;
                        fprintf(stderr, "!");
                        if(timer == 20){
                            fprintf(stderr,"Notify couldn't be send!\n");
                            packet_free(change);
                            return EXIT_FAILURE;}
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
                        if(timer == 20){
                            fprintf(stderr, "Notify couldn't be send!\n");
                            free(msg);
                            packet_free(change);
                            return EXIT_FAILURE;
                        }
                    }} //?
                else{
                    while(forward(n, change) == -1){
                        timer += 1;
                        fprintf(stderr, "!");
                        if(timer == 20){
                            fprintf(stderr,"Notify couldn't be send!\n");
                            packet_free(change);
                            return EXIT_FAILURE;}
                    }
                }
                packet_free(change);
            }
            peer_free(n);
        }
    }else if(p->flags & PKT_FLAG_FNGR){
        got_packet(p);
        if(fngr_socket == -5){
            fngr_socket = c->socket;
        }
        send_FACK(); //Am ende nach FNGR



    }else if(p->flags & PKT_FLAG_FACK){
        got_packet(p);
    }
        /**
         * TODO:
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
        if(trials == 20){
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
 * TODO:
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

    /*if (argc < 10) {
        fprintf(stderr, "Not enough args! I need ID IP PORT ID_P IP_P PORT_P " "ID_S IP_S PORT_S\n");
    }*/

    if(argc < 3 || argc > 6) {
        fprintf(stderr,
                "Amount of Arguments invalid! It should be ./peer IP PORT [ID] [Peer-IP Peer-PORT]. [ID] is not necessary.\n");
        return EXIT_FAILURE;
    }

    // Read arguments for self
    /*uint16_t idSelf = strtoul(argv[1], NULL, 10);
    char *hostSelf = argv[2];
    char *portSelf = argv[3];*/

    // Read arguments for self

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



    /*// Read arguments for predecessor
    uint16_t idPred = strtoul(argv[4], NULL, 10);
    char *hostPred = argv[5];
    char *portPred = argv[6];

    // Read arguments for successor
    uint16_t idSucc = strtoul(argv[7], NULL, 10);
    char *hostSucc = argv[8];
    char *portSucc = argv[9];
    */

    // Initialize all chord peers
    self = peer_init(idSelf, hostSelf,portSelf); //  Not really necessary but convenient to store us as a peer
    //pred = peer_init(idPred, hostPred, portPred);
    //succ = peer_init(idSucc, hostSucc, portSucc);
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
        //Fehler

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
    ft = (htable **)malloc(sizeof(htable * ));
    *ht = NULL;
    *rt = NULL;
    *ft = NULL;
    srv->succ = succ;
    srv->self = self;
    srv->packet_cb = handle_packet;
    server_run(srv); //added succ
    close(srv->socket);
}
