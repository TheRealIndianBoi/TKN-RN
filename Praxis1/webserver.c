#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>

int sockfd, new_fd;
char *port;
struct addrinfo hints, *serverinfo, *pointer;
struct sockaddr_storage client_addr;
socklen_t sin_size;
struct sigaction sa;

int yes = 1;    //?
char s[INET6_ADDRSTRLEN];
int rv;
#define BACKLOG 10
#define BUFFERSIZE 4096
enum Response {

    R200,
    R201,
    R204,
    R400,
    R403,
    R404,
    R500,
    R501,
    R505
};
char *ResponseList[] = {
        "HTTP/1.0 200 Ok",
        "HTTP/1.0 201 Created",
        "HTTP/1.0 204 No Content",
        "HTTP/1.0 400 Bad Request",
        "HTTP/1.0 403 Forbidden",
        "HTTP/1.0 404 Not Found",
        "HTTP/1.0 500 Internal Server Error",
        "HTTP/1.0 501 Not implemented",
        "HTTP/1.0 505 HTTP Version Not Supported"
};
enum Methods{
    GET,
    POST,
    HEAD,
    PUT,
    DELETE,
    OPTIONS,
    PATCH,
    ADMIN, //Only for me
};
char *MethodList[] = {
    "GET",
    "POST",
    "HEAD",
        "PUT",
        "DELETE",
        "OPTIONS",
        "PATCH",
        "ADMIN"
};
struct paths{
    char * url;
    char *response;
    struct paths *next ;
};

struct paths PathArray[] = {
        {.url = "/", .response = NULL, .next = &PathArray[1]},
        {.url = "/static", .response = NULL, .next = &PathArray[2]},
        {.url = "/dynamic", .response = NULL, .next = &PathArray[3]},
        {.url = "/static/foo", .response = "Foo", .next = &PathArray[4]},
        {.url = "/static/bar", .response = "Bar", .next = &PathArray[5]},
        {.url = "/static/baz", .response = "Baz", .next = NULL},
};

char* allPaths(){
    char *response = calloc(10240, sizeof(char));
    strcpy(response, "Paths:\r\n");
    struct paths *findpaths = &PathArray[0];
    while(findpaths != NULL){
        strcat(response, findpaths->url);
        strcat(response, "\r\n");
        findpaths = findpaths->next;
    }

    return response;
}

int connect_to() {
    unsigned int port_nr = strtol(port, NULL,
                                  10);
    if (port_nr < 1024) {
        printf("Given Port is privileged, so connection couldn't be established ...\n");
        return EXIT_FAILURE;
    } else if (port_nr > 65535) {

        printf("Given Port is greater than the highest TCP-Port 65535, so connection couldn't be established ...\n");
        return EXIT_FAILURE;
    }


    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    rv = getaddrinfo(NULL, port, &hints, &serverinfo);
    if (rv != 0) {
        fprintf(stderr, "Error for getaddrinfo: %s\n", gai_strerror(rv));

        return EXIT_FAILURE;
    }
    printf("Successfully established Connection ...\n");

    return EXIT_SUCCESS;
}

/**
 *Checks if Value of Pointer is a Number or not!
 * @param value = pointer to number
 * @return 1 if number else 0
 */
int isnr(char *value) {
    for (int i = 0; i < strlen(value); ++i) {
        if (!isdigit(value[i])) {
            return 0;
        }
    }
    return 1;
}

void sigchld_handler() {
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}
void deleteFile(char * string){

    printf("Deleting URL: %s\n", string);
    struct paths *delete = &PathArray[0];
    struct paths *before = &PathArray[0];
    while(delete != NULL){
        if(strcmp(delete->url, string) == 0){
            before->next = delete->next;
            free(delete->url);
            free(delete->response);
            free(delete);

            break;
        }
        before = delete;
        delete = delete->next;
    }
}
char *responsemaker(char * path_response, char*response_nr){
    char *response = calloc(4096, sizeof(char));
    strcpy(response, response_nr);
    strcat(response, "\r\n");
    //Header
    char server_header[4096] = "Server: Webserver-TKN_RN\r\n";
    strcat(server_header, "Content-Type: text/html; charset=iso-8859-1\r\n");
    char body[4096];
    if(path_response != NULL){
        strcpy(body, path_response);
    }else{
        strcpy(body, "");
    }
    strcat(server_header, "Content-Length: ");
    char contentlength[1000];
    sprintf(contentlength, "%lu", strlen(body));
    strcat(server_header, contentlength);
    strcat(server_header, "\r\n");
    strcat(response, server_header);
    if(path_response != NULL){
        strcat(response, "\r\n");
        strcat(response, body);
    }else{
        strcat(response, "\r\n");
    }
    return response;
}

char * CheckURL(char * string, int response){
    if(strcmp(string, "/") == 0){
        if(response){
            return responsemaker(PathArray[0].response, ResponseList[R200]);
        }
        return ResponseList[R200];
    }
    printf("Checking URL: %s\n", string);
    if(string[strlen(string)-1] == '/'){
        string[strlen(string) - 1] = '\0';
    }

    printf("Checking URL: %s\n", string);
    struct paths *find = &PathArray[0];
    int valid = 0;
    while(find != NULL){
        printf("Checking: %s\n", find->url);
        if(strcmp(find->url, string) == 0){
            valid = 1;
            break;
        }
        find = find->next;
    }
    if(valid == 0){
        if(response){
            return responsemaker(NULL, ResponseList[R404]);
        }
        return ResponseList[R404];
    }
    if(response){
            return responsemaker(find->response, ResponseList[R200]);
    }
    return ResponseList[R200];

}
char *addFile(char *string, char* payload){
    char * substring = "HTTP";
    char * test = calloc(strlen(string), sizeof(char));
    strcpy(test, string);
    char * end_p = strstr(string, substring);
    char* http_pointer = strstr(test, substring);
    if(http_pointer == NULL){
        return responsemaker(NULL, ResponseList[R400]); //Problem
    }
    char *url = calloc(124, sizeof(char));
    strncpy(url, test, (strlen(test) - strlen(end_p)));
    url[strlen(url) - 1] = '\0';
    char *http = http_pointer +strlen(substring) + 1;
    printf("Url: %s\nHTTP: **%s**\n",url, http);
    free(test);
    if(url[0] == '\0' || http[0] == '\0'){
        free(url);
        return responsemaker(NULL, ResponseList[R400]);
    }

    char * get = CheckURL(url, 0);
    struct paths *add = &PathArray[2];
    if(strcmp(get, ResponseList[R200]) == 0){
        while(strcmp(add->url, url) != 0){
            add = add->next;
        }
        strcpy(add->response, payload);
        free(url);
        return responsemaker(NULL, ResponseList[R200]);
    }
    struct paths *new = malloc(sizeof(struct paths));
    new->next = NULL;
    new->url = calloc(strlen(url), sizeof(char));
    strcpy(new->url, url);
    new->response = calloc(4089, sizeof(char));
    strcpy(new->response, payload);
    free(url);
    while(add->next != NULL){
        add = add->next;
    }
    add->next = new;
    return responsemaker(NULL, ResponseList[R201]);

}


char *checkNoPayload(char *string, int method){
    char * substring = "HTTP";
    char * test = calloc(strlen(string), sizeof(char));
    strcpy(test, string);
    char * end_p = strstr(string, substring);
    char* http_pointer = strstr(test, substring);
    if(http_pointer == NULL){
        return responsemaker(NULL, ResponseList[R400]);
    }
    char *url = calloc(124, sizeof(char));
    strncpy(url, test, (strlen(test) - strlen(end_p)));
    url[strlen(url) - 1] = '\0';
    char *http = http_pointer +strlen(substring) + 1;
    printf("Url: %s\nHTTP: **%s**\n",url, http);
    if(url[0] == '\0' || http[0] == '\0'){
        free(test);
        free(url);
        return responsemaker(NULL, ResponseList[R400]);
    }
    if(method == GET){
        free(test);
        char * result = CheckURL(url,1);
        free(url);
        return result;
    }
    if(method == DELETE){
        if(strncmp(url, "/dynamic/", strlen("/dynamic/")) != 0 || strlen(url) == strlen("/dynamic/")){
            free(test);
            free(url);
            return responsemaker(NULL, ResponseList[R403]);
        }
        if(strcmp(CheckURL(url, 0), ResponseList[R200]) == 0){
            deleteFile(url);
            free(test);
            free(url);
            return responsemaker(NULL, ResponseList[R200]);
        }
        free(test);
        free(url);
        return responsemaker(NULL, ResponseList[R404]);
    }
    free(test);
    free(url);
    return responsemaker(NULL, ResponseList[R501]);
}

char *check(char *string) {
    printf("Checking String: **%s**\n", string);
    if (string == NULL || strcmp(string, "\0") == 0) {
        return responsemaker(NULL, ResponseList[R400]);
    }
    size_t firstline_pos = strcspn(string, "\r\n");
    char * firstline_end = strstr(string, "\r\n");
    char *firstline = calloc(1024,sizeof(char));
    strncpy(firstline, string, firstline_pos);
    firstline[firstline_pos] = '\0';
    printf("FirstLine: %s\n", firstline);
    //First Line Check
    char *substring = "/";
    char * pointer_next = strstr(firstline, substring);
    size_t pos = strcspn(firstline, substring);
    if(pointer_next == NULL){
        //NO method
        free(firstline);
        return responsemaker(NULL, ResponseList[R400]);
    }
    char *method = string;
    strncpy(method, firstline, pos-1);
    method[pos-1] = '\0';
    char *text = pointer_next;
    int valid_method = 0;
    for (int i = 0; i < (sizeof(MethodList) / sizeof(MethodList[0])); ++i) {
            if(strcmp(MethodList[i], method) == 0){
                valid_method = 1;
                break;
            }
    }
    if(valid_method == 0){
        free(firstline);
        return responsemaker(NULL, ResponseList[R400]);
    }
    printf("Method: %s\n", method);
    if(strcmp(MethodList[ADMIN], method) == 0){
        free(firstline);
        return allPaths();
    }
    if(strcmp(MethodList[GET], method) == 0){
        char* result = checkNoPayload(text, GET);
        free(firstline);
        return result;
    }

    if(strcmp(MethodList[HEAD], method) == 0){
        char* result = checkNoPayload(text, HEAD);
        free(firstline);
        return result;
    }

    if(strcmp(MethodList[OPTIONS], method) == 0){
        return responsemaker(NULL, ResponseList[R501]);
    }
    if(strcmp(MethodList[DELETE], method) == 0){
        char* result = checkNoPayload(text, DELETE);
        free(firstline);
        return result;
    }
    char *url = calloc(124, sizeof(char));
    substring = "HTTP";
    char * end_p = strstr(text, substring);
    strncpy(url, text, (strlen(text) - strlen(end_p)));
    url[strlen(url) - 1] = '\0';
    printf("All URL: **%s**\n", url);
    if(strncmp(url, "/dynamic/", strlen("/dynamic/")) != 0 || strlen(url) == strlen("/dynamic/")){
        free(url);
        free(firstline);
        return responsemaker(NULL, ResponseList[R403]);
    }
    free(url);
    printf("\r\nHeader:\n");
    if(firstline_end == NULL){
        printf("No Payload or Header\n");
        free(firstline);
        return responsemaker(NULL, ResponseList[R400]);
    }
    //Check Header and Payload implement needed
    char * HeaderList = firstline_end + strlen("\r\n");
    char * allHeader = calloc(4096, sizeof(char));
    strcpy(allHeader, HeaderList);
    printf("%s\n",allHeader);
    char * next = strtok(allHeader, "\r\n");
    char *content_length_point = NULL;
    int content_length = 0;
    char body[4096];
    ssize_t number = 0;
    while(next != NULL){
        content_length_point = strstr(next, "Content-Length:");
        if(content_length_point != NULL){
            content_length = (int) strtol(content_length_point + strlen("Content-Length:"), NULL, 10);
            if(content_length != 0){
                while(content_length != 0){
                    number = recv(new_fd, body, content_length, 0);
                    if(number != -1){
                        content_length -= (int) number;
                    }else{
                        printf("Error with Recieving!");
                    }
                }
            }
            break;
        }
        next = strtok(NULL, "\r\n");
    }
    free(allHeader);
    printf("Body: **%s**\n", body);
    if(strcmp(MethodList[PUT], method) == 0){
        char* result = addFile(text, body);
        free(firstline);
        return result;
    }
    memset(body, 0, 4096);

    free(firstline);
    return responsemaker(NULL, ResponseList[R501]);


}

void response(char *string) {
    char * message = check(string);
    ssize_t sent = send(new_fd, message, strlen(message), 0);
    while (sent < strlen(message)){
        if(sent == -1){
            perror("send");
        }
        else{
        sent = send(new_fd, message + sent, strlen(message) - sent, 0);
        }
    }
    free(message);
}

void communicate(){

    char buf[BUFFERSIZE];
    ssize_t number = 1;
    char * substring = "\r\n\r\n";
    ssize_t  index = 0;
    while ((number = recv(new_fd, buf + index, 1, 0)) > 0){
        if(index >= BUFFERSIZE){
            printf("Memory for buffer was to low!");
            exit(EXIT_FAILURE);
        }
        char *end = strstr(buf, substring);
        if (end == NULL) {
            index ++;
            continue;
        }
        buf[strlen(buf) - strlen("\r\n\r\n")] = '\0';
        response(buf);
        index = 0;
        memset(buf, 0, BUFFERSIZE);
    }

    if (number == -1) {
        printf("Error from Client!\n");
        close(new_fd);
        exit(EXIT_FAILURE);
    }

}

int bind_connection() {
    for (pointer = serverinfo; pointer != NULL; pointer = pointer->ai_next) {
        if ((sockfd = socket(pointer->ai_family,
                             pointer->ai_socktype, pointer->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            printf("Error with Setup of Socket ...\n");
            return EXIT_FAILURE;
        }
        if (bind(sockfd, pointer->ai_addr, pointer->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }
        break;


    }
    freeaddrinfo(serverinfo);
    if (pointer == NULL) {
        fprintf(stderr, "Server failed to bind!\n");
        return EXIT_FAILURE;
    }
    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        printf("Error with binding...\n");
        return EXIT_FAILURE;
    }
    sa.sa_handler = sigchld_handler;
    sigemptyset((&sa.sa_mask));
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        printf("Error with Sigaction...\n");
        return EXIT_FAILURE;
    }

    printf("Waiting for Connections ...\n");
    while (1) {
        sin_size = sizeof client_addr;
        new_fd = accept(sockfd, (struct sockaddr *) &client_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }
        inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr *) &client_addr), s, sizeof(s));
        printf("Incoming Connection from %s\n\n", s);

        communicate();
        printf("Closing Connection!\n\n");
        close(new_fd);
    }

}

/**
     * argc = count of arguments,
     * argv = all arguments,
     * argv[0] = executed file (not useful),
     * port = argv[1] -> Set connection to Adress with given Port,
     */
int main(int argc, char **argv) {
    // Start here :) - Ok 8]
    if (argc != 2 || isnr(argv[1]) != 1) {
        printf("Execute of Main with given Arguments not Possible. Use:");
        printf("./[Executable File-Path] [Port]\n");
        return EXIT_FAILURE;
    }

    printf("\nExecuted Webserver.c ...\n");
    port = argv[1];
    printf("Setting Connection with Port %s ...\n", port);

    if (connect_to() == EXIT_FAILURE) {
        printf("Exiting with Failure ...\n\n");
        return EXIT_FAILURE;
    }
    printf("Binding Socket ...\n");
    bind_connection();


}

