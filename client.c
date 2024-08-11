#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include <ctype.h>
#include "helpers.h"
#include "requests.h"

#define HOST "34.246.184.49"
#define PORT 8080
#define SERVER "34.246.184.49:8080"
char *message;
char *response;
int sockfd;

void register_user() {
    char username[100];
    char password[100];

    char *buffer = calloc(BUFLEN, sizeof(char));
    size_t buflen = BUFLEN;

    // Remove the newline character
    getchar();
    printf("username=");
    getline(&buffer, &buflen, stdin);
    buffer[strlen(buffer) - 1] = '\0';
    strcpy(username, buffer);
    printf("password=");
    getline(&buffer, &buflen, stdin);
    buffer[strlen(buffer) - 1] = '\0';
    strcpy(password, buffer);

    // Check if username and password are valid
    // If they contain spaces, they are invalid
    for (int i = 0; i < strlen(username); i++) {
        if (isspace(username[i])) {
            printf("ERROR invalid username");
            return;
        }
    }

    for (int i = 0; i < strlen(password); i++) {
        if (isspace(password[i])) {
            printf("ERROR invalid password");
            return;
        }
    }

    // Build the body of the request
    char **body_data = malloc(sizeof(char *));
    body_data[0] = calloc(LINELEN, sizeof(char));
    sprintf(body_data[0], "{\n\t\"username\": \"%s\", \n\t\"password\": \"%s\"\n}", username, password);
    // Compute the message and send it to the server
    message = compute_post_request(HOST, "/api/v1/tema/auth/register", "application/json", body_data, 1, NULL, 0, NULL);
    send_to_server(sockfd, message);
    // Receive the response from the server
    response = receive_from_server(sockfd);

    // Check if the response contains the word "error"
    char *p = strstr(response, "error");
    if(p != NULL) {
        printf("ERROR failed to register user");
        return;
    }
    else {
        printf("SUCCESS user registered");
    }

    free(body_data[0]);
    free(body_data);
    free(response);
    return;
}

void login(char **cookies)
{
    char username[100];
    char password[100];
    char *buffer = calloc(BUFLEN, sizeof(char));
    size_t buflen = BUFLEN;

    getchar();
    printf("username=");
    getline(&buffer, &buflen, stdin);
    buffer[strlen(buffer) - 1] = '\0';
    strcpy(username, buffer);
    printf("password=");
    getline(&buffer, &buflen, stdin);
    buffer[strlen(buffer) - 1] = '\0';
    strcpy(password, buffer);

    // Check if the user is already logged in by checking if the cookies are not NULL
    if (*cookies != NULL) {
        printf("ERROR already logged in");
        return;
    }

    // Check if username and password are valid
    // If they contain spaces, they are invalid
    for (int i = 0; i < strlen(username); i++) {
        if (isspace(username[i])) {
            printf("ERROR invalid username");
            return;
        }
    }

    for (int i = 0; i < strlen(password); i++) {
        if (isspace(password[i])) {
            printf("ERROR invalid password");
            return;
        }
    }
    
    char **body_data = calloc(1, sizeof(char *));
    body_data[0] = calloc(LINELEN, sizeof(char));
    sprintf(body_data[0], "{\n\t\"username\": \"%s\", \n\t\"password\": \"%s\"\n}", username, password);
    message = compute_post_request(SERVER, "/api/v1/tema/auth/login", "application/json", body_data, 1, NULL, 0, NULL);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // Check if the response contains the word "error"
    char *p = strstr(response, "error");
    if (p != NULL) {
        // Check if the response contains the word "Credentials"
        // If it does, the password is invalid
        if (strstr(response, "Credentials") != NULL) {
            printf("ERROR invalid password");
            return;
        }
        
        printf("ERROR no account with this username");
        return;
    }
    else {
        // Extract the cookies from the response and print the success message
        *cookies = strdup(strtok(strstr(response, "connect.sid"), ";"));
        printf("SUCCESS logged in");
    }
    
    free(body_data[0]);
    free(body_data);
    free(response);
    return;
}

void enter_library(char **cookies, char **token)
{
    // Check if the user is logged in
    if (*cookies == NULL) {
        printf("ERROR not logged in");
        return;
    }

    // Check if the user is already in the library
    if (*token != NULL) {
        printf("ERROR already in library");
        return;
    }

    message = compute_get_request(HOST, "/api/v1/tema/library/access", NULL, cookies, 1, NULL);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    char *p = strstr(response, "error");
    if (p != NULL) {
        printf("ERROR failed to enter library");
        return;
    }
    else {
        // Extract the token from the response and print the success message
        // The token is everything after the word "token" and before the last character
        *token = strdup(strtok(strstr(response, "\"token"), "}"));
        // Skip "token= ""
        *token = *token + 9;
        // Remove the last character
        (*token)[strlen(*token) - 1] = '\0';
        printf("SUCCESS entered library");
    }

    free(response);
    return;
    
}

void get_books(char **token, char **cookies)
{
    // Check if the user is logged in
    if (*cookies == NULL) {
        printf("ERROR not logged in");
        return;
    }

    // Check if the user is in the library
    if (*token == NULL) {
        printf("ERROR not in library");
        return;
    }

    message = compute_get_request(HOST, "/api/v1/tema/library/books", NULL, NULL, 0, *token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    
    if (strstr(response, "error") != NULL) {
        printf("ERROR failed to get books");
        return;
    }

    // Extract the books from the response and print them
    char *books = strstr(response, "[");
    printf("%s\n", books);
    free(response);
    return;
}

void get_book(char **token, char **cookies)
{
    int id;
    printf("id=");
    scanf("%d", &id);

    // Check if the user is logged in
    if (*cookies == NULL) {
        printf("ERROR not logged in");
        return;
    }

    // Check if the user is in the library
    if (*token == NULL) {
        printf("ERROR not in library");
        return;
    }

    // Build the URL for the request by adding the id to the URL
    char *url = calloc(LINELEN, sizeof(char));
    // Add the id to the URL
    sprintf(url, "/api/v1/tema/library/books/%d", id);
    message = compute_get_request(HOST, url, NULL, NULL, 0, *token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // Check if the response contains the word "error"
    if (strstr(response, "error")) {
        if (strstr(response, "No book was found") != NULL) {
            printf("ERROR there is currently no book with this id");
            return;
        }
    
        printf ("ERROR you have no access to the library.");
        return;
    }

    // Extract the book from the response and print it
    char *book = basic_extract_json_response(response);
    printf("%s\n", book);
    free(url);
    free(response);
    return;

}

void add_book(char **token, char **cookies)
{
    char title[100], author[100], genre[100], publisher[100], page_count[100];
    char *buffer = calloc(BUFLEN, sizeof(char));
    size_t buflen = BUFLEN;
    // Remove the newline character
    getchar();
    printf("title=");
    // Read the input from the user and remove the newline character
    getline(&buffer, &buflen, stdin);
    buffer[strlen(buffer) - 1] = '\0';
    strcpy(title, buffer);
    printf("author=");
    getline(&buffer, &buflen, stdin);
    buffer[strlen(buffer) - 1] = '\0';
    strcpy(author, buffer);
    printf("genre=");
    getline(&buffer, &buflen, stdin);
    buffer[strlen(buffer) - 1] = '\0';
    strcpy(genre, buffer);
    printf("publisher=");
    getline(&buffer, &buflen, stdin);
    buffer[strlen(buffer) - 1] = '\0';
    strcpy(publisher, buffer);
    printf("page_count=");
    getline(&buffer, &buflen, stdin);
    buffer[strlen(buffer) - 1] = '\0';
    strcpy(page_count, buffer);
    free(buffer);

    // Check if the user is logged in
    if (*cookies == NULL) {
        printf("ERROR not logged in");
        return;
    }

    // Check if the user is in the library
    if (*token == NULL) {
        printf("ERROR not in library");
        return;
    }

    // Check if the fields are valid
    if (strlen(title) == 0 || strlen(author) == 0 || strlen(genre) == 0 || strlen(publisher) == 0 || strlen(page_count) == 0) {
        printf("ERROR invalid fields");
        return;
    }

    // Check if the page_count is numeric
    int is_numeric = 1;
    for (int i = 0; i < strlen(page_count); i++) {
        if (!isdigit(page_count[i])) {
            is_numeric = 0; 
            break;
        }
    }

    // If the page_count is not numeric, print the error message
    if (!is_numeric) {
        printf("ERROR invalid page_count");
        return;
    }

    char **body_data = calloc(1, sizeof(char *));
    body_data[0] = calloc(LINELEN, sizeof(char));
    // Build the body of the request and covert page_count to an integer
    sprintf(body_data[0], "{\n\t\"title\": \"%s\", \n\t\"author\": \"%s\", \n\t\"genre\": \"%s\", \n\t\"page_count\": %d, \n\t\"publisher\": \"%s\"\n}", title, author, genre, atoi(page_count), publisher);
    message = compute_post_request(HOST, "/api/v1/tema/library/books", "application/json", body_data, 1, NULL, 0, *token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // Check if the response contains the word "error"
    if (strstr(response, "error") != NULL) {
        printf("ERROR failed to add book");
        return;
    }
    else {
        printf("SUCCESS added book");
    }

    free(body_data[0]);
    free(body_data);
    free(response);
    return;
}

void delete_book(char **token, char **cookies)
{
    int id;
    printf("id=");
    scanf("%d", &id);

    // Check if the user is logged in
    if (*cookies == NULL) {
        printf("ERROR not logged in");
        return;
    }

    // Check if the user is in the library
    if (*token == NULL) {
        printf("ERROR not in library");
        return;
    }

    // Build the URL for the request by adding the id to the URL
    char *url = calloc(LINELEN, sizeof(char));
    sprintf(url, "/api/v1/tema/library/books/%d", id);
    message = compute_delete_request(HOST, url, *token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    if (strstr(response, "error") != NULL) {
        if (strstr(response, "No book was deleted") != NULL) {
            printf("ERROR there are currently no books with this id");
            return;
        }
    
        printf ("ERROR you have no access to the library.");
        return;
    }
    
    printf("SUCCESS deleted book");
    free(url);
    free(response);
    return;
}

void logout(char **cookies, char **token) {
    // Check if the user is logged in
    if (*cookies == NULL) {
        printf("ERROR not logged in");
        return;
    }

    message = compute_get_request(HOST, "/api/v1/tema/auth/logout", NULL, cookies, 1, NULL);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    char *p = strstr(response, "error");
    if (p != NULL) {
        printf("ERROR failed to logout");
        return;
    }
    else {
        // Set the cookies and token to NULL and print the success message
        *cookies = NULL;
        *token = NULL;
        printf("SUCCESS logged out");
    }

    free(response);
    return;
}

int main(int argc, char *argv[])
{
    char *cookies = NULL;
    char *token = NULL;
    while(1) {
        // Open connection to server for each command
        sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Failed to open connection");
            return 1;
        }

        char command[100];
        scanf("%s", command);

        if (strcmp(command, "register") == 0) {
            register_user();
        } else if (strcmp(command, "login") == 0) {
            login(&cookies);
        } else if (strcmp(command, "enter_library") == 0) {
            enter_library(&cookies, &token);
        } else if (strcmp(command, "get_books") == 0) {
            get_books(&token, &cookies);
        } else if (strcmp(command, "get_book") == 0) {
            get_book(&token, &cookies);
        } else if (strcmp(command, "add_book") == 0) {
            add_book(&token, &cookies);
        } else if (strcmp(command, "delete_book") == 0) {
            delete_book(&token, &cookies);
        } else if (strcmp(command, "logout") == 0) {
            logout(&cookies, &token);
        } else if (strcmp(command, "exit") == 0) {
            close_connection(sockfd);
            break;
        } else {
            printf("ERROR invalid command\n");
        }

        close_connection(sockfd);
    }
}
