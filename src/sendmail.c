/*
 * Copyright (c) 2023 Int32_ (wInt32)
 *
 * This software is licensed under the MIT License below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <semaphore.h>
#include <errno.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "Ws2_32.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <sendmail.h>
#include "cJSON.h"

#define GNU_SOURCE

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};
static char *sendmailc_base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = (char *)malloc(*output_length+1);
    encoded_data[*output_length] = 0;
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

static int sendmailc_error = 0;
static const char *sendmailc_error_str = "";

/* initialize sendmailc */
sendmailc_t *sendmailc_init(void) {
    sendmailc_t *s = malloc(sizeof(sendmailc_t));
    if (s == NULL)
        return NULL;
    s->smtp_server_url = NULL;
    s->smtp_username = NULL;
    s->curl = curl_easy_init();
    return s;
}

static sem_t data_ready;

static size_t google_response_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    sendmailc_error = 0;

    size_t realsize = size * nmemb;
    sendmailc_buffer_t *buffer = userp;

    char *ptr = malloc(realsize + 1);
    if (ptr == NULL) {
        sendmailc_error = ENOMEM;
        return CURLE_OUT_OF_MEMORY;
    }

    buffer->memory = ptr;
    memcpy(buffer->memory, contents, realsize);
    buffer->size = realsize;
    buffer->memory[realsize] = 0;

    sem_post(&data_ready);
    return realsize;
}


static int google_request(CURL *curl, sendmailc_google_oauth2_t *auth, char *request) {
    char request_buffer[2048];
    snprintf(request_buffer, sizeof(request_buffer)-1, request, auth->authorization_code, auth->client_id, auth->client_secret);

    sem_init(&data_ready, 0, 0);
    sendmailc_buffer_t response_buffer = {0};

    #ifndef __linux
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    #endif
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_buffer);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &google_response_callback);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_buffer);
    curl_easy_setopt(curl, CURLOPT_URL, "https://accounts.google.com/o/oauth2/token");
    CURLcode result = curl_easy_perform(curl);

    if (result != CURLE_OK) {
        sendmailc_error_str = curl_easy_strerror(result);
        return SENDMAILC_ERROR;
    }
        

    sem_wait(&data_ready);
    sem_destroy(&data_ready);


    cJSON *root = cJSON_Parse(response_buffer.memory);
    if (!root) {
        free(response_buffer.memory);
        return SENDMAILC_ERROR;
    }

    cJSON *access_token_object = cJSON_GetObjectItemCaseSensitive(root, "access_token");
    cJSON *refresh_token_object = cJSON_GetObjectItemCaseSensitive(root, "refresh_token");
    
    char *at = cJSON_GetStringValue(access_token_object);
    if (at == NULL)  {
        cJSON_Delete(root);
        free(response_buffer.memory);
        return SENDMAILC_ERROR;
    }
    int a = strlen(at) + 1;
    auth->access_token=malloc(a);
    if (auth->access_token == NULL) {
        cJSON_Delete(root);
        free(response_buffer.memory);
        return SENDMAILC_ERROR;
    }
    memcpy(auth->access_token, at, a);

    char *rf = cJSON_GetStringValue(refresh_token_object);
    if (rf == NULL)
        return SENDMAILC_ERROR;
    int r = strlen(rf) + 1;
    auth->refresh_token=malloc(r);
    if (auth->refresh_token == NULL) {
        cJSON_Delete(root);
        free(response_buffer.memory);
        return SENDMAILC_ERROR;
    }
    memcpy(auth->refresh_token, rf, r);

    cJSON_Delete(root);
    free(response_buffer.memory);
    return SENDMAILC_OK;
}

static int google_authorize(CURL *curl, sendmailc_google_oauth2_t *auth) {
    auth->authorization_code = auth->get_auth_code(auth->client_id, auth->client_secret);
    if (auth->authorization_code == NULL)
        return SENDMAILC_ERROR;

    char *request = "grant_type=authorization_code&redirect_uri=http://localhost:12000&code=%s&client_id=%s&client_secret=%s";
    google_request(curl, auth, request);
}

sendmailc_buffer_t response_buffer = {0};

static int google_refresh_tokens(CURL *curl, sendmailc_google_oauth2_t *auth) {
    char *request = "grant_type=refresh_toke&redirect_uri=http://localhost:12000&code=%s&client_id=%s&client_secret=%s";
    google_request(curl, auth, request);
}

/* fetch missing fields in sendmailc_google_oauth2 from google */
int sendmailc_google_auth(sendmailc_t *sendmailc, sendmailc_google_oauth2_t *auth) {

    if (auth->client_id == NULL || auth->client_secret == NULL)
        return SENDMAILC_ERROR;

    int ret = 0;
    if (auth->access_token == NULL || auth->refresh_token == NULL) {
        if (auth->refresh_token == NULL ) {
            if (auth->get_auth_code == NULL)
                return SENDMAILC_ERROR;

            if (google_authorize(sendmailc->curl, auth) < 0)
                return SENDMAILC_ERROR;
            goto smtp_auth;
        }
        
        if (google_refresh_tokens(sendmailc->curl, auth) < 0)
            return SENDMAILC_ERROR;
    }

    smtp_auth:
    char *gmail_smtp_url = "smtps://smtp.gmail.com";
    size_t url_len = strlen(gmail_smtp_url);
    sendmailc->smtp_server_url = calloc(url_len+1, 1);
    strcpy(sendmailc->smtp_server_url, gmail_smtp_url);
    int address_len = strlen(auth->user_email_address);
    sendmailc->smtp_username = calloc(address_len+1, 1);
    memcpy(sendmailc->smtp_username, auth->user_email_address, address_len);

    char credentials_buffer[2048] = {0};
    char *credentials = "user=%s\001auth=Bearer %s\001\001";
    snprintf(credentials_buffer, sizeof(credentials_buffer)-1, credentials, sendmailc->smtp_username, auth->access_token);

    printf("credentials buffer(%i): %s\n", sizeof(credentials_buffer), credentials_buffer);
    size_t len = 0;
    char *base64_credentials = sendmailc_base64_encode(credentials_buffer, strlen(credentials_buffer), &len);

    char command_buffer[2048] = {0};
    char *auth_command = "AUTH XOAUTH2 %s";
    snprintf(command_buffer, sizeof(command_buffer)-1, auth_command, base64_credentials);

    printf("cmd: %s\n", command_buffer);


    curl_easy_setopt(sendmailc->curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(sendmailc->curl, CURLOPT_URL, sendmailc->smtp_server_url);
    curl_easy_setopt(sendmailc->curl, CURLOPT_CUSTOMREQUEST, command_buffer);
    int res = curl_easy_perform(sendmailc->curl);
    if (res == CURLE_OK)
        return SENDMAILC_OK;
    
    return SENDMAILC_ERROR;

}

/* create a new email */
sendmailc_email_t *sendmailc_email_new(sendmailc_t *sendmailc) {
    sendmailc_email_t *email = calloc(1, sizeof(sendmailc_email_t));
    if (email == NULL)
        return NULL;
    email->to=NULL;
    email->headers=NULL;
    email->from=NULL;
    if (sendmailc->smtp_username != NULL) {
        size_t name_len = strlen(sendmailc->smtp_username);
        email->from = malloc(name_len+1);
        if (email->from == NULL) {
            free(email);
            return NULL;
        }
        strcpy(email->from, sendmailc->smtp_username);
    }
    
    email->body=NULL;
}

/* add recipient*/
void sendmailc_email_add_to(sendmailc_email_t *email, const char *email_address) {
    email->to = curl_slist_append(email->to, email_address);
}

/* set the subject */
int sendmailc_email_set_subject(sendmailc_email_t *email, const char *subject) {
    int len = strlen(subject)+1;
    free(email->subject);
    email->subject = malloc(len);
    if (email->subject == NULL) {
        return SENDMAILC_ERROR;
    }
    strcpy(email->subject, subject);
}

/* add a custom header */
void sendmailc_email_add_header(sendmailc_email_t *email, const char *header, const char *value) {
    char buffer[1024] = {0};
    snprintf(buffer, sizeof(buffer), "%s: %s\n", header, value);
    email->headers = curl_slist_append(email->headers, buffer);
}

/* set the body of the email */
int sendmailc_email_set_body(sendmailc_email_t *email, const char *body) {
    int len = strlen(body)+1;
    free(email->body);
    email->body = malloc(len);
    if (email->body == NULL) {
        return SENDMAILC_ERROR;
    }
    strcpy(email->body, body);
}

struct upload_data {
    size_t bytes_read;
    sendmailc_buffer_t *buffer;
};

static size_t smtp_read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{

    struct upload_data *upload = userp;
    sendmailc_buffer_t *buffer = upload->buffer;

    size_t room = size * nmemb;

    if (upload->bytes_read > 0)
        return 0;

    if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1))
        return 0;

    upload->bytes_read = strlen(strncpy(ptr, buffer->memory, room))+1;

    return upload->bytes_read;
}


/* send the email */
int sendmailc_send_email(sendmailc_t *sendmailc, sendmailc_email_t *email) {

    size_t to_len = 0;
    struct curl_slist *current = NULL;
    current = email->to;

    while (current != NULL) {
        to_len += strlen(current->data);
        current = current->next;
    }

    char *to_buffer = calloc(to_len+5, 1);
    if (to_buffer == NULL)
        return SENDMAILC_ERROR;

    strcpy(to_buffer, "To: ");

    current = email->to;
    while (current != NULL) {
        strcat(to_buffer, current->data);

        if (current->next !=NULL)
            strcat(to_buffer, ", ");

        current = current->next;
    }

    int subject_len = strlen(email->subject);
    int body_len = strlen(email->body);
    size_t from_len = strlen(email->from);

    size_t header_len = 0;
    struct curl_slist *current_header = NULL;
    current_header = email->headers;

    while (current_header != NULL) {
        header_len += strlen(current_header->data);
        current_header = current_header->next;
    }

    char *header_buffer = calloc(header_len+1, 1);
    if (header_buffer == NULL) {
        free(to_buffer);
        return SENDMAILC_ERROR;
    }

    current_header = email->headers;
    while (current_header != NULL) {
        strcat(header_buffer, current_header->data);
        current_header = current_header->next;
    }

    struct upload_data upload_data = {0};
    upload_data.buffer = malloc(sizeof(sendmailc_buffer_t));
    if (upload_data.buffer == NULL) {
        free(to_buffer);
        free(header_buffer);
        return SENDMAILC_ERROR;
    }
    upload_data.bytes_read = 0;

    upload_data.buffer->size = to_len + from_len + body_len + header_len + subject_len +20;
    upload_data.buffer->memory = calloc(upload_data.buffer->size + 1, 1);
    if (upload_data.buffer->memory == NULL) {
        free(to_buffer);
        free(header_buffer);
        free(upload_data.buffer);
        return SENDMAILC_ERROR;
    }

    snprintf(upload_data.buffer->memory, upload_data.buffer->size, "%sSubject: %s\r\n\r\n%s\r\n", header_buffer, email->subject, email->body);

    //curl_easy_reset(sendmailc->curl);
    curl_easy_setopt(sendmailc->curl, CURLOPT_URL, sendmailc->smtp_server_url);
    curl_easy_setopt(sendmailc->curl, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(sendmailc->curl, CURLOPT_MAIL_FROM, email->from);
    curl_easy_setopt(sendmailc->curl, CURLOPT_MAIL_RCPT, email->to);
    curl_easy_setopt(sendmailc->curl, CURLOPT_READFUNCTION, &smtp_read_callback);
    curl_easy_setopt(sendmailc->curl, CURLOPT_READDATA, &upload_data);

    int res = curl_easy_perform(sendmailc->curl);
    if (res == CURLE_OK)
        return SENDMAILC_OK;
    
    return SENDMAILC_ERROR;
}

#ifdef __unix__
#define os_socket_t int
typedef struct os_state {
    
} os_state_t;

static int os_socket_init(os_socket_t *server, os_socket_t *client, os_state_t *state, int port, int timeout_msec) {
    *server = socket(AF_INET, SOCK_STREAM, PF_UNSPEC);
    struct sockaddr_in serv_addr, cli_addr;
    size_t cli_addr_len;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    int reuseaddr = 1;
    struct timeval timeout = {0};
    timeout.tv_usec = 1000*timeout_msec;
    setsockopt(*server, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
    setsockopt(*server, SOL_SOCKET, 15, &reuseaddr, sizeof(reuseaddr));
    setsockopt(*server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (bind(*server, (void*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind()");
        return SENDMAILC_ERROR;
    }
    listen(*server, 1);
    *client = accept(*server, (void*)&cli_addr, (void*)&cli_addr_len);
    if (*client < 0) {
        perror("accept()");
        return SENDMAILC_ERROR;
    }
}

static void os_cleanup(os_socket_t client, os_socket_t server) {
    close(client);
    close(server);
}

#endif

#if defined(_WIN32) || defined(_WIN64)
#define os_socket_t SOCKET
typedef struct os_state {
    WSADATA wsaData;
} os_state_t;

static int os_socket_init(os_socket_t *server, os_socket_t *client, os_state_t *state, int port, int timeout_msec) {
    int iResult;

    // initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &state->wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup(): %d\n", iResult);
        return SENDMAILC_ERROR;
    }

    struct addrinfo *result = NULL, *ptr = NULL, hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // resolve the local address and port to be used by the server
    iResult = getaddrinfo(NULL, "sendmailc", &hints, &result);
    if (iResult != 0) {
        fprintf(stderr, "getaddrinfo(): %d\n", iResult);
        WSACleanup();
        return 1;
    }
    *server = INVALID_SOCKET;

    // create a SOCKET for the server to listen for client connections
    *server = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (*server == INVALID_SOCKET) {
        fprintf(stderr, "socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }
    int reuseaddr = 1;
    setsockopt(*server, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuseaddr, sizeof(reuseaddr));
    setsockopt(*server, SOL_SOCKET, SO_RCVTIMEO, (const char *)&reuseaddr, sizeof(reuseaddr));
    setsockopt(*server, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_msec, sizeof(timeout_msec));

    // setup the TCP listening socket
    iResult = bind(*server, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "bind(): %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(*server);
        WSACleanup();
        return 1;
    }
    freeaddrinfo(result);
    if (listen(*server, 1) == SOCKET_ERROR) {
        fprintf(stderr, "listen(): %ld\n", WSAGetLastError());
        closesocket(*server);
        WSACleanup();
        return 1;
    }
    *client = INVALID_SOCKET;

    // accept a client socket
    *client = accept(*server, NULL, NULL);
    if (*client == INVALID_SOCKET) {
        fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
        closesocket(*server);
        WSACleanup();
        return 1;
    }
}

static void os_cleanup(os_socket_t client, os_socket_t server) {
    closesocket(client);
    closesocket(server);
    WSACleanup();
}
#endif


static char *http_listen(int port, int timeout_msec) {

    os_socket_t server;
    os_socket_t client;
    os_state_t state = {};
    if (os_socket_init(&server, &client, &state, port, timeout_msec) == SENDMAILC_ERROR)
        return NULL;

    char buf[4096];

    if (recv(client, buf, 4095, 0) < 0) {
        return NULL;
    }

    const char headers[] = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n";
    const char success_page[] = "<html><body><h1>Authenticated.</h1></body></html>\r\n";
    const char error_page[] = "<html><body><h1>Authentication error.</h1></body></html>\r\n";

    char *pattern = "GET /?code=%[^&]s";
    char *authorization_code = calloc(256, 1);

    if (authorization_code == NULL) {
        send(client, error_page, sizeof(error_page)-1, 0);
        goto cleanup;
    }

    sscanf(buf, pattern, authorization_code);
    puts("Auth code:");
    puts(authorization_code);
    send(client, headers, sizeof(headers)-1, 0);
    if (authorization_code[0] == 0) {
        send(client, error_page, sizeof(error_page)-1, 0);
        free(authorization_code);
        authorization_code = NULL;
        goto cleanup;
    }
    send(client, success_page, sizeof(success_page)-1, 0);

cleanup:
    os_cleanup(client, server);
    return authorization_code;
}

char *get_auth_code(const char *client_id, const char *client_secret) {

    #ifdef __linux__
        #define COMMAND "xdg-open \""
    #endif
    #ifdef __APPLE__
        #define COMMAND "open \""
    #endif
    #if defined(_WIN32) || defined(_WIN64)
        #define COMMAND "start \"\" \""
    #endif
    char cmd_base[] = COMMAND "https://accounts.google.com/o/oauth2/v2/auth?scope=https://mail.google.com/&response_type=code&redirect_uri=http://localhost:12000&client_id=";
    #undef COMMAND

    size_t cmd_size = sizeof cmd_base + strlen(client_id)+1;

    char *cmd = malloc(cmd_size+1);
    if (cmd == NULL) {
        return NULL;
    }

    strcpy(cmd, cmd_base);
    strcat(cmd, client_id);

    cmd[cmd_size-2] = '\"';
    cmd[cmd_size-1] = 0;

    // dangerous
    system(cmd);
    free(cmd);

    return http_listen(12000, 10*1000);
}

/* initialize the auth object (MHD) */
sendmailc_google_oauth2_t *sendmailc_google_oauth2_new(const char *client_id, const char *client_secret, const char *user_email_address) {
    sendmailc_google_oauth2_t *auth = malloc(sizeof(sendmailc_google_oauth2_t));
    if (auth == NULL)
        return NULL;

    size_t client_id_len = strlen(client_id);
    size_t client_secret_len = strlen(client_secret);
    size_t user_email_address_len = strlen(user_email_address);

    auth->client_id = calloc(client_id_len+1, 1);
    strcpy(auth->client_id, client_id);

    auth->client_secret = calloc(client_secret_len+1, 1);
    strcpy(auth->client_secret, client_secret);

    auth->user_email_address = calloc(user_email_address_len+1, 1);
    strcpy(auth->user_email_address, user_email_address);

    auth->access_token=NULL;
    auth->authorization_code=NULL;
    auth->get_auth_code=&get_auth_code;
    auth->refresh_token=NULL;
    return auth;
}

/* free the email struct */
void sendmailc_free_email(sendmailc_email_t *email) {
    curl_slist_free_all(email->to);
    curl_slist_free_all(email->headers);
    free(email->body);
    free(email->from);
    free(email->subject);
    free(email);
}

/* free the google oauth2 struct */
void sendmailc_free_google_oauth2(sendmailc_google_oauth2_t *auth) {
    free(auth->client_id);
    free(auth->client_secret);
    free(auth->user_email_address);
    free(auth->authorization_code);
    free(auth->access_token);
    free(auth->refresh_token);
    free(auth);
}

/* free, cleanup and exit sendmailc */
void sendmailc_exit(sendmailc_t *sendmailc) {
    curl_easy_cleanup(sendmailc->curl);
    free(sendmailc->smtp_server_url);
    free(sendmailc->smtp_username);
}