#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>

#include <curl/curl.h>
#include <microhttpd.h>


#include <sendmail.h>
#include "b64.h"
#include "callbacks.h"


int int32_cgmail_result = 0;
size_t int32_cgmail_authorization_code_size = 0; 
char *int32_cgmail_authorization_code = NULL;

size_t int32_cgmail_access_token_size = 0;
char *int32_cgmail_access_token = NULL;

size_t int32_cgmail_refresh_token_size = 0;
char *int32_cgmail_refresh_token = NULL;

inline void int32_cgmail_set_auth_code(const char *auth_code) {
    if (auth_code == NULL)
        return;

    int32_cgmail_authorization_code_size = strlen(auth_code);
    int32_cgmail_authorization_code = malloc(int32_cgmail_authorization_code_size+1);
    strcpy(int32_cgmail_authorization_code, auth_code);
}


inline void int32_cgmail_set_result(int res) {
    int32_cgmail_result = res;
}

inline void int32_cgmail_set_ac_tk(const char *ac_tk) {
    if (ac_tk == NULL)
        return;

    int32_cgmail_access_token_size = strlen(ac_tk);
    int32_cgmail_access_token = malloc(int32_cgmail_access_token_size+1);
    strcpy(int32_cgmail_access_token, ac_tk);
}

inline void int32_cgmail_set_rf_tk(const char *rf_tk) {
    if (rf_tk == NULL)
        return;

    int32_cgmail_refresh_token_size = strlen(rf_tk);
    int32_cgmail_refresh_token = malloc(int32_cgmail_refresh_token_size+1);
    strcpy(int32_cgmail_refresh_token, rf_tk);
}



int google_get_oauth2_authorization_code(char **auth_code, void *curl, const char *client_id) {

    #ifndef __linux
        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    #endif

    struct MHD_Daemon *daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, 12000, NULL, NULL, &int32_cgmail_http_callback, NULL, MHD_OPTION_END);

    if (daemon == NULL)
        return 0;


    #ifdef __linux
        #define COMMAND "xdg-open \""
    #else
        #define COMMAND "start \"\" \""
    #endif
    char cmd_base[] = COMMAND "https://accounts.google.com/o/oauth2/v2/auth?scope=https://mail.google.com/&response_type=code&redirect_uri=http://127.0.0.1:12000&client_id=";
    #undef COMMAND

    size_t cmd_size = sizeof cmd_base + strlen(client_id)+1;

    char *cmd = malloc(cmd_size+1);

    strcpy(cmd, cmd_base);
    strcat(cmd, client_id);

    cmd[cmd_size-2] = '\"';
    cmd[cmd_size-1] = 0;

    // this should never be used in production code
    system(cmd);
    free(cmd);

    while (!int32_cgmail_result) {}
    if (int32_cgmail_result < 0)
        return 0;

    int32_cgmail_result = 0;

    (*auth_code) = int32_cgmail_authorization_code;
    return int32_cgmail_authorization_code_size;
    
}

int google_get_oauth2_access_token(char **ac_tk, char **rf_tk, const char *auth_code, void *curl, const char *client_id, const char *client_secret){

    #ifndef __linux
        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    #endif

    if (auth_code == NULL)
        return 0;

    char request_base[] = "grant_type=authorization_code&redirect_uri=http://127.0.0.1:12000&code=";
    char client_id_arg[] = "&client_id=";
    char client_secret_arg[] = "&client_secret=";

    size_t request_size = sizeof request_base + sizeof client_id_arg + sizeof client_secret_arg + strlen(auth_code) + strlen(client_id) + strlen(client_secret) + 1;

    char *request = malloc(request_size);
    strcpy(request, request_base);
    strcat(request, auth_code);
    strcat(request, client_id_arg);
    strcat(request, client_id);
    strcat(request, client_secret_arg);
    strcat(request, client_secret);
    request[request_size-1] = 0;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, int32_cgmail_write_callback);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
    curl_easy_setopt(curl, CURLOPT_URL, "https://accounts.google.com/o/oauth2/token");
    curl_easy_perform(curl);

    while (!int32_cgmail_result){}
    (*ac_tk) = int32_cgmail_access_token;
    (*rf_tk) = int32_cgmail_refresh_token;

    if (int32_cgmail_result < 0 ||*ac_tk == NULL || *rf_tk == NULL)
        return 0;

    return int32_cgmail_access_token_size;
}

int google_get_oauth2_refresh_token(char **ac_tk, char *rf_tk, void *curl, const char *client_id, const char *client_secret) {

    #ifndef __linux
        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    #endif

    char request_base[] = "grant_type=refresh_token&refresh_token=";
    char client_id_arg[] = "&client_id=";
    char client_secret_arg[] = "&client_secret=";

    size_t request_size = sizeof request_base + sizeof client_id_arg + sizeof client_secret_arg + strlen(rf_tk) + strlen(client_id) + strlen(client_secret) + 1;

    char *request = malloc(request_size);
    strcpy(request, request_base);
    strcat(request, rf_tk);
    strcat(request, client_id_arg);
    strcat(request, client_id);
    strcat(request, client_secret_arg);
    strcat(request, client_secret);
    request[request_size-1] = 0;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, int32_cgmail_write_callback);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
    curl_easy_setopt(curl, CURLOPT_URL, "https://oauth2.googleapis.com/token");
    curl_easy_perform(curl);

    while (!int32_cgmail_result){}
    (*ac_tk) = int32_cgmail_access_token;

    if (int32_cgmail_result < 0 ||*ac_tk == NULL)
        return 0;

    return int32_cgmail_access_token_size;
}

int smtp_auth_oauth2(void *curl, const char *url, const char *sender_email_addr, const char *ac_tk) {

    #ifndef __linux
        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    #endif

    char auth_str_user_arg[] = "user=";
    char auth_str_auth_arg[] = "\001auth=Bearer ";

    size_t auth_str_size = sizeof auth_str_user_arg + sizeof auth_str_auth_arg + strlen(sender_email_addr) + strlen(ac_tk) + 3;
    char *auth_str = malloc(auth_str_size);
    strcpy(auth_str, auth_str_user_arg);
    strcat(auth_str, sender_email_addr);
    strcat(auth_str, auth_str_auth_arg);
    strcat(auth_str, ac_tk);
    strcat(auth_str, "\x01\x01");
    auth_str[auth_str_size-1] = 0;

    size_t len = 0;
    char *base64_auth = int32_cgmail_base64_encode(auth_str, strlen(auth_str), &len);
    #if 0
    char *b64_auth_zero = malloc(len+1);
    strncpy(b64_auth_zero, base64_auth, len);
    b64_auth_zero[len] = 0;
    free(base64_auth);
    base64_auth = b64_auth_zero;
    #endif
    char auth_header_base[] = "AUTH XOAUTH2 ";

    size_t auth_header_size = sizeof auth_header_base + strlen(base64_auth) + 1;
    
    char *auth_header = malloc(auth_header_size);
    strcpy(auth_header, auth_header_base);
    strcat(auth_header, base64_auth);

    free(auth_str);
    free(base64_auth);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, auth_header);
    int res = curl_easy_perform(curl);
    if (res == CURLE_OK)
        return 1;
    
    return 0;
}

int smtp_send_mail(void *curl, const char *url, const char *sender_email_addr, void *recipients_slist, const char *body) {

    #ifndef __linux
        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    #endif

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, sender_email_addr);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients_slist);

    struct upload_status up = {0};
    up.data = body;

    curl_easy_setopt(curl, CURLOPT_READDATA, &up);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, int32_cgmail_read_callback);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);

    int res = curl_easy_perform(curl);
    if (res == CURLE_OK)
        return 1;
    
    return 0;
}