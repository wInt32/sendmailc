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

#include <curl/curl.h>

#define SENDMAILC_OK      0
#define SENDMAILC_ERROR   1

enum sendmailc_smtp_auth_type {
    GOOGLE_OAUTH,
};

typedef struct sendmailc {
    CURL *curl;
    char *smtp_server_url;
    char *smtp_username;
} sendmailc_t;


typedef struct sendmailc_email {
    struct curl_slist *to;
    struct curl_slist *headers;
    char *subject;
    char *from;
    char *body;
} sendmailc_email_t;

typedef struct sendmailc_google_oauth2 {
    char *client_id;
    char *client_secret;
    char *authorization_code;
    char *access_token;
    char *refresh_token;
    char *user_email_address;
    char *(*get_auth_code)(const char *client_id, const char *client_secret);

} sendmailc_google_oauth2_t;

typedef struct sendmailc_buffer {
    char *memory;
    size_t size;
} sendmailc_buffer_t;


/* initialize sendmailc */
sendmailc_t *sendmailc_init(void);

/* fetch missing fields in sendmailc_google_oauth2 from google */
int sendmailc_google_auth(sendmailc_t *sendmailc, sendmailc_google_oauth2_t *auth);

/* create a new email */
sendmailc_email_t *sendmailc_email_new(sendmailc_t *sendmailc);

/* add recipient */
void sendmailc_email_add_to(sendmailc_email_t *email, const char *email_address);

/* add ca custom header */
void sendmailc_email_add_header(sendmailc_email_t *email, const char *header, const char *value);

/* set the body of the email */
int sendmailc_email_set_body(sendmailc_email_t *email, const char *body);

/* set the subject of the email */
int sendmailc_email_set_subject(sendmailc_email_t *email, const char *subject);

/* send the email */
int sendmailc_send_email(sendmailc_t *sendmailc, sendmailc_email_t *email);

/* initialize the auth object */
sendmailc_google_oauth2_t *sendmailc_google_oauth2_new(const char *client_id, const char *client_secret, const char *user_email_address);

/* free the email struct */
void sendmailc_free_email(sendmailc_email_t *email);

/* free the google oauth2 struct */
void sendmailc_free_google_oauth2(sendmailc_google_oauth2_t *auth);

/* free, cleanup and exit sendmailc */
void sendmailc_exit(sendmailc_t *sendmailc);