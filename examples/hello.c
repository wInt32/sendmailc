#include <sendmail.h>

/* defines client_id, client_secret and user_email_address, replace with your own */
#include "credentials.h"

int main() {
    // initialize sendmailc
    sendmailc_t *sendmailc = sendmailc_init();

    // create the google oauth2 struct
    sendmailc_google_oauth2_t *auth = sendmailc_google_oauth2_new(client_id, client_secret, user_email_address);

    // authenticate to google, gets the access token
    sendmailc_google_auth(sendmailc, auth);

    // create a new email
    sendmailc_email_t *email = sendmailc_email_new(sendmailc);

    // add a recipient
    sendmailc_email_add_to(email, user_email_address);

    sendmailc_email_set_subject(email, "Hello!");

    // add a custom header
    sendmailc_email_add_header(email, "Content-Type", "text/html");

    sendmailc_email_set_body(email, "<html><body><b>Hello Gmail!</b></body></html>\n");

    // send the email
    sendmailc_send_email(sendmailc, email);

    // cleanup
    sendmailc_free_email(email);
    sendmailc_free_google_oauth2(auth);
    sendmailc_exit(sendmailc);
}