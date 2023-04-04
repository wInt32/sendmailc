# sendmailc
Send SMTP mail/authenticate to google with C

## Building
It's pretty simple, just run `make` and you'll get `libsendmail.a` in the `lib` folder.
In your program you should `#include <sendmail.h>` and link to `-lsendmail`.

## Example code
```c
#include <stdlib.h>
#include <curl/curl.h>
#include <sendmail.h>

// This is the mail we want to send
static const char *payload_text = "TEST";
 

int main() {

    // Tokens
    char *authorization_code = NULL;
    char *access_token = NULL;
    char *refresh_token = NULL;

    CURL *curl = curl_easy_init();

    // Get the auth code, opens a browser for the user to sign in
    google_get_oauth2_authorization_code(&authorization_code, curl, CLIENT_ID);

    if (ac == NULL)
        return -1;
    
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    
    // From the auth code, we can get the access and refresh tokens
    int len = google_get_oauth2_access_token(&access_token, &refresh_token, authorization_code, curl, CLIENT_ID, CLIENT_SECRET);
    if (len < 0)
        return -1;

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    // Authenticate to gmail's smtp server using the access token
    smtp_auth_oauth2(curl, "smtps://smtp.gmail.com", SENDER_EMAIL_ADDRESS, at);

    struct curl_slist *recip = NULL;
    recip = curl_slist_append(recip, RECIPIENT_EMAIL_ADDRESS);

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    // Let's send the mail
    smtp_send_mail(curl, "smtps://smtp.gmail.com", SENDER_EMAIL_ADDRESS, recip, payload_text);
        
}
```