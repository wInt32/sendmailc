// Sets authorization_code ptr to the auth code obtained from google and returns the length or 0 on failure
// NOTE: Auth code is needed only once, you can use refresh token to get the access token again
// NOTE: This opens a port and uses the system() function to open a web browser and authenticate the user
int google_get_oauth2_authorization_code(char **authorization_code, void *curl, const char *client_id);

// Sets access_token ptr and refresh_token ptr to corresponding values obtained from google from the auth_code
// Returns the length of the access token, or 0 on failure
int google_get_oauth2_access_token(char **access_token, char **refresh_token, const char *auth_code, void *curl, const char *client_id, const char *client_secret);

// Sets access_token ptr and refresh_token ptr to corresponding values obtained from google from the refresh_token
// Returns the length of the access token, or 0 on failure
int google_get_oauth2_refresh_token(char **access_token, char *refresh_token, void *curl, const char *client_id, const char *client_secret);

// Sends the AUTH XOAUTH2 command to the SMTP server
// Returns 1 on success and 0 on failure
int smtp_auth_oauth2(void *curl, const char *url, const char *sender_email_addr, const char *access_token);

// Sends the email
int smtp_send_mail(void *curl, const char *url, const char *sender_email_addr, void *recipients_slist, const char *body);