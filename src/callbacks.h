#include <microhttpd.h>
#include "cJSON.h"

extern inline void int32_cgmail_set_auth_code(const char *authorization_code);
extern inline void int32_cgmail_set_result(int res);
extern inline void int32_cgmail_set_ac_tk(const char *ac_tk);
extern inline void int32_cgmail_set_rf_tk(const char *rf_tk);

static enum MHD_Result int32_cgmail_http_callback(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    const char *page = "<html><body><h1>Authenticated.</h1></body></html>";
    const char *page_error = "<html><body><h1>Authentication error.</h1></body></html>";
    struct MHD_Response *response;
    int ret;
    
    const char *code = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "code");

    if (code == NULL) {
        int32_cgmail_set_auth_code(code);
        int32_cgmail_set_result(-1);
        response = MHD_create_response_from_buffer(strlen(page_error)+1, (void*)page_error, MHD_RESPMEM_MUST_COPY);
        //response = MHD_create_response_from_data(strlen(page_error), (void*)page_error, MHD_NO, MHD_YES);

    } else {
        int32_cgmail_set_auth_code(code);
        int32_cgmail_set_result(1);
        response = MHD_create_response_from_buffer(strlen(page)+1, (void*)page, MHD_RESPMEM_MUST_COPY);
        //response = MHD_create_response_from_data(strlen(page), (void*)page, MHD_NO, MHD_YES);

    }

    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;
}

size_t int32_cgmail_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    // This function will be called with the response data

    int res = 1;

    cJSON *root = cJSON_Parse(ptr);
    if (!root) {
        res = -1;
        goto cleanup;
    }

    cJSON *ac_tk_json = cJSON_GetObjectItemCaseSensitive(root, "access_token");
    cJSON *rf_tk_json = cJSON_GetObjectItemCaseSensitive(root, "refresh_token");
    
    if (!cJSON_IsString(ac_tk_json) || !cJSON_IsString(rf_tk_json))
        res = -1;

    cleanup:

    int32_cgmail_set_ac_tk(cJSON_GetStringValue(ac_tk_json));
    int32_cgmail_set_rf_tk(cJSON_GetStringValue(rf_tk_json));
    int32_cgmail_set_result(res);

    cJSON_Delete(root);

    return size * nmemb;
}

struct upload_status {
    size_t bytes_read;
    const char *data;
};

static size_t int32_cgmail_read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct upload_status *upload_ctx = (struct upload_status *)userp;
  const char *data;
  size_t room = size * nmemb;
 
  if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
    return 0;
  }
 
  data = &(upload_ctx->data)[upload_ctx->bytes_read];
 
  if(data) {
    size_t len = strlen(data);
    if(room < len)
      len = room;
    memcpy(ptr, data, len);
    upload_ctx->bytes_read += len;
 
    return len;
  }
 
  return 0;
}