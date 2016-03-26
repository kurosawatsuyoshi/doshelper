#include "mod_doshelper.h"

extern char *str_conv(request_rec *r, char *buf, const char *conv, const char *to) {
    char *pbuf;

    // Validation Check
    if (buf == (char *)NULL) return apr_pstrdup(r->pool, "");
    if (conv == (char *)NULL || to == (char *)NULL) return buf;

    while ((pbuf = strstr(buf, conv)) != (char *)NULL) {
        *pbuf = '\0';
        pbuf += strlen(conv);
        buf = apr_psprintf(r->pool, "%s%s%s", buf, to, pbuf);
    }

    return buf;
}

extern const char *get_ip_address(request_rec *r) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    apr_array_header_t *ip_array = (apr_array_header_t *)NULL;
    char *token = (char *)NULL;
    const char *address = (const char *)NULL;
    const char *pbuf;
    const char *ptmp;

    /* TODO X-Forwarded-For Test
    const apr_array_header_t *arr;
    apr_table_entry_t *elts = (apr_table_entry_t *)NULL;
#if (AP_SERVER_MAJORVERSION_NUMBER >= 2) && (AP_SERVER_MINORVERSION_NUMBER >= 3)
    apr_table_setn(r->headers_in,
        "X-Forwarded-For", apr_psprintf(r->pool, "192.168.0.1, %s", r->connection->client_ip));
#else
    apr_table_setn(r->headers_in,
        "X-Forwarded-For", apr_psprintf(r->pool, "192.168.0.1, %s", r->connection->remote_ip));
#endif
    arr = (apr_array_header_t *)apr_table_elts(r->headers_in);
    elts = (apr_table_entry_t *)arr->elts;
    //long i;
    //for (i = 0; i < arr->nelts; i++) { DEBUGLOG("%s: %s", elts[i].key, elts[i].val); }
    */

    if (cfg->common->forwarded == FLG_ON){
        pbuf = apr_table_get(r->headers_in, ENV_FORWARDED);
        if (pbuf){
            ptmp = pbuf;
            ip_array = apr_array_make(r->pool, 0, sizeof(char *));
            while ((token = ap_get_token(r->pool, &ptmp, 1)) && *token) {
                *(char **) apr_array_push(ip_array) = token;
                if (*ptmp != '\0')  ptmp++;
            }
            DEBUGLOG("%s: [%s]", ENV_FORWARDED, pbuf);
            if (ip_array->nelts > 1) {
                address = apr_pstrdup(r->pool, ((char **)ip_array->elts)[(ip_array->nelts) - 1]);
            }
            else if (ip_array->nelts == 1) {
                address = pbuf;
            }
        }
        else {
            INFOLOG("%s: [%s]", ENV_FORWARDED, "Not Set");
        }
    }

    if (address == (char *)NULL) {
#if (AP_SERVER_MAJORVERSION_NUMBER >= 2) && \
    (AP_SERVER_MINORVERSION_NUMBER >= 3)
        address = r->connection->client_ip;
#else
        address = r->connection->remote_ip;
#endif
    }

    if (address == (char *)NULL) { ALERTLOG("IP: [NULL]"); }
    DEBUGLOG("address: [%s]", address);

    return address;
}

extern apr_status_t check_regular_expression(request_rec *r, char *haystack, char *needle) {
    ap_regex_t *regexp = (ap_regex_t *)NULL;
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];

    // Validation Check
    if (haystack == (char *)NULL) { return DECLINED; }
    if (needle == (char *)NULL) { return DECLINED; }

    if (strlen(haystack) > 0) {
        regexp = (ap_regex_t *)ap_pregcomp(r->pool, (const char *)haystack, REG_EXTENDED|REG_ICASE);
        if (regexp != (ap_regex_t *)NULL &&
            ap_regexec(regexp, (const char*)needle, regexp->re_nsub + 1, regmatch, 0) == 0) {
            ap_pregfree(r->pool, regexp);
            return APR_SUCCESS;
        }
        ap_pregfree(r->pool, regexp);
    }

    return DECLINED;
}

extern char *extract_string(char *str, char *key, char *delimit) {
    size_t i = 0;

    // Validation Check
    if (str == (char *)NULL) { return (char *)NULL; };
    if (key == (char *)NULL) { return str; };
    if (delimit == (char *)NULL) { return str; };

    i = strlen(key);
    while (*str++ != '\0') {
        if (strncmp(str, key, i) == 0) {
            return (char *)strtok((str+i), delimit);
        }
    }

    return (char *)NULL;
}

