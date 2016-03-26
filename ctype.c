#include "mod_doshelper.h"

extern apr_status_t check_ignore_content_type(request_rec *r, const char *buf) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    apr_table_entry_t **elts = (apr_table_entry_t **)NULL;
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
    int i;

    // Validation Check
    if (buf == (const char *)NULL) { return DECLINED; }

    elts = (apr_table_entry_t **)cfg->common->ct_regexp->elts;
    for (i = 0; i < cfg->common->ct_regexp->nelts; i++) {
        if (elts[i] != (apr_table_entry_t *)NULL &&
            !ap_regexec((ap_regex_t*)elts[i], buf, AP_MAX_REG_MATCH, regmatch, 0)) {
            return DECLINED;
        }
    }
    return APR_SUCCESS;
}

extern apr_status_t check_content_type(request_rec *r) {
    const char *content_type;

    // will check the content-type or accept (HTTP_ACCEPT)
    content_type = (char *)ap_sub_req_lookup_uri(r->uri, r, NULL)->content_type;
    if (!content_type) {
        content_type = apr_pstrdup(r->pool, "");
    }
    if (check_ignore_content_type(r, content_type) == DECLINED) { return DECLINED; }

    return APR_SUCCESS;
}
