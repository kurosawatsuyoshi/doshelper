#include "mod_doshelper.h"

extern apr_status_t put_screen_ip_set(request_rec *r, char *proc) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    char *pbuf = (char *)NULL;

    // Validation Check
    if (proc == (char *)NULL) { return DECLINED; }

    if (cfg->ctl->setfile->page == (char *)NULL ||
        strlen(cfg->ctl->setfile->page) == 0) return DECLINED;

    pbuf = apr_pstrdup(r->pool, cfg->ctl->setfile->page);
    pbuf = str_conv(r, pbuf, CNV_IP, get_ip_address(r));
    pbuf = str_conv(r, pbuf, CNV_PROC, proc);
    pbuf = str_conv(r, pbuf, CNV_URI, r->uri);

    return put_screen(r, pbuf);
}

extern apr_status_t put_screen_ip_complete(request_rec *r, char *ip, char *proc) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    char *pbuf = (char *)NULL;

    // Validation Check
    if (ip == (char *)NULL) { return DECLINED; }
    if (proc == (char *)NULL) { return DECLINED; }
    if (cfg->ctl->cplfile->page == (char *)NULL ||
        strlen(cfg->ctl->cplfile->page) == 0) return DECLINED;

    pbuf = apr_pstrdup(r->pool, cfg->ctl->cplfile->page);
    pbuf = str_conv(r, pbuf, CNV_IP, get_ip_address(r));
    pbuf = str_conv(r, pbuf, CNV_PROC, proc);
    pbuf = str_conv(r, pbuf, CNV_IP, ip);

    return put_screen(r, pbuf);
}

extern apr_status_t put_screen_ip_list(request_rec *r, char *iplist, char *proc) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    char *pbuf = (char *)NULL;

    // Validation Check
    if (iplist == (char *)NULL) { return DECLINED; }
    if (cfg->ctl->listfile->page == (char *)NULL ||
        strlen(cfg->ctl->listfile->page) == 0) { return DECLINED; }

    pbuf = apr_pstrdup(r->pool, cfg->ctl->listfile->page);
    pbuf = str_conv(r, pbuf, CNV_IP, get_ip_address(r));
    pbuf = str_conv(r, pbuf, CNV_PROC, proc);
    pbuf = str_conv(r, pbuf, CNV_URI, r->uri);

    if (strlen(iplist) > 0) {
        pbuf = str_conv(r, pbuf, CNV_LIST, iplist);
    }
    else {
        pbuf = str_conv(r, pbuf, CNV_LIST, "There are no IPs registered as a ip-blacklist.");
    }

    return put_screen(r, pbuf);
}

extern char *str_unescape(request_rec *r, const char *comment) {
    char *pbuf = (char *)NULL;

    pbuf = apr_psprintf(r->pool, "%s", comment);
    pbuf = str_conv(r, pbuf, "%09", "");
    pbuf = str_conv(r, pbuf, "%E3%80%80", "");
    pbuf = str_conv(r, pbuf, "+", "");
    ap_unescape_url(pbuf);

    return pbuf;
}

extern int set_white_address_redis(request_rec *r, redisContext *context, const char *address) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    redisReply *rep = (redisReply *)NULL;
    char *path = (char *)NULL;
    unsigned int cnt = 0;

    // Validation Check
    if (context == (redisContext *)NULL) return 0;
    if (address == (const char *)NULL) return 0;

    // Port decision check
    if (cfg->common->development == FLG_OFF) {
        path = apr_psprintf(r->pool, "%s", s->server_hostname);
    }
    else {
        path = apr_psprintf(r->pool, "%s:%d", s->server_hostname, (int)r->server->port);
    }

    // IP Control Set Passing
    rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
        "SET "MODULE_KEY_NAME":"REDIS_KEY_FREE":%s:%s %s", path, address, "1"));

    if (rep == (redisReply *)NULL) {
        ALERTLOG("failed to set the white address rep[NULL]");
        return -1;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to set the white address rep->type[%d]", rep->type);
        freeReplyObject(rep);
        return -1;
    }
    cnt = (unsigned int)rep->integer;
    freeReplyObject(rep);

    WARNLOG("IP-control: SET "REDIS_KEY_FREE":%s:%s [%s]", path, address, "1");

    return cnt;
}

extern int delete_white_address_redis(request_rec *r, redisContext *context, const char *address) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    redisReply *rep = (redisReply *)NULL;
    char *path = (char *)NULL;
    unsigned int cnt = 0;

    // Validation Check
    if (context == (redisContext *)NULL) return 0;
    if (address == (const char *)NULL) return 0;

    // Port decision check
    if (cfg->common->development == FLG_OFF) {
        path = apr_psprintf(r->pool, "%s", s->server_hostname);
    }
    else {
        path = apr_psprintf(r->pool, "%s:%d", s->server_hostname, (int)r->server->port);
    }

    // IP Control Set Passing
    rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
        "DEL "MODULE_KEY_NAME":"REDIS_KEY_FREE":%s:%s", path, address));

    if (rep == (redisReply *)NULL) {
        ALERTLOG("failed to delete the white address rep[NULL]");
        return -1;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to delete the white address rep->type[%d]", rep->type);
        freeReplyObject(rep);
        return -1;
    }
    cnt = (unsigned int)rep->integer;
    freeReplyObject(rep);

    WARNLOG("IP-control: DEL "REDIS_KEY_FREE":%s:%s", path, address);

    return cnt;
}

extern char* get_list_ip_redis(request_rec *r, redisContext *context, char *ip, char *arg) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    redisReply *rep = (redisReply *)NULL;
    char *path = (char *)NULL;
    char *pbuf = (char *)NULL;
    char *plists = "";
    unsigned long i = 0;

    // Validation Check
    if (context == (redisContext *)NULL) return (char *)NULL;
    if (ip == (char *)NULL) return (char *)NULL;
    if (arg == (char *)NULL) return (char *)NULL;

    // Port decision check
    if (cfg->common->development == FLG_OFF) {
        path = apr_psprintf(r->pool, "%s", s->server_hostname);
    }
    else {
        path = apr_psprintf(r->pool,
            "%s:%d", s->server_hostname, (int)r->server->port);
    }

    // Common-DoS or URL-DoS check
    if (strcmp(arg, IP_WHITE_LIST) == 0) {
        rep = (redisReply*)redisCommand(context, apr_psprintf(r->pool,
            "KEYS "MODULE_KEY_NAME":"REDIS_KEY_FREE":%s:%s*", path, ip));
        WARNLOG("IP-control: KEYS "MODULE_KEY_NAME":"REDIS_KEY_FREE":%s:%s*", path, ip);
    }
    else if (strcmp(arg, IP_BLACK_LIST) == 0) {
        rep = (redisReply*)redisCommand(context, apr_psprintf(r->pool,
            "KEYS "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s*", path, ip));
        WARNLOG("IP-control: KEYS "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s*", path, ip);
    }
    if (rep == (redisReply *)NULL) {
        ALERTLOG("failed to ip_list keys the redis rep[NULL]");
        return (char *)NULL;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to ip_list keys the redis rep->type[%d]", rep->type);
        freeReplyObject(rep);
        return (char *)NULL;
    }

    // OK is returned always
    if (rep->type == REDIS_REPLY_ARRAY) {
        plists = apr_pstrcat(r->pool, "<pre>", NULL);
        for (i = 0; i < (unsigned long)rep->elements; i++) {
            pbuf = apr_pstrdup(r->pool, rep->element[i]->str);
            if (strcmp(arg, IP_WHITE_LIST) == 0) {
                pbuf = str_conv(r, pbuf, apr_psprintf(r->pool,
                    MODULE_KEY_NAME":"REDIS_KEY_FREE":%s:",path), "");
                plists = apr_pstrcat(r->pool, plists, pbuf, NULL);
                plists = apr_pstrcat(r->pool, plists, "\t",
                    "<a href=\"", cfg->ctl->white->del,
                    "?", pbuf, "\" style=\"text-decoration: none\">",
                    "<input type=\"button\" value=\"delete\" />", "</a>", NULL);
            }
            else if (strcmp(arg, IP_BLACK_LIST) == 0) {
                pbuf = str_conv(r, pbuf, apr_psprintf(r->pool,
                    MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:",path), "");
                plists = apr_pstrcat(r->pool, plists, pbuf, NULL);
                plists = apr_pstrcat(r->pool, plists, "\t",
                    "<a href=\"", cfg->ctl->black->del,
                    "?", pbuf, "\" style=\"text-decoration: none\">",
                    "<input type=\"button\" value=\"delete\" />", "</a>", NULL);
            }
            plists = apr_pstrcat(r->pool, plists, "<br/>", NULL);
        }
        plists = apr_pstrcat(r->pool, plists, "</pre>", NULL);
    }
    freeReplyObject(rep);

    return plists;
}

