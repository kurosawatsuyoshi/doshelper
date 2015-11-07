/* 
**  mod_doshelper.c -- Apache doshelper module
**
**  Copyright (C) 2012-2015 Tsuyoshi Kurosawa
**  The author is Tsuyoshi Kurosawa <kurosawa.tsuyoshi@jamhelper.com>.
**
*/ 
#include "mod_doshelper.h"

// Declaration 
module AP_MODULE_DECLARE_DATA doshelper_module;

static char *util_strconv(request_rec *r, char *buf, const char *conv, const char *to) {
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

static const char *get_ip_address(request_rec *r) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    apr_array_header_t *ip_array = (apr_array_header_t *)NULL;
    char *token = (char *)NULL;
    const char *address = (const char *)NULL;
    const char *pbuf;
    const char *ptmp;

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

static apr_status_t put_screen(request_rec *r, char *pbuf) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    char *phtml = (char *)NULL;

    // Validation Check
    if (pbuf == (char *)NULL) { return DECLINED; }

    phtml = apr_pstrdup(r->pool, pbuf);
    phtml = util_strconv(r, phtml, CNV_WHITELIST, cfg->ctl->white->list);
    phtml = util_strconv(r, phtml, CNV_WHITESET, cfg->ctl->white->set);
    phtml = util_strconv(r, phtml, CNV_WHITEDEL, cfg->ctl->white->del);
    phtml = util_strconv(r, phtml, CNV_BLACKLIST, cfg->ctl->black->list);
    phtml = util_strconv(r, phtml, CNV_BLACKSET, cfg->ctl->black->set);
    phtml = util_strconv(r, phtml, CNV_BLACKDEL, cfg->ctl->black->del);

    r->content_type = "text/html";
    if (!r->header_only) {
        ap_rputs(phtml, r);
        return APR_SUCCESS;
    }

    return DECLINED;
}

static apr_status_t put_screen_dos(request_rec *r) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    char *pbuf = (char *)NULL;

    if (cfg->dosfile->page == (char *)NULL || strlen(cfg->dosfile->page) == 0) return DECLINED;

    pbuf = apr_pstrdup(r->pool, cfg->dosfile->page);
    pbuf = util_strconv(r, pbuf, CNV_IP, get_ip_address(r));
    pbuf = util_strconv(r, pbuf, CNV_APACHE_MAJOR,
        (const char *)apr_psprintf(r->pool, "%d", AP_SERVER_MAJORVERSION_NUMBER));
    pbuf = util_strconv(r, pbuf, CNV_APACHE_MINOR,
        (const char *)apr_psprintf(r->pool, "%d", AP_SERVER_MINORVERSION_NUMBER));

    return put_screen(r, pbuf);
}

static apr_status_t put_screen_ip_set(request_rec *r, char *proc) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    char *pbuf = (char *)NULL;

    // Validation Check
    if (proc == (char *)NULL) { return DECLINED; }

    if (cfg->ctl->setfile->page == (char *)NULL ||
        strlen(cfg->ctl->setfile->page) == 0) return DECLINED;

    pbuf = apr_pstrdup(r->pool, cfg->ctl->setfile->page);
    pbuf = util_strconv(r, pbuf, CNV_IP, get_ip_address(r));
    pbuf = util_strconv(r, pbuf, CNV_PROC, proc);
    pbuf = util_strconv(r, pbuf, CNV_URI, r->uri);

    return put_screen(r, pbuf);
}

static apr_status_t put_screen_ip_complete(request_rec *r, char *ip, char *proc) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    char *pbuf = (char *)NULL;

    // Validation Check
    if (ip == (char *)NULL) { return DECLINED; }
    if (proc == (char *)NULL) { return DECLINED; }
    if (cfg->ctl->cplfile->page == (char *)NULL ||
        strlen(cfg->ctl->cplfile->page) == 0) return DECLINED;

    pbuf = apr_pstrdup(r->pool, cfg->ctl->cplfile->page);
    pbuf = util_strconv(r, pbuf, CNV_PROC, proc);
    pbuf = util_strconv(r, pbuf, CNV_IP, ip);

    return put_screen(r, pbuf);
}

static apr_status_t put_screen_ip_list(request_rec *r, char *iplist, char *proc) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    char *pbuf = (char *)NULL;

    // Validation Check
    if (iplist == (char *)NULL) { return DECLINED; }
    if (cfg->ctl->listfile->page == (char *)NULL ||
        strlen(cfg->ctl->listfile->page) == 0) { return DECLINED; }

    pbuf = apr_pstrdup(r->pool, cfg->ctl->listfile->page);
    pbuf = util_strconv(r, pbuf, CNV_IP, get_ip_address(r));
    pbuf = util_strconv(r, pbuf, CNV_PROC, proc);
    pbuf = util_strconv(r, pbuf, CNV_URI, r->uri);

    if (strlen(iplist) > 0) { 
        pbuf = util_strconv(r, pbuf, CNV_LIST, iplist);
    }
    else {
        pbuf = util_strconv(r, pbuf, CNV_LIST, "There are no IPs registered as a ip-blacklist.");
    }

    return put_screen(r, pbuf);
}

static apr_status_t check_regular_expression(request_rec *r, char *haystack, char *needle) {
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

static apr_status_t check_ignore_content_type(request_rec *r, const char *buf) {
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

static apr_status_t check_content_type(request_rec *r) {
    const char *content_type;
    //const char *accept;

    // will check the content-type or accept (HTTP_ACCEPT)
    content_type = (char *)ap_sub_req_lookup_uri(r->uri, r, NULL)->content_type;
    if (!content_type) {
        content_type = apr_pstrdup(r->pool, "");
    }
    if (check_ignore_content_type(r, content_type) == DECLINED) { return DECLINED; }

    return APR_SUCCESS;
}

static apr_status_t decline_check(request_rec *r) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    // DECLINED Section
    if (r->header_only) return DECLINED;
    if (cfg->common->action == FLG_OFF) return DECLINED;
    if (!ap_is_initial_req(r)) return DECLINED;
    if (apr_table_get(r->subprocess_env, DOSHELPER_IGNORE)) return DECLINED;
    if (check_content_type(r) == DECLINED) return DECLINED;

    return APR_SUCCESS;
}

static char *extract_string(char *str, char *key, char *delimit) {
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

static apr_status_t set_environment_variable
    (request_rec *r, status_s *st, char* uuid, unsigned long counter) {
    server_rec *s = (server_rec *)r->server;

    switch(st->status) {
      case __DOS:
        apr_table_setn(r->subprocess_env, "DH_DOS", ENV_DOS);
        apr_table_setn(r->subprocess_env, "DH_CNT", apr_psprintf(r->pool, "%lu", counter));
        INFOLOG("setenv[DH_DOS=%s, DH_CNT=%lu]", ENV_DOS, counter);
        break;

      case __NORMAL:
        break;
    }

    return APR_SUCCESS;
}

static apr_status_t check_redis_version(server_rec *s, redisContext *context) {
    apr_pool_t *p = s->process->pool;
    redisReply *rep = (redisReply *)NULL;
    char *pbuf = (char *)NULL;

    // Validation Check
    if (context == (redisContext *)NULL) return DECLINED;

    // version check (Only Master Connect)
    rep = (redisReply*)redisCommand(context, REDIS_CMD_INFO_SERVER);
    if (rep == (redisReply *)NULL) {
        // Redis Time Out or Server Down
        ALERTLOG("failed to check the Redis Version rep[NULL]");
        return DECLINED;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to check the Redis Version rep->type[%d]", rep->type);
        freeReplyObject(rep);
        return DECLINED;
    }
    if (rep->str != (char *)NULL && strstr(rep->str, REDIS_CMD_STR_DELIMIT)){
        pbuf = apr_pstrdup(p,
            extract_string(rep->str, REDIS_CMD_INFO_SVR_VERSION, REDIS_CMD_STR_DELIMIT));
    }
    freeReplyObject(rep);

    if (pbuf == (char *)NULL || atof(pbuf) < atof(REDIS_VERSION_LATER)) {
        EMERGLOG("version of redis will work with %s or latere [%s]", REDIS_VERSION_LATER, pbuf);
        return DECLINED;
    }

    return APR_SUCCESS;
}

static apr_status_t check_redis_master(server_rec *s, redisContext *context) {
    apr_pool_t *p = s->process->pool;
    redisReply *rep = (redisReply *)NULL;
    char *pbuf = (char *)NULL;

    // Validation Check
    if (context == (redisContext *)NULL) return DECLINED;

    // master check (Only Master Connect)
    rep = (redisReply*)redisCommand(context, REDIS_CMD_INFO_REPICATION);
    if (rep == (redisReply *)NULL) {
        // Redis Time Out or Server Down
        INFOLOG("failed to check the RedisMaster rep[NULL]");
        return DECLINED;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to check the RedisMaster rep->type[%d]", rep->type);
        freeReplyObject(rep);
        return DECLINED;
    }
    if (rep->str != (char *)NULL && strstr(rep->str, REDIS_CMD_STR_DELIMIT)){
        pbuf = apr_pstrdup(p,
            extract_string(rep->str, REDIS_CMD_INFO_REP_ROLE, REDIS_CMD_STR_DELIMIT));
        DEBUGLOG("redis master/slave check [%s]", pbuf);
    }
    freeReplyObject(rep);

    if (pbuf == (char *)NULL || ap_strcasecmp_match(pbuf, REDIS_DEFAULT_MASTER) != 0) {
        return DECLINED;
    }

    return APR_SUCCESS;
}

static redisContext *connect_redis_master(server_rec *s, char *redisip_port) {
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    apr_pool_t *p = s->process->pool;
    char *redis_ip = (char *)NULL, *redis_port = (char *)NULL;
    redisContext *context = (redisContext *)NULL;
    redisReply *rep = (redisReply *)NULL;

    // Redis Timeout Set 
    struct timeval timeout = { cfg->redis->timeout_sec, cfg->redis->timeout_msec };

    // Get RedisIP
    redis_ip = apr_pstrdup(p, redisip_port);

    // Get RedisPort
    if ((redis_port = strchr(redis_ip, ':')) != (char *)NULL) {
        *redis_port++ = '\0';
    }
    else {
        redis_port = apr_pstrdup(p, REDIS_DEFAULT_PORT);
    }

    // Connect Redis
    context = redisConnectWithTimeout(redis_ip, strtol(redis_port, (char **)NULL, 10), timeout);
    if (context == (redisContext *)NULL) {
        EMERGLOG("failed to connect the redis master [NULL][%s:%s]", redis_ip, redis_port);
        return (redisContext *)NULL;
    }
    if (context->err) {
        DEBUGLOG("failed to %s [%s:%s]", context->errstr, redis_ip, redis_port);
        goto exit_function;
    }

    // Auth Check
    if (cfg->redis->requirepass) {
        rep = (redisReply*)redisCommand(context, apr_psprintf(p,
            "AUTH %s", cfg->redis->requirepass));
        if (rep == (redisReply *)NULL) {
            EMERGLOG("failed to authenticate the redis master [NULL][%s:%s]", redis_ip, redis_port);
            goto exit_function;
        }
        if (rep->type == REDIS_REPLY_ERROR) {
            EMERGLOG("failed to authenticate the redis master [%d][%s:%s]",
                rep->type, redis_ip, redis_port);
            freeReplyObject(rep);
            goto exit_function;
        }
    }

    // Version check (Redis Version Check)
    if (check_redis_version(s, context) != APR_SUCCESS) { goto exit_function; }

    // master check (Only Master Connect)
    if (check_redis_master(s, context) == APR_SUCCESS) {
        rep = (redisReply*)redisCommand(context, "select %d", cfg->redis->database);
        if (rep == (redisReply *)NULL) {
            EMERGLOG("failed to select the database [NULL][%s:%s]", redis_ip, redis_port);
            goto exit_function;
        }
        if (rep->type == REDIS_REPLY_ERROR) {
            EMERGLOG("failed to select the database [%d][%s:%s]", rep->type, redis_ip, redis_port);
            freeReplyObject(rep);
            goto exit_function;
        }
        freeReplyObject(rep);
        return (redisContext *)context;
    }

exit_function:
    redisFree(context);
    return (redisContext *)NULL;
}

static redisContext *connect_redis_server(server_rec *s) {
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    redisContext *context = (redisContext *)NULL;
    char **lists = (char **)NULL;
    int i = 0;

    // Redis Server List
    lists = (char **)cfg->redis->server->elts;

    // Connect to Redis
    i = cfg->redis->history;
    if (cfg->redis->server->nelts > 1) {
        if ((context = connect_redis_master(s, lists[i])) != (redisContext *)NULL) {
            return (redisContext *)context;
        }
    }

    // ReConnect to New Redis Server
    for (i = 0; i < cfg->redis->server->nelts; i++) {
        if ((context = connect_redis_master(s, lists[i])) != (redisContext *)NULL) {
            cfg->redis->history = i;
            return (redisContext *)context;
        }
    }

    return (redisContext *)NULL;
}

static redisContext *connect_redis(server_rec *s) {
    redisContext *context = (redisContext *)NULL;

    // Redis Connection
    if ((context = connect_redis_server(s)) == (redisContext *)NULL) {
        ALERTLOG("faild to redis master not connected..");
        return (redisContext *)NULL;
    }
    if (context->err != REDIS_OK) {
        ALERTLOG("faild to %s err[%d]", context->errstr, context->err);
        redisFree(context);
        return (redisContext *)NULL;
    }

    return (redisContext *)context;
}

static int get_free_address_redis(request_rec *r, redisContext *context, const char *address) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    redisReply *rep = (redisReply *)NULL;
    unsigned int cnt = 0;
    char *path = (char *)NULL;

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

    // Get the Free Access
    rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
        "GET "MODULE_KEY_NAME":"REDIS_KEY_FREE":%s:%s", path, address));

    if (rep == (redisReply *)NULL) {
        ALERTLOG("failed to get the free address rep[NULL]");
        return 0;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to get the free address rep->type[%d]", rep->type);
        freeReplyObject(rep);
        return 0;
    }
    if (rep->str != (char *)NULL) {
        cnt = strtol(rep->str, (char **)NULL, 10);
    }
    freeReplyObject(rep);
    INFOLOG("GET "MODULE_KEY_NAME":"REDIS_KEY_FREE":%s:%s count[%d]", path, address, cnt);

    return cnt;
}

static apr_status_t set_free_address_redis
    (request_rec *r, redisContext *context, const char *address, const int sec) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    redisReply *rep = (redisReply *)NULL;
    char *path = (char *)NULL;

    // Validation Check
    if (context == (redisContext *)NULL) return DECLINED;
    if (address == (const char *)NULL) return DECLINED;
    if (sec < 1) return APR_SUCCESS;

    // Port decision check
    if (cfg->common->development == FLG_OFF) {
        path = apr_psprintf(r->pool, "%s", s->server_hostname);
    }
    else {
        path = apr_psprintf(r->pool, "%s:%d", s->server_hostname, (int)r->server->port);
    }

    // Set the Free Access
    rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
        "SETEX "MODULE_KEY_NAME":"REDIS_KEY_FREE":%s:%s %d %s", path, address, sec, "1"));

    if (rep == (redisReply *)NULL) {
        ALERTLOG("failed to SETEX the free address rep[NULL]");
        return DECLINED;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to SETEX the free address %s. rep->type[%d]", rep->str, rep->type);
        freeReplyObject(rep);
        return DECLINED;
    }
    freeReplyObject(rep);

    INFOLOG("SETEX "MODULE_KEY_NAME":"REDIS_KEY_FREE":%s:%s %d %s", path, address, sec, "1");

    return APR_SUCCESS;
}

static char *str_unescape(request_rec *r, const char *comment) {
    char *pbuf = (char *)NULL;

    pbuf = apr_psprintf(r->pool, "%s", comment);
    pbuf = util_strconv(r, pbuf, "%09", "");
    pbuf = util_strconv(r, pbuf, "%E3%80%80", "");
    pbuf = util_strconv(r, pbuf, "+", "");
    ap_unescape_url(pbuf);

    return pbuf;
}

static int set_white_address_redis(request_rec *r, redisContext *context, const char *address) {
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

static int delete_white_address_redis(request_rec *r, redisContext *context, const char *address) {
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

static int set_dos_address_redis
    (request_rec *r, redisContext *context, const char *address, detailsdos_s *details, unsigned int block) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    redisReply *rep = (redisReply *)NULL;
    char *path = (char *)NULL;
    unsigned int cnt = 0;
    int dostime = 0;

    // Validation Check
    if (context == (redisContext *)NULL) return 0;
    if (address == (const char *)NULL) return 0;

    // Port decision check
    if (cfg->common->development == FLG_OFF) {
        path = apr_psprintf(r->pool, "%s", s->server_hostname);
    }
    else {
        path = apr_psprintf(r->pool,
            "%s:%d", s->server_hostname, (int)r->server->port);
    }

    // Common-DoS or URL-DoS check
    if (details == (detailsdos_s *)NULL) {
        dostime = cfg->common_dos->time;
    }
    else {
        dostime = details->time;
        path = apr_psprintf(r->pool, "%s:%s", path, details->path);
    }

    // IP Control Bloking
    if (block) {
        rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
            "SET "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s %d",
                path, address, cfg->common_dos->request + 1));

        if (rep == (redisReply *)NULL) {
            ALERTLOG("failed to set or incr the address rep[NULL]");
            return -1;
        }
        if (rep->type == REDIS_REPLY_ERROR) {
            ALERTLOG("failed to set or incr the address rep->type[%d]", rep->type);
            freeReplyObject(rep);
            return -1;
        }
        cnt = (unsigned int)rep->integer;
        freeReplyObject(rep);

        WARNLOG("IP-control: SET "REDIS_KEY_DOS":%s:%s count[%d]",
            path, address, cfg->common_dos->request+1);
        return cnt;
    }

    // Access Control Checking
    rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
            "EXISTS "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s", path, address));

    if (rep == (redisReply *)NULL) {
        ALERTLOG("failed to check the redis exist rep[NULL]");
        return -1;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to check the redis exist rep->type[%d]", rep->type);
        freeReplyObject(rep);
        return -1;
    }
    cnt = (unsigned int)rep->integer;
    freeReplyObject(rep);

    DEBUGLOG("EXISTS "REDIS_KEY_DOS":%s:%s count[%d]", path, address, cnt);

    if (cnt == 0) {
        rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
            "SETEX "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s %d %s", path, address, dostime, "1"));
        if (rep != (redisReply *)NULL && rep->type != REDIS_REPLY_ERROR) {
            INFOLOG("SETEX "REDIS_KEY_DOS":%s:%s sec[%d] count[%s]", path, address, dostime, "1");
        }
    }
    else {
        rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
            "INCR "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s", path, address));
        if (rep != (redisReply *)NULL && rep->type != REDIS_REPLY_ERROR) {
            INFOLOG("INCR "REDIS_KEY_DOS":%s:%s count[%d]", path, address, (unsigned int)rep->integer);
        }
    }
    if (rep == (redisReply *)NULL) {
        ALERTLOG("failed to set or incr the address rep[NULL]");
        return -1;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to set or incr the address rep->type[%d]", rep->type);
        freeReplyObject(rep);
        return -1;
    }
    cnt = (unsigned int)rep->integer;
    freeReplyObject(rep);

    return cnt;
}

static int delete_dos_address_redis
    (request_rec *r, redisContext *context, const char *address, detailsdos_s *details) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    redisReply *rep = (redisReply *)NULL;
    unsigned int cnt = 0;
    char *path = (char *)NULL;

    // Validation Check
    if (context == (redisContext *)NULL) return 0;
    if (address == (const char *)NULL) return 0;

    // Port decision check
    if (cfg->common->development == FLG_OFF) {
        path = apr_psprintf(r->pool, "%s", s->server_hostname);
    }
    else {
        path = apr_psprintf(r->pool,
            "%s:%d", s->server_hostname, (int)r->server->port);
    }
    if (details != (detailsdos_s *)NULL) {
        path = apr_psprintf(r->pool, "%s:%s", path, details->path);
    }

    // Common-DoS or URL-DoS check
    rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
            "DEL "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s", path, address));

    WARNLOG("IP-control: DEL "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s", path, address);

    if (rep == (redisReply *)NULL) {
        ALERTLOG("failed to delete the redis rep[NULL]");
        return -1;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to delete the redis rep->type[%d]", rep->type);
        freeReplyObject(rep);
        return -1;
    }
    cnt = (unsigned int)rep->integer;
    freeReplyObject(rep);

    return cnt;
}

static char* get_list_ip_redis(request_rec *r, redisContext *context, char *ip, char *arg) {
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
                pbuf = util_strconv(r, pbuf, apr_psprintf(r->pool,
                    MODULE_KEY_NAME":"REDIS_KEY_FREE":%s:",path), "");
                plists = apr_pstrcat(r->pool, plists, pbuf, NULL);
                plists = apr_pstrcat(r->pool, plists, "\t",
                    "<a href=\"", cfg->ctl->white->del,
                    "?", pbuf, "\" style=\"text-decoration: none\">",
                    "<input type=\"button\" value=\"delete\" />", "</a>", NULL);
            }
            else if (strcmp(arg, IP_BLACK_LIST) == 0) {
                pbuf = util_strconv(r, pbuf, apr_psprintf(r->pool,
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

static apr_status_t set_wait_dos_redis
    (request_rec *r, redisContext *context, const char *address, detailsdos_s *details) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    redisReply *rep = (redisReply *)NULL;
    char *path = (char *)NULL;
    long ttl = 0;
    int dostime = 0;

    // Validation Check
    if (context == (redisContext *)NULL) return DECLINED;
    if (address == (const char *)NULL) return DECLINED;

    if (cfg->common->development == FLG_OFF) {
        path = apr_psprintf(r->pool, "%s", s->server_hostname);
    }
    else {
        path = apr_psprintf(r->pool, "%s:%d", s->server_hostname, (int)r->server->port);
    }

    // Common-DoS or URL-DoS check
    if (details == (detailsdos_s *)NULL) {
        dostime = cfg->common_dos->wait;
    }
    else {
        dostime = details->wait;
        path = apr_psprintf(r->pool, "%s:%s", path, details->path);
    }

    // IP Control Bloking
    rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
        "TTL "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s", path, address));

    if (rep == (redisReply *)NULL) {
        ALERTLOG("failed to get the TTL rep[NULL]");
        return DECLINED;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to get the TTL rep->type[%d]", rep->type);
        freeReplyObject(rep);
        return DECLINED;
    }
    ttl = (long)rep->integer;
    freeReplyObject(rep);

    INFOLOG("TTL "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s [%ld]", path, address, ttl);
    if (ttl < 0) return APR_SUCCESS;

    rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
        "EXPIRE "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s %d", path, address, dostime));

    INFOLOG("EXPIRE "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s %d", path, address, dostime);

    if (rep == (redisReply *)NULL) {
        ALERTLOG("failed to set the expire rep[NULL]");
        return DECLINED;
    }
    if (rep->type == REDIS_REPLY_ERROR) {
        ALERTLOG("failed to set the expire rep->type[%d]", rep->type);
        freeReplyObject(rep);
        return DECLINED;
    }
    freeReplyObject(rep);

    return APR_SUCCESS;
}

static detailsdos_s *get_detail_dos_list(request_rec *r) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    detailsdos_s *val = (detailsdos_s *)NULL;
    char *url = (char *)NULL;
    int i = 0;

    if (r->args == (char *)NULL) { url = r->uri; }
    else { url = apr_psprintf(r->pool, "%s?%s", r->uri, r->args); }

    // Config Detail ID Getting
    for (i = 0; i < cfg->detailsdos_s->nelts; i++) {
        val = (detailsdos_s *)(cfg->detailsdos_s->elts + (cfg->detailsdos_s->elt_size * i));

        // URL(Path) Check
        if (check_regular_expression(r, val->path, url) == APR_SUCCESS) {
            return val;
        }
    }

    return (detailsdos_s *)NULL;
}

static apr_status_t check_free_address_handler
    (request_rec *r, redisContext *context, const char *address, status_s *st) {

    // get of the Free Access IP
    if (get_free_address_redis(r, context, address) > 0) {
        // Set Status
        st->status = __NORMAL;
        st->visit  = __VISIT;
        return APR_SUCCESS;
    }

    return DECLINED;
}

static apr_status_t check_common_dos_handler
    (request_rec *r, redisContext *context, const char *address, status_s *st) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    unsigned int cnt = 0;

    // Validation Check
    if (context == (redisContext *)NULL) { return DECLINED; };
    if (address == (const char *)NULL) { return DECLINED; };

    // judgment of the dos attack
    cnt = set_dos_address_redis(r, context, address, (detailsdos_s *)NULL, 0);
    if (cnt > cfg->common_dos->request) {
        if (set_wait_dos_redis(r, context, address, (detailsdos_s *)NULL) == APR_SUCCESS) {
            // Set Status
            st->visit  = __ERROR;
            st->status = __DOS;
            // Set Environment
            set_environment_variable(r, st, (char *)NULL, (unsigned long)cnt); 
            return DECLINED;
        }
    }

    return APR_SUCCESS;
}

static apr_status_t check_dos_handler
    (request_rec *r, redisContext *context, const char *address, status_s *st) {
    detailsdos_s *details = (detailsdos_s *)NULL;
    unsigned int cnt = 0;

    // Validation Check
    if (context == (redisContext *)NULL) { return DECLINED; };
    if (address == (const char *)NULL) { return DECLINED; };

    details = get_detail_dos_list(r);
    if (details == (detailsdos_s *)NULL) { return APR_SUCCESS; };

    // set of the DoS attack
    cnt = set_dos_address_redis(r, context, address, details, 0);
    if (cnt > details->request) {
        if (set_wait_dos_redis(r, context, address, details) == APR_SUCCESS) {
            // Set Status
            st->visit  = __ERROR;
            st->status = __DOS;
            // Set Environment
            set_environment_variable(r, st, (char *)NULL, (unsigned long)cnt); 
            return DECLINED;
        }
    }

    return APR_SUCCESS;
}

static apr_status_t doshelper_handler(request_rec *r) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    redisContext *context = (redisContext *)NULL;
    const char *address = (const char *)NULL;
    status_s *st = (status_s *)NULL;
    apr_status_t status = DECLINED;

    // DECLINED Check
    if (decline_check(r) == DECLINED) return DECLINED;

    // status
    st = (status_s *)apr_pcalloc(r->pool, sizeof(status_s));
    st->status = __NORMAL;
    st->visit  = __ERROR;

    // Enter the critical section 
    if (cfg->mutex->action && cfg->mutex->mutex != (apr_global_mutex_t *)NULL) {
        apr_global_mutex_lock(cfg->mutex->mutex);
        INFOLOG("--start-- apache%d.%d",
            AP_SERVER_MAJORVERSION_NUMBER, AP_SERVER_MINORVERSION_NUMBER);
        INFOLOG("mutex[lock][%ld]", (long)cfg->mutex->mutex);
    }
    else {
        INFOLOG("--start-- apache%d.%d",
            AP_SERVER_MAJORVERSION_NUMBER, AP_SERVER_MINORVERSION_NUMBER);
    }

    // get IP address
    address = get_ip_address(r);
    if (address == (const char*)NULL) { goto exit_handler; }

    // Set Environment (Terget URI)
    apr_table_setn(r->subprocess_env, "DH_TGT", ENV_TGT);
    apr_table_setn(r->subprocess_env, "DH_CTT",
        ap_sub_req_lookup_uri(r->uri, r, NULL)->content_type);

    DEBUGLOG("setenv[DH_TGT=%s] uri=[%s] content-type[DH_CTT=%s]",
        ENV_TGT, r->uri, ap_sub_req_lookup_uri(r->uri, r, NULL)->content_type);

    // Redis Connect
    if (cfg->redis->context == (redisContext *)NULL || check_redis_master(s, cfg->redis->context) != APR_SUCCESS) {
        if (cfg->redis->context != (redisContext *)NULL) { redisFree(cfg->redis->context); }
        if ((cfg->redis->context = connect_redis(s)) == (redisContext *)NULL) { goto exit_handler; }
    }
    context = cfg->redis->context;

    // Free IP Check (White IP)
    status = check_free_address_handler(r, context, address, st);
    if (status == APR_SUCCESS) { goto exit_handler; }

    // DoS Check (DoS or Black IP)
    status = check_dos_handler(r, context, address, st);
    if (status == DECLINED || st->status != __NORMAL) { goto exit_handler; }

    // Common DoS Check
    if ( cfg->common_dos->action == FLG_ON) {
        status = check_common_dos_handler(r, context, address, st);
        if (status == DECLINED || st->status != __NORMAL) { goto exit_handler; }
    }

exit_handler:
    // End the critical section
    if (cfg->mutex->action && cfg->mutex->mutex != (apr_global_mutex_t *)NULL) {
        INFOLOG("mutex[unlk][%ld]", (long)cfg->mutex->mutex);
        apr_global_mutex_unlock(cfg->mutex->mutex);
    }
    INFOLOG("--exit-- apache%d.%d",
        AP_SERVER_MAJORVERSION_NUMBER, AP_SERVER_MINORVERSION_NUMBER);
 
    if (st->status == __NORMAL || strlen(cfg->dosfile->page) > 0 ) {
        return DECLINED;
    }

    return cfg->common->http_service_return;
}

static apr_status_t control_proc(request_rec *r, char *arg) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    redisContext *context = (redisContext *)NULL;
    const char *address = (const char *)NULL;
    char *plist =(char *)NULL;
    char *pbuf = (char *)NULL;

    // Redis Connect
    if (cfg->redis->context == (redisContext *)NULL ||
        check_redis_master(s, cfg->redis->context) != APR_SUCCESS) {
        if (cfg->redis->context != (redisContext *)NULL) {
            redisFree(cfg->redis->context);
        }
        if ((cfg->redis->context = connect_redis(s)) == (redisContext *)NULL) {
            goto exit_handler;
        }
    }
    context = cfg->redis->context;

    if (r->args != (char *)NULL && strlen(r->args) > 0) {
        pbuf = apr_pstrdup(r->pool, str_unescape(r, r->args));
        pbuf = util_strconv(r, pbuf, "value=", "");

        if (strcmp(arg, IP_WHITE_LIST) == 0) {
            plist = get_list_ip_redis(r, context, pbuf, IP_WHITE_LIST);
            if (plist != (char *)NULL && strlen(plist) >= 0) {
                if (put_screen_ip_list(r, plist, arg) == APR_SUCCESS) { goto exit_handler; }
            }
        }
        if (strcmp(arg, IP_WHITE_SET) == 0) {
            if (set_white_address_redis(r, context, pbuf) >= 0) {
              if (put_screen_ip_complete(r, pbuf, arg) == APR_SUCCESS) { goto exit_handler; }
            }
        }
        if (strcmp(arg, IP_WHITE_DEL) == 0) {
            if (delete_white_address_redis(r, context, pbuf) >= 0) {
                if (put_screen_ip_complete(r, pbuf, arg) == APR_SUCCESS) { goto exit_handler; }
            }
        }
        if (strcmp(arg, IP_BLACK_LIST) == 0) {
            plist = get_list_ip_redis(r, context, pbuf, IP_BLACK_LIST);
            if (plist != (char *)NULL && strlen(plist) >= 0) {
                if (put_screen_ip_list(r, plist, arg) == APR_SUCCESS) { goto exit_handler; }
            }
        }
        if (strcmp(arg, IP_BLACK_SET) == 0) {
            if (set_dos_address_redis(r, context, pbuf, (detailsdos_s *)NULL, 1) >= 0) {
                if (put_screen_ip_complete(r, pbuf, arg) == APR_SUCCESS) { goto exit_handler; }
            }
        }
        if (strcmp(arg, IP_BLACK_DEL) == 0) {
            if (delete_dos_address_redis(r, context, pbuf, (detailsdos_s *)NULL) >= 0) {
                if (put_screen_ip_complete(r, pbuf, arg) == APR_SUCCESS) { goto exit_handler; }
            }
        }
    }
    else {
        if (strcmp(arg, IP_WHITE_LIST) == 0) {
            plist = get_list_ip_redis(r, context, "", IP_WHITE_LIST);
            if(plist != (char *)NULL && strlen(plist) >= 0) {
                if (put_screen_ip_list(r, plist, arg) == APR_SUCCESS) { goto exit_handler; }
            }
        }
        else if (strcmp(arg, IP_BLACK_LIST) == 0) {
            plist = get_list_ip_redis(r, context, "", IP_BLACK_LIST);
            if (plist != (char *)NULL && strlen(plist) >= 0) {
                if (put_screen_ip_list(r, plist, arg) == APR_SUCCESS) { goto exit_handler; }
            }
        }
        else {
//TODO
            if (put_screen_ip_set(r, arg) == APR_SUCCESS) { goto exit_handler; }
        }
    }

    return DECLINED;

exit_handler:
    // Free Address Set
    address = get_ip_address(r);
    if (address == (const char*)NULL) { return DECLINED; }

    return set_free_address_redis(r, context, address, cfg->ctl->freetime);
}

static apr_status_t control_handler(request_rec *r, int lookup_uri) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    if (cfg->ctl->action == FLG_OFF) return DECLINED;

    // List the White IP
    if (ap_strcasecmp_match(cfg->ctl->white->list, r->uri) == APR_SUCCESS) {
        if (strlen(cfg->ctl->listfile->page) == 0) return DECLINED;
        if (control_proc(r, IP_WHITE_LIST) == APR_SUCCESS) { return OK; }
        return DECLINED;
    }
    // Set the White IP
    if (ap_strcasecmp_match(cfg->ctl->white->set, r->uri) == APR_SUCCESS) {
        if (strlen(cfg->ctl->setfile->page) == 0) return DECLINED;
        if (control_proc(r, IP_WHITE_SET) == APR_SUCCESS) { return OK; }
        return DECLINED;
    }
    // Delete the White IP
    if (ap_strcasecmp_match(cfg->ctl->white->del, r->uri) == APR_SUCCESS) {
        if (strlen(cfg->ctl->setfile->page) == 0) return DECLINED;
        if (control_proc(r, IP_WHITE_DEL) == APR_SUCCESS) { return OK; }
        return DECLINED;
    }

    // List the Black IP
    if (ap_strcasecmp_match(cfg->ctl->black->list, r->uri) == APR_SUCCESS) {
        if (strlen(cfg->ctl->listfile->page) == 0) return DECLINED;
        if (control_proc(r, IP_BLACK_LIST) == APR_SUCCESS) { return OK; }
        return DECLINED;
    }
    // Set the Black IP
    if (ap_strcasecmp_match(cfg->ctl->black->set, r->uri) == APR_SUCCESS) {
        if (strlen(cfg->ctl->setfile->page) == 0) return DECLINED;
        if (control_proc(r, IP_BLACK_SET) == APR_SUCCESS) { return OK; }
        return DECLINED;
    }
    // Delete the Black IP
    if (ap_strcasecmp_match(cfg->ctl->black->del, r->uri) == APR_SUCCESS) {
        if (strlen(cfg->ctl->setfile->page) == 0) return DECLINED;
        if (control_proc(r, IP_BLACK_DEL) == APR_SUCCESS) { return OK; }
        return DECLINED;
    }

    return DECLINED;
}

static apr_status_t template_handler(request_rec *r) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    const char *pbuf = (const char *)NULL;

    // DECLINED Check
    if (decline_check(r) == DECLINED) return DECLINED;

    // HTML Template Mode - BlockPage
    if (strlen(cfg->dosfile->page) > 0) {
        pbuf = (const char *)apr_table_get(r->subprocess_env, "DH_DOS");
        if (pbuf != (const char *)NULL && strlen(pbuf) > 0) {
            if (put_screen_dos(r) == APR_SUCCESS) return OK;
        }
    }

    return DECLINED;
}

static apr_status_t mutex_create(apr_pool_t *p, server_rec *s) {
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    apr_status_t status = APR_SUCCESS;

    status = apr_global_mutex_create(&(cfg->mutex->mutex), NULL, APR_LOCK_DEFAULT, p);
    if(status != APR_SUCCESS){
        EMERGLOG("failed to create the mutex [%d][%s:%d]", status, s->server_hostname, s->port);
        return status;
    }

#ifdef AP_NEED_SET_MUTEX_PERMS
#if (AP_SERVER_MAJORVERSION_NUMBER >= 2) && (AP_SERVER_MINORVERSION_NUMBER > 3)
    status = ap_unixd_set_global_mutex_perms(cfg->mutex->mutex);
#else
    status = unixd_set_global_mutex_perms(cfg->mutex->mutex);
#endif
    if(status != APR_SUCCESS){
        EMERGLOG("failed to initialize the mutex [%d][%s:%d]", status, s->server_hostname, s->port);
        return status;
    }
#endif

    WARNLOG("mutex[%ld] [%s:%d]", (long)cfg->mutex->mutex, s->server_hostname, s->port);

    return APR_SUCCESS;
}

static void initialize_child(apr_pool_t *p, server_rec *s) {
    config_s *cfg = (config_s *)NULL;

    do {
        cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

        /* prevent other processes from accessing the segment */
        if (cfg && cfg->mutex->action) {
            if (apr_global_mutex_child_init(&(cfg->mutex->mutex), NULL, p)) {
                EMERGLOG("failed to attach Mutex");
            }
        }
    } while((s = s->next) != NULL);

    return;
}

static char* initialize_read_templatefile
    (server_rec *s, apr_pool_t *p, char *filepath, char *comment) {
    apr_status_t status = APR_SUCCESS;
    apr_file_t *fp = (apr_file_t*)NULL;
    struct stat buf;
    apr_size_t read;
    char *page =NULL;

    // Template Page Reading
    // APR 1.3 Over
    //   apr_file_open(&fp, filepath, APR_FOPEN_READ, APR_FPROT_UREAD|APR_FPROT_UWRITE, p);
    // APR 1.2 Under(1.3 or more in also OK)
    if (filepath != (char *)NULL && strlen(filepath) > 0) {
        status = apr_file_open(&fp, filepath, APR_READ, APR_UREAD|APR_UWRITE, p);
        if (fp == (apr_file_t *)NULL || status != APR_SUCCESS) {
            EMERGLOG("%s is specified path is incorrect[%s]", comment, filepath);
            return (char *)NULL;
        }
        else {
            status = stat(filepath, &buf);
            if (status != APR_SUCCESS) {
                EMERGLOG("%s is specified path is incorrect[%d]", comment, status);
                return (char *)NULL;
            }

            page = apr_pcalloc(p, (apr_size_t)buf.st_size+1);
            status = apr_file_read_full(fp, page, (apr_size_t)buf.st_size, &read);
            if (status != APR_SUCCESS) {
                EMERGLOG("failed to %s Reading [%d]", comment, status);
                return (char *)NULL;
            }
            return page;
        }
    }

    return (char *)NULL;
}

static apr_status_t initialize_set_templatefile
    (server_rec *s, apr_pool_t *p, initfile_s *file, char *comment) {

    if (strlen(file->filepath) > 0) {
        file->page = initialize_read_templatefile(s, p, file->filepath, comment);
        if (file->page == (char *)NULL) {
            file->page = apr_pstrdup(p, "");
            return DECLINED;
        }
    }

    return APR_SUCCESS;
}

static apr_status_t initialize_module
    (apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
    config_s *cfg = (config_s *)NULL;
    apr_status_t status = APR_SUCCESS;
    void *user_data;

    // Only the first time
    apr_pool_userdata_get(&user_data, USER_DATA_KEY, s->process->pool);
    if (user_data == (void *)NULL) {
        apr_pool_userdata_set((const void *)(1),
            USER_DATA_KEY, apr_pool_cleanup_null, s->process->pool);
        return APR_SUCCESS;
    }
    DEBUGLOG("server[%s], port[%d]", s->server_hostname, s->port);

    do {
        // Get Server Config
        cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

        // Global Mutex Create...
        if (cfg && cfg->mutex->action) {
            if (mutex_create(p, s) != APR_SUCCESS) { return HTTP_INTERNAL_SERVER_ERROR; }
        }

        // DoS TamplatePage Reading
        status = initialize_set_templatefile(s, p, cfg->dosfile, "Dosfilepath");

        // IP Set-Form TamplatePage Reading
        status = initialize_set_templatefile(s, p, cfg->ctl->setfile, "IpSetFormFilePath");

        // IP Complete-Form TamplatePage Reading
        status = initialize_set_templatefile(s, p, cfg->ctl->cplfile, "IpCompleteFilePath");

        // IP List-Form TamplatePage Reading
        status = initialize_set_templatefile(s, p, cfg->ctl->listfile, "IpListFilePath");

    } while((s = s->next) != NULL);

    return OK;
}

static const char* set_action_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    if (ap_strcasecmp_match("on", arg) == 0) {
        cfg->common->action = FLG_ON;
    }
    else {
        cfg->common->action = FLG_OFF;
    }

    DEBUGLOG("%s:%d=[action]=[%s]", parms->server->server_hostname, parms->server->port, arg);

    return (const char *)NULL;
}

static const char* set_mutex_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    if (ap_strcasecmp_match("on", arg) == 0) { cfg->mutex->action = FLG_ON; }
    else { cfg->mutex->action = FLG_OFF; }

    DEBUGLOG("%s:%d=[mutex]=[%s]", parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_development_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    if (ap_strcasecmp_match("on", arg) == 0) { cfg->common->development = FLG_ON; }
    else { cfg->common->development = FLG_OFF; }

    DEBUGLOG("%s:%d=[development]=[%s]", parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_redis_server_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    *((const char **)apr_array_push(cfg->redis->server)) = apr_pstrdup(parms->pool, arg);

    DEBUGLOG("%s:%d=[redis->server]=[%s]", parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_redis_requirepass_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    cfg->redis->requirepass = apr_pstrdup(parms->pool, (char*)arg);

    DEBUGLOG("%s:%d=[redis->requirepass]=[****]",
        parms->server->server_hostname, parms->server->port);
    return (const char *)NULL;
}

static const char* set_redis_timeout_config
    (cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    unsigned long lval;

    lval = strtol(arg1, (char **)NULL, 10);
    if ((lval > UINT_MAX) || (lval < 0)) {
        return "Integer invalid number RedisTimeout Seconds(0-65535)";
    }
    cfg->redis->timeout_sec = (unsigned int)lval;
    lval = strtol(arg2, (char **)NULL, 10);
    if ((lval > 999999) || (lval < 0)) {
        return "Integer invalid number RedisTimeout milliseconds(0-999999)";
    }
    cfg->redis->timeout_msec = (unsigned long)lval;

    DEBUGLOG("%s:%d=[redis_timeout]=[%s.%s]",
        parms->server->server_hostname, parms->server->port, arg1, arg2);
    return (const char *)NULL;
}

static const char* set_redis_database_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    unsigned long lval;

    lval = strtol(arg, (char **)NULL, 10);
    if ((lval > UINT_MAX) || (lval < 0)) {
        return "Integer invalid number Redis Database(0-15[65535])";
    }
    cfg->redis->database = (unsigned int)lval;

    DEBUGLOG("%s:%d=[redis_detabases]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char *set_ignore_contenttype_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    *(char **) apr_array_push(cfg->common->ct_ignore) = apr_pstrdup(parms->pool, arg);
    *(ap_regex_t **)apr_array_push(cfg->common->ct_regexp) =
        ap_pregcomp(parms->pool, arg, AP_REG_EXTENDED|AP_REG_ICASE);

    DEBUGLOG("%s:%d=[ignore_contenttype]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_forwarded_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    if (ap_strcasecmp_match("on", arg) == 0) { cfg->common->forwarded = FLG_ON; }
    else { cfg->common->forwarded = FLG_OFF; }

    DEBUGLOG("%s:%d=[forwarded]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_return_type_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    unsigned long lval;

    if (ap_strcasecmp_match("HTTP_CONTINUE", arg) == 0) {
        cfg->common->http_service_return = HTTP_CONTINUE;
    } else if (ap_strcasecmp_match("HTTP_SWITCHING_PROTOCOLS", arg) == 0) {
        cfg->common->http_service_return = HTTP_SWITCHING_PROTOCOLS;
    } else if (ap_strcasecmp_match("HTTP_PROCESSING", arg) == 0) {
        cfg->common->http_service_return = HTTP_PROCESSING;
    } else if (ap_strcasecmp_match("HTTP_OK", arg) == 0) {
        cfg->common->http_service_return = HTTP_OK;
    } else if (ap_strcasecmp_match("HTTP_CREATED", arg) == 0) {
        cfg->common->http_service_return = HTTP_CREATED;
    } else if (ap_strcasecmp_match("HTTP_ACCEPTED", arg) == 0) {
        cfg->common->http_service_return = HTTP_ACCEPTED;
    } else if (ap_strcasecmp_match("HTTP_NON_AUTHORITATIVE", arg) == 0) {
        cfg->common->http_service_return = HTTP_NON_AUTHORITATIVE;
    } else if (ap_strcasecmp_match("HTTP_NO_CONTENT", arg) == 0) {
        cfg->common->http_service_return = HTTP_NO_CONTENT;
    } else if (ap_strcasecmp_match("HTTP_RESET_CONTENT", arg) == 0) {
        cfg->common->http_service_return = HTTP_RESET_CONTENT;
    } else if (ap_strcasecmp_match("HTTP_PARTIAL_CONTENT", arg) == 0) {
        cfg->common->http_service_return = HTTP_PARTIAL_CONTENT;
    } else if (ap_strcasecmp_match("HTTP_MULTI_STATUS", arg) == 0) {
        cfg->common->http_service_return = HTTP_MULTI_STATUS;
    } else if (ap_strcasecmp_match("HTTP_MULTIPLE_CHOICES", arg) == 0) {
        cfg->common->http_service_return = HTTP_MULTIPLE_CHOICES;
    } else if (ap_strcasecmp_match("HTTP_MOVED_PERMANENTLY", arg) == 0) {
        cfg->common->http_service_return = HTTP_MOVED_PERMANENTLY;
    } else if (ap_strcasecmp_match("HTTP_MOVED_TEMPORARILY", arg) == 0) {
        cfg->common->http_service_return = HTTP_MOVED_TEMPORARILY;
    } else if (ap_strcasecmp_match("HTTP_SEE_OTHER", arg) == 0) {
        cfg->common->http_service_return = HTTP_SEE_OTHER;
    } else if (ap_strcasecmp_match("HTTP_NOT_MODIFIED", arg) == 0) {
        cfg->common->http_service_return = HTTP_NOT_MODIFIED;
    } else if (ap_strcasecmp_match("HTTP_USE_PROXY", arg) == 0) {
        cfg->common->http_service_return = HTTP_USE_PROXY;
    } else if (ap_strcasecmp_match("HTTP_TEMPORARY_REDIRECT", arg) == 0) {
        cfg->common->http_service_return = HTTP_TEMPORARY_REDIRECT;
    } else if (ap_strcasecmp_match("HTTP_BAD_REQUEST", arg) == 0) {
        cfg->common->http_service_return = HTTP_BAD_REQUEST;
    } else if (ap_strcasecmp_match("HTTP_UNAUTHORIZED", arg) == 0) {
        cfg->common->http_service_return = HTTP_UNAUTHORIZED;
    } else if (ap_strcasecmp_match("HTTP_PAYMENT_REQUIRED", arg) == 0) {
        cfg->common->http_service_return = HTTP_PAYMENT_REQUIRED;
    } else if (ap_strcasecmp_match("HTTP_FORBIDDEN", arg) == 0) {
        cfg->common->http_service_return = HTTP_FORBIDDEN;
    } else if (ap_strcasecmp_match("HTTP_NOT_FOUND", arg) == 0) {
        cfg->common->http_service_return = HTTP_NOT_FOUND;
    } else if (ap_strcasecmp_match("HTTP_METHOD_NOT_ALLOWED", arg) == 0) {
        cfg->common->http_service_return = HTTP_METHOD_NOT_ALLOWED;
    } else if (ap_strcasecmp_match("HTTP_NOT_ACCEPTABLE", arg) == 0) {
        cfg->common->http_service_return = HTTP_NOT_ACCEPTABLE;
    } else if (ap_strcasecmp_match("HTTP_PROXY_AUTHENTICATION_REQUIRED", arg) == 0) {
        cfg->common->http_service_return = HTTP_PROXY_AUTHENTICATION_REQUIRED;
    } else if (ap_strcasecmp_match("HTTP_REQUEST_TIME_OUT", arg) == 0) {
        cfg->common->http_service_return = HTTP_REQUEST_TIME_OUT;
    } else if (ap_strcasecmp_match("HTTP_CONFLICT", arg) == 0) {
        cfg->common->http_service_return = HTTP_CONFLICT;
    } else if (ap_strcasecmp_match("HTTP_GONE", arg) == 0) {
        cfg->common->http_service_return = HTTP_GONE;
    } else if (ap_strcasecmp_match("HTTP_LENGTH_REQUIRED", arg) == 0) {
        cfg->common->http_service_return = HTTP_LENGTH_REQUIRED;
    } else if (ap_strcasecmp_match("HTTP_PRECONDITION_FAILED", arg) == 0) {
        cfg->common->http_service_return = HTTP_PRECONDITION_FAILED;
    } else if (ap_strcasecmp_match("HTTP_REQUEST_ENTITY_TOO_LARGE", arg) == 0) {
        cfg->common->http_service_return = HTTP_REQUEST_ENTITY_TOO_LARGE;
    } else if (ap_strcasecmp_match("HTTP_REQUEST_URI_TOO_LARGE", arg) == 0) {
        cfg->common->http_service_return = HTTP_REQUEST_URI_TOO_LARGE;
    } else if (ap_strcasecmp_match("HTTP_UNSUPPORTED_MEDIA_TYPE", arg) == 0) {
        cfg->common->http_service_return = HTTP_UNSUPPORTED_MEDIA_TYPE;
    } else if (ap_strcasecmp_match("HTTP_RANGE_NOT_SATISFIABLE", arg) == 0) {
        cfg->common->http_service_return = HTTP_RANGE_NOT_SATISFIABLE;
    } else if (ap_strcasecmp_match("HTTP_EXPECTATION_FAILED", arg) == 0) {
        cfg->common->http_service_return = HTTP_EXPECTATION_FAILED;
    } else if (ap_strcasecmp_match("HTTP_UNPROCESSABLE_ENTITY", arg) == 0) {
        cfg->common->http_service_return = HTTP_UNPROCESSABLE_ENTITY;
    } else if (ap_strcasecmp_match("HTTP_LOCKED", arg) == 0) {
        cfg->common->http_service_return = HTTP_LOCKED;
    } else if (ap_strcasecmp_match("HTTP_FAILED_DEPENDENCY", arg) == 0) {
        cfg->common->http_service_return = HTTP_FAILED_DEPENDENCY;
    } else if (ap_strcasecmp_match("HTTP_UPGRADE_REQUIRED", arg) == 0) {
        cfg->common->http_service_return = HTTP_UPGRADE_REQUIRED;
    } else if (ap_strcasecmp_match("HTTP_INTERNAL_SERVER_ERROR", arg) == 0) {
        cfg->common->http_service_return = HTTP_INTERNAL_SERVER_ERROR;
    } else if (ap_strcasecmp_match("HTTP_NOT_IMPLEMENTED", arg) == 0) {
        cfg->common->http_service_return = HTTP_NOT_IMPLEMENTED;
    } else if (ap_strcasecmp_match("HTTP_BAD_GATEWAY", arg) == 0) {
        cfg->common->http_service_return = HTTP_BAD_GATEWAY;
    } else if (ap_strcasecmp_match("HTTP_SERVICE_UNAVAILABLE", arg) == 0) {
        cfg->common->http_service_return = HTTP_SERVICE_UNAVAILABLE;
    } else if (ap_strcasecmp_match("HTTP_GATEWAY_TIME_OUT", arg) == 0) {
        cfg->common->http_service_return = HTTP_GATEWAY_TIME_OUT;
    } else if (ap_strcasecmp_match("HTTP_VERSION_NOT_SUPPORTED", arg) == 0) {
        cfg->common->http_service_return = HTTP_VERSION_NOT_SUPPORTED;
    } else if (ap_strcasecmp_match("HTTP_VARIANT_ALSO_VARIES", arg) == 0) {
        cfg->common->http_service_return = HTTP_VARIANT_ALSO_VARIES;
    } else if (ap_strcasecmp_match("HTTP_INSUFFICIENT_STORAGE", arg) == 0) {
        cfg->common->http_service_return = HTTP_INSUFFICIENT_STORAGE;
    } else if (ap_strcasecmp_match("HTTP_NOT_EXTENDED", arg) == 0) {
        cfg->common->http_service_return = HTTP_NOT_EXTENDED;
    } else  {
        lval = strtol(arg, (char **)NULL, 10);
        if ((lval > UINT_MAX) || (lval < 0)) {
            return "Integer invalid number return_type(100-510[65535])";
        }
        cfg->common->http_service_return = (unsigned int)lval;
    }

    DEBUGLOG("%s:%d=[return_type]=[%s]", parms->server->server_hostname, parms->server->port, arg);
    return (const char*)NULL;
}

static const char* set_dosaction_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    if (ap_strcasecmp_match("on", arg) == 0) { cfg->common_dos->action = FLG_ON; }
    else { cfg->common_dos->action = FLG_OFF; }

    DEBUGLOG("%s:%d=[common dos action]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_time_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    unsigned long lval;

    lval = strtol(arg, (char **)NULL, 10);
    if ((lval > UINT_MAX) || (lval < 0)) {
        return "Integer invalid number DoSTime(0-15[65535])";
    }
    cfg->common_dos->time = (unsigned int)lval;

    DEBUGLOG("%s:%d=[time]=[%s]", parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_request_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    unsigned long lval;

    lval = strtol(arg, (char **)NULL, 10);
    if ((lval > UINT_MAX) || (lval < 0)) {
        return "Integer invalid number DoSRequest(0-15[65535])";
    }
    cfg->common_dos->request = (unsigned int)lval;

    DEBUGLOG("%s:%d=[request]=[%s]", parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_wait_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    unsigned long lval;

    lval = strtol(arg, (char **)NULL, 10);
    if ((lval > UINT_MAX) || (lval < 0)) {
        return "Integer invalid number DoSWait(0-15[65535])";
    }
    cfg->common_dos->wait = (unsigned int)lval;

    DEBUGLOG("%s:%d=[wait]=[%s]", parms->server->server_hostname, parms->server->port, arg);

    return (const char *)NULL;
}

static const char* set_doscase_config
    (cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    char *key = (char *)NULL, *value = (char *)NULL;
    detailsdos_s *val = (detailsdos_s *)NULL;
    unsigned long lval = 0;
    int i = 0, fg = FLG_OFF;

    // Set Path (check for duplicate path)
    fg = FLG_OFF;
    for (i = 0; i < cfg->detailsdos_s->nelts; i++) {
        val = (detailsdos_s*)(cfg->detailsdos_s->elts + (cfg->detailsdos_s->elt_size * i));
        if (strcmp(arg1, val->path) == 0) {
            fg = FLG_ON;
            break;
        }
    }
    // check for duplicate
    if (fg == FLG_OFF) {
        val = (detailsdos_s*)apr_array_push(cfg->detailsdos_s);
        val->path = apr_pstrdup(parms->pool, arg1);
    }

    // Arg2 Split into key and value
    key = ap_getword(parms->pool, (const char **)&arg2, '=');
    value = ap_getword_conf(parms->pool, (const char**)&arg2);

    if (key) {
        if (ap_strcasecmp_match(key, "checktime") == 0 || ap_strcasecmp_match(key, "ctime") == 0) {
            lval = strtol(value, (char **)NULL, 10);
            if ((lval > UINT_MAX) || (lval < 1)) {
                return "Time:Integer invalid number Time(for Sec) (1-65535)";
            }
            val->time = (unsigned int)lval;
            DEBUGLOG("%s:%d=[%s][%s]=[%lu]",
                parms->server->server_hostname, parms->server->port, arg1, key, lval);
        }
        else if (ap_strcasecmp_match(key, "request") == 0 || ap_strcasecmp_match(key, "req") == 0) {
            lval = strtol(value, (char **)NULL, 10);
            if ((lval > UINT_MAX) || (lval < 1)) {
                return "Request:Integer invalid number Request (1-65535)";
            }
            val->request = (unsigned int)lval;
            DEBUGLOG("%s:%d=[%s][%s]=[%lu]",
                parms->server->server_hostname, parms->server->port, arg1, key, lval);
        }
        else if (ap_strcasecmp_match(key, "waittime") == 0 ||
                 ap_strcasecmp_match(key, "wtime") == 0) {
            lval = strtol(value, (char **)NULL, 10);
            if ((lval > UINT_MAX) || (lval < 1)) {
                return "Wait:Integer invalid number Wait(for Sec) (1-65535)";
            }
            val->wait = (unsigned int)lval;
            DEBUGLOG("%s:%d=[%s][%s]=[%lu]",
                parms->server->server_hostname, parms->server->port, arg1, key, lval);
        }
    }
    return (const char *)NULL;
}

static const char* set_dosfilepath_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    cfg->dosfile->filepath = apr_pstrdup(parms->pool, (char*)arg);

    DEBUGLOG("%s:%d=[DoshelperDosfilepath]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_ctl_action_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    if (ap_strcasecmp_match("on", arg) == 0) { cfg->ctl->action = FLG_ON; }
    else { cfg->ctl->action = FLG_OFF; }

    DEBUGLOG("%s:%d=[control action]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_ipwhiteset_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    cfg->ctl->white->set = apr_pstrdup(parms->pool, (char*)arg);

    DEBUGLOG("%s:%d=[DoshelperIpWhiteSet]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_ipwhitedel_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    cfg->ctl->white->del = apr_pstrdup(parms->pool, (char*)arg);

    DEBUGLOG("%s:%d=[DoshelperIpWhiteDel]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_ipwhitelist_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    cfg->ctl->white->list = apr_pstrdup(parms->pool, (char*)arg);

    DEBUGLOG("%s:%d=[DoshelperIpWhiteList]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_ipblackset_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    cfg->ctl->black->set = apr_pstrdup(parms->pool, (char*)arg);

    DEBUGLOG("%s:%d=[DoshelperIpBlackSet]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_ipblackdel_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    cfg->ctl->black->del = apr_pstrdup(parms->pool, (char*)arg);

    DEBUGLOG("%s:%d=[DoshelperIpBlackDel]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_ipblacklist_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    cfg->ctl->black->list = apr_pstrdup(parms->pool, (char*)arg);

    DEBUGLOG("%s:%d=[DoshelperIpBlackList]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_ipsetfilepath_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    cfg->ctl->setfile->filepath = apr_pstrdup(parms->pool, (char*)arg);

    DEBUGLOG("%s:%d=[DoshelperIpSetFormFilePath]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_ipcplfilepath_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    cfg->ctl->cplfile->filepath = apr_pstrdup(parms->pool, (char*)arg);

    DEBUGLOG("%s:%d=[DoshelperIpCompleteFilePath]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_iplistfilepath_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);

    cfg->ctl->listfile->filepath = apr_pstrdup(parms->pool, (char*)arg);

    DEBUGLOG("%s:%d=[DoshelperIpListFilePath]=[%s]",
        parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_display_count_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    unsigned long lval;

    lval = strtol(arg, (char **)NULL, 10);
    if ((lval > UINT_MAX) || (lval < 1)) {
        return "Integer invalid number Display Count(1-32[65535])";
    }
    cfg->ctl->display = (unsigned int)lval;

    DEBUGLOG("%s:%d=[dispcount]=[%s]", parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static const char* set_control_free_config(cmd_parms *parms, void *mconfig, const char *arg) {
    server_rec *s = (server_rec *)parms->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    unsigned long lval;

    lval = strtol(arg, (char **)NULL, 10);
    if ((lval > UINT_MAX) || (lval < 0)) {
        return "Integer invalid number open control screen time[sec](0-65535)";
    }
    cfg->ctl->freetime = (unsigned int)lval;

    DEBUGLOG("%s:%d=[freetime]=[%s]", parms->server->server_hostname, parms->server->port, arg);
    return (const char *)NULL;
}

static command_rec doshelper_cmds[] = {
    AP_INIT_TAKE1("DoshelperAction", set_action_config,
        NULL, OR_FILEINFO, "Enable to doshelper or Not"),
    AP_INIT_TAKE1("DoshelperMutex", set_mutex_config,
        NULL, OR_FILEINFO, "Enable to Mutex Mode or Not"),
    AP_INIT_TAKE1("DoshelperDevelopment", set_development_config,
        NULL, OR_FILEINFO, "Development of doshelper"),
    AP_INIT_ITERATE("DoshelperRedisServer", set_redis_server_config,
        NULL, OR_FILEINFO, "Redis Server IP List"),
    AP_INIT_TAKE1("DoshelperRedisRequirepass", set_redis_requirepass_config,
        NULL, OR_FILEINFO, "Redis Requirepass or Not"),
    AP_INIT_TAKE2("DoshelperRedisConnectTimeout", set_redis_timeout_config,
        NULL, OR_FILEINFO, "Redis Connect Timeout Not Set"),
    AP_INIT_TAKE1("DoshelperRedisDatabase", set_redis_database_config,
        NULL, OR_FILEINFO, "Error of the Redis Database number"),
    AP_INIT_ITERATE("DoshelperIgnoreContentType", set_ignore_contenttype_config,
        NULL, OR_FILEINFO, "The names of ignoring Content Type"),
    AP_INIT_TAKE1("DoshelperForwarded", set_forwarded_config,
        NULL, OR_FILEINFO, "Enable to Get the IP, which is forwarded"),
    AP_INIT_TAKE1("DoshelperReturnType", set_return_type_config,
        NULL, OR_FILEINFO, "Control of the Retrun"),
    AP_INIT_TAKE1("DoshelperCommmonDosAction", set_dosaction_config,
        NULL, OR_FILEINFO, "Enable to all checks of DoS attackis or Not"),
    AP_INIT_TAKE1("DoshelperDosCheckTime", set_time_config,
        NULL, OR_FILEINFO, "DoS Second interval"),
    AP_INIT_TAKE1("DoshelperDosRequest", set_request_config,
        NULL, OR_FILEINFO, "DoS number of requests"),
    AP_INIT_TAKE1("DoshelperDosWaitTime", set_wait_config,
        NULL, OR_FILEINFO, "Access stop time"),
    AP_INIT_ITERATE2("DoshelperDosCase", set_doscase_config,
        NULL, OR_FILEINFO, "Dos Attacks Setting..."),
    AP_INIT_TAKE1("DoshelperControlAction", set_ctl_action_config,
        NULL, OR_FILEINFO, "Use of the control function"),
    AP_INIT_TAKE1("DoshelperDosFilePath", set_dosfilepath_config,
        NULL, OR_FILEINFO, "DoS blocking filepath or Not"),
    AP_INIT_TAKE1("DoshelperIpWhiteSet", set_ipwhiteset_config,
        NULL, OR_FILEINFO, "white ip set uri form or Not"),
    AP_INIT_TAKE1("DoshelperIpWhiteDel", set_ipwhitedel_config,
        NULL, OR_FILEINFO, "white ip delete form uri or Not"),
    AP_INIT_TAKE1("DoshelperIpWhiteList", set_ipwhitelist_config,
        NULL, OR_FILEINFO, "white ip list form uri or Not"),
    AP_INIT_TAKE1("DoshelperIpBlackSet", set_ipblackset_config,
        NULL, OR_FILEINFO, "Black ip set uri form or Not"),
    AP_INIT_TAKE1("DoshelperIpBlackDel", set_ipblackdel_config,
        NULL, OR_FILEINFO, "Black ip delete form uri or Not"),
    AP_INIT_TAKE1("DoshelperIpBlackList", set_ipblacklist_config,
        NULL, OR_FILEINFO, "Black ip list form uri or Not"),
    AP_INIT_TAKE1("DoshelperIpSetFormFilePath", set_ipsetfilepath_config,
        NULL, OR_FILEINFO, "ip setting template form filepath or Not"),
    AP_INIT_TAKE1("DoshelperIpCompleteFilePath", set_ipcplfilepath_config,
        NULL, OR_FILEINFO, "ip complete template form filepath or Not"),
    AP_INIT_TAKE1("DoshelperIpListFilePath", set_iplistfilepath_config,
        NULL, OR_FILEINFO, "ip black list template filepath or Not"),
    AP_INIT_TAKE1("DoshelperDisplayCount", set_display_count_config,
        NULL, OR_FILEINFO, "count of uuid display"),
    AP_INIT_TAKE1("DoshelperControlFree", set_control_free_config,
        NULL, OR_FILEINFO, "Open time at the control screen access"),
    {NULL}
};

static void *create_doshelper_config_svr(apr_pool_t *p, server_rec *dummy) {
    config_s *cfg = (config_s*)apr_pcalloc(p, sizeof(*cfg));

    cfg->mutex = (mutex_s *)apr_pcalloc(p, sizeof(mutex_s));
    cfg->mutex->action = FLG_ON;
    cfg->mutex->mutex = (apr_global_mutex_t *)NULL;
    cfg->common = (common_s *)apr_pcalloc(p, sizeof(common_s));
    cfg->common->action = FLG_OFF;
    cfg->common->development = FLG_OFF;
    cfg->common->forwarded = FLG_OFF;
    cfg->common->http_service_return = DECLINED;
    cfg->common->ct_ignore = apr_array_make(p, 0, sizeof(char*));
    cfg->common->ct_regexp = apr_array_make(p, 0, sizeof(char*));
    cfg->redis = (redis_s *)apr_pcalloc(p, sizeof(redis_s));
    cfg->redis->server = apr_array_make(p, 0, sizeof(char*));
    cfg->redis->history = 0;
    cfg->redis->requirepass = (char *)NULL;
    cfg->redis->timeout_sec = 0;
    cfg->redis->timeout_msec = 50000;
    cfg->redis->database = 0;
    cfg->redis->context = (redisContext *)NULL;
    cfg->common_dos = (commondos_s *)apr_pcalloc(p, sizeof(commondos_s));
    cfg->common_dos->action = FLG_OFF;
    cfg->common_dos->time = 0;
    cfg->common_dos->request = 0;
    cfg->common_dos->wait = 0;
    cfg->detailsdos_s = apr_array_make(p, 0, sizeof(detailsdos_s));
    cfg->dosfile = (initfile_s *)apr_pcalloc(p, sizeof(initfile_s));
    cfg->dosfile->filepath = apr_pstrdup(p, "");
    cfg->dosfile->page = apr_pstrdup(p, "");
    cfg->ctl = (control_s *)apr_pcalloc(p, sizeof(control_s));
    cfg->ctl->action = FLG_OFF;
    cfg->ctl->white = (action_s *)apr_pcalloc(p, sizeof(action_s));
    cfg->ctl->white->set = apr_pstrdup(p, "");
    cfg->ctl->white->del = apr_pstrdup(p, "");
    cfg->ctl->white->list = apr_pstrdup(p, "");
    cfg->ctl->black = (action_s *)apr_pcalloc(p, sizeof(action_s));
    cfg->ctl->black->set = apr_pstrdup(p, "");
    cfg->ctl->black->del = apr_pstrdup(p, "");
    cfg->ctl->black->list = apr_pstrdup(p, "");
    cfg->ctl->wait = (action_s *)apr_pcalloc(p, sizeof(action_s));
    cfg->ctl->wait->set = apr_pstrdup(p, "");
    cfg->ctl->wait->del = apr_pstrdup(p, "");
    cfg->ctl->wait->list = apr_pstrdup(p, "");
    cfg->ctl->setfile = (initfile_s *)apr_pcalloc(p, sizeof(initfile_s));
    cfg->ctl->setfile->filepath = apr_pstrdup(p, "");
    cfg->ctl->setfile->page = apr_pstrdup(p, "");
    cfg->ctl->cplfile = (initfile_s *)apr_pcalloc(p, sizeof(initfile_s));
    cfg->ctl->cplfile->filepath = apr_pstrdup(p, "");
    cfg->ctl->cplfile->page = apr_pstrdup(p, "");
    cfg->ctl->listfile = (initfile_s *)apr_pcalloc(p, sizeof(initfile_s));
    cfg->ctl->listfile->filepath = apr_pstrdup(p, "");
    cfg->ctl->listfile->page = apr_pstrdup(p, "");
    cfg->ctl->display = 500;
    cfg->ctl->freetime = 0;

    return (void*)cfg;
}

static void doshelper_register_hooks(apr_pool_t *p) {
    ap_hook_post_config(initialize_module, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(doshelper_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_quick_handler(control_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_handler(template_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

module AP_MODULE_DECLARE_DATA doshelper_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,
    NULL,
    create_doshelper_config_svr,
    NULL,
    doshelper_cmds,
    doshelper_register_hooks
};
