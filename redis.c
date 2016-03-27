#include "mod_doshelper.h"

extern apr_status_t check_redis_version(server_rec *s, redisContext *context) {
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

extern apr_status_t check_redis_master(server_rec *s, redisContext *context) {
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

extern redisContext *connect_redis_master(server_rec *s, char *redisip_port) {
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
        WARNLOG("failed to %s [%s:%s]", context->errstr, redis_ip, redis_port);
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

extern redisContext *connect_redis_server(server_rec *s) {
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

extern redisContext *connect_redis(server_rec *s) {
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

extern int get_free_address_redis(request_rec *r, redisContext *context, const char *address) {
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

extern apr_status_t set_free_address_redis
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

extern int set_dos_address_redis
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
        dostime = cfg->dos->time;
    }
    else {
        dostime = details->time;
        path = apr_psprintf(r->pool, "%s:%s", path, details->path);
    }

    // IP Control Bloking
    if (block) {
        rep = (redisReply *)redisCommand(context, apr_psprintf(r->pool,
            "SET "MODULE_KEY_NAME":"REDIS_KEY_DOS":%s:%s %d",
                path, address, cfg->dos->request + 1));

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
            path, address, cfg->dos->request+1);
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

extern int delete_dos_address_redis
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

extern apr_status_t set_wait_dos_redis
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
        dostime = cfg->dos->wait;
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

