/* 
**  mod_doshelper.c -- Apache doshelper module
**
**  Copyright (C) 2012-2015 Tsuyoshi Kurosawa
**  The author is Tsuyoshi Kurosawa <kurosawa.tsuyoshi@jamhelper.com>.
**
*/ 
#include "mod_doshelper.h"

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

static detailsdos_s *get_detail_dos_list(request_rec *r) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    detailsdos_s *val = (detailsdos_s *)NULL;
    char *url = (char *)NULL;
    int i = 0;

    if (r->args == (char *)NULL) { url = r->uri; }
    else { url = apr_psprintf(r->pool, "%s?%s", r->uri, r->args); }

    // Config Detail ID Getting
    for (i = 0; i < cfg->dos->detailsdos_s->nelts; i++) {
        val = (detailsdos_s *)(cfg->dos->detailsdos_s->elts + (cfg->dos->detailsdos_s->elt_size * i));

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
    if (cnt > cfg->dos->request) {
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
    if ( cfg->dos->action == FLG_ON) {
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
 
    if (st->status == __NORMAL || strlen(cfg->dos->dosfile->page) > 0 ) {
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
        pbuf = str_conv(r, pbuf, "value=", "");

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
    if (strcmp(r->uri, "*") == APR_SUCCESS) return DECLINED;

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
    if (strlen(cfg->dos->dosfile->page) > 0) {
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
        status = initialize_set_templatefile(s, p, cfg->dos->dosfile, "Dosfilepath");

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

    if (ap_strcasecmp_match("on", arg) == 0) { cfg->dos->action = FLG_ON; }
    else { cfg->dos->action = FLG_OFF; }

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
    cfg->dos->time = (unsigned int)lval;

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
    cfg->dos->request = (unsigned int)lval;

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
    cfg->dos->wait = (unsigned int)lval;

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
    for (i = 0; i < cfg->dos->detailsdos_s->nelts; i++) {
        val = (detailsdos_s*)(cfg->dos->detailsdos_s->elts + (cfg->dos->detailsdos_s->elt_size * i));
        if (strcmp(arg1, val->path) == 0) {
            fg = FLG_ON;
            break;
        }
    }
    // check for duplicate
    if (fg == FLG_OFF) {
        val = (detailsdos_s*)apr_array_push(cfg->dos->detailsdos_s);
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

    cfg->dos->dosfile->filepath = apr_pstrdup(parms->pool, (char*)arg);

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
    cfg->dos = (dos_s *)apr_pcalloc(p, sizeof(dos_s));
    cfg->dos->action = FLG_OFF;
    cfg->dos->time = 0;
    cfg->dos->request = 0;
    cfg->dos->wait = 0;
    cfg->dos->detailsdos_s = apr_array_make(p, 0, sizeof(detailsdos_s));
    cfg->dos->dosfile = (initfile_s *)apr_pcalloc(p, sizeof(initfile_s));
    cfg->dos->dosfile->filepath = apr_pstrdup(p, "");
    cfg->dos->dosfile->page = apr_pstrdup(p, "");
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
