#include "mod_doshelper.h"

extern apr_status_t put_screen(request_rec *r, char *pbuf) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    char *phtml = (char *)NULL;

    // Validation Check
    if (pbuf == (char *)NULL) { return DECLINED; }

    phtml = apr_pstrdup(r->pool, pbuf);
    phtml = str_conv(r, phtml, CNV_WHITELIST, cfg->ctl->white->list);
    phtml = str_conv(r, phtml, CNV_WHITESET, cfg->ctl->white->set);
    phtml = str_conv(r, phtml, CNV_WHITEDEL, cfg->ctl->white->del);
    phtml = str_conv(r, phtml, CNV_BLACKLIST, cfg->ctl->black->list);
    phtml = str_conv(r, phtml, CNV_BLACKSET, cfg->ctl->black->set);
    phtml = str_conv(r, phtml, CNV_BLACKDEL, cfg->ctl->black->del);

    r->content_type = "text/html";
    if (!r->header_only) {
        ap_rputs(phtml, r);
        return APR_SUCCESS;
    }

    return DECLINED;
}

extern apr_status_t put_screen_dos(request_rec *r) {
    server_rec *s = (server_rec *)r->server;
    config_s *cfg = (config_s *)ap_get_module_config(s->module_config, &doshelper_module);
    char *pbuf = (char *)NULL;

    if (cfg->dos->dosfile->page == (char *)NULL ||
        strlen(cfg->dos->dosfile->page) == 0) return DECLINED;

    pbuf = apr_pstrdup(r->pool, cfg->dos->dosfile->page);
    pbuf = str_conv(r, pbuf, CNV_IP, get_ip_address(r));
    pbuf = str_conv(r, pbuf, CNV_APACHE_MAJOR,
        (const char *)apr_psprintf(r->pool, "%d", AP_SERVER_MAJORVERSION_NUMBER));
    pbuf = str_conv(r, pbuf, CNV_APACHE_MINOR,
        (const char *)apr_psprintf(r->pool, "%d", AP_SERVER_MINORVERSION_NUMBER));

    return put_screen(r, pbuf);
}

