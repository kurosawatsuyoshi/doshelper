#ifndef _DOSHELPER_CONTROL_H_
#define _DOSHELPER_CONTROL_H_
extern apr_status_t put_screen_ip_set(request_rec*, char*);
extern apr_status_t put_screen_ip_complete(request_rec*, char*, char*);
extern apr_status_t put_screen_ip_list(request_rec*, char*, char*);
extern char *str_unescape(request_rec*, const char*);
extern int set_white_address_redis(request_rec*, redisContext*, const char*);
extern int delete_white_address_redis(request_rec*, redisContext*, const char*);
extern char* get_list_ip_redis(request_rec*, redisContext*, char*, char*);
#endif // _DOSHELPER_CONTROL_H_

