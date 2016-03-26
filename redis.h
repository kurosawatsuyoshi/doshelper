#ifndef _DOSHELPER_REDIS_H_
#define _DOSHELPER_REDIS_H_
extern apr_status_t check_redis_version(server_rec*, redisContext*);
extern apr_status_t check_redis_master(server_rec*, redisContext*);
extern redisContext *connect_redis_master(server_rec*, char*);
extern redisContext *connect_redis_server(server_rec*);
extern redisContext *connect_redis(server_rec*);
extern int get_free_address_redis(request_rec*, redisContext*, const char*);
extern apr_status_t set_free_address_redis(request_rec*, redisContext*, const char*, const int);
extern int set_dos_address_redis(request_rec*, redisContext*, const char*, detailsdos_s*, unsigned int);
extern int delete_dos_address_redis(request_rec*, redisContext*, const char*, detailsdos_s*);
extern apr_status_t set_wait_dos_redis(request_rec*, redisContext*, const char*, detailsdos_s*);
#endif // _DOSHELPER_REDIS_H_

