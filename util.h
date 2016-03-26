#ifndef _DOSHELPER_UTIL_H_
#define _DOSHELPER_UTIL_H_
extern char *str_conv(request_rec*, char*, const char*, const char *); 
extern const char *get_ip_address(request_rec*);
extern apr_status_t check_regular_expression(request_rec*, char*, char*);
extern char *extract_string(char*, char*, char*);
#endif // _DOSHELPER_UTIL_H_

