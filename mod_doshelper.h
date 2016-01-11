#ifdef _WIN32
  #include <rpc.h>
  #include <stdarg.h>
#else
  #include "unixd.h"
#endif
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "apr_version.h"
#include "apr_strings.h"
#include "apr_global_mutex.h"
#include "util_script.h"
#include "hiredis/hiredis.h"
#include <sys/stat.h>

#define MODULE_NAME "mod_doshelper"
#define MODULE_VERSION "1.0.0"
#define MODULE_KEY_NAME "doshelper"
#define USER_DATA_KEY "DosHelperUserDataKey"
#define DOSHELPER_IGNORE "DOSHELPER_IGNORE"
#define FLG_ON  1
#define FLG_OFF 0
#define ENV_FORWARDED "X-Forwarded-For"
#define ENV_DOS "DoSAttack"
#define ENV_TGT "Target"

// Redis Define
#define REDIS_DEFAULT_PORT "6379"
#define REDIS_DEFAULT_MASTER "MASTER"
#define REDIS_VERSION_LATER "2.8"
#define REDIS_KEY_FREE "free__"
#define REDIS_KEY_DOS "dos___"
#define REDIS_CMD_INFO_REPICATION "INFO replication"
#define REDIS_CMD_INFO_REP_ROLE "role:"
#define REDIS_CMD_INFO_SERVER "INFO server"
#define REDIS_CMD_INFO_SVR_VERSION "redis_version:"
#define REDIS_CMD_STR_DELIMIT "\r\n"

// IP Control Define
#define IP_WHITE_LIST "IP White List"
#define IP_WHITE_SET "IP White List Set"
#define IP_WHITE_DEL "IP White List Delete"
#define IP_BLACK_LIST "IP Black List"
#define IP_BLACK_SET "IP Black List Set"
#define IP_BLACK_DEL "IP Black List Delete"
#define CNV_IP   "$_[\"ip\"]"
#define CNV_UUID "$_[\"uuid\"]"
#define CNV_APACHE_MAJOR "$_[\"major\"]"
#define CNV_APACHE_MINOR "$_[\"minor\"]"
#define CNV_PROC "$_[\"proc\"]"
#define CNV_LIST "$_[\"iplist\"]"
#define CNV_URI  "$_[\"uri\"]"
#define CNV_WHITELIST  "$_[\"whitelist\"]"
#define CNV_WHITESET  "$_[\"whiteset\"]"
#define CNV_WHITEDEL  "$_[\"whitedel\"]"
#define CNV_BLACKLIST  "$_[\"blacklist\"]"
#define CNV_BLACKSET  "$_[\"blackset\"]"
#define CNV_BLACKDEL  "$_[\"blackdel\"]"

// for Apache 2.0,  define the AP_NEED_SET_MUTEX_PERMS
#ifndef AP_NEED_SET_MUTEX_PERMS
  #if !defined(OS2) && !defined(WIN32) && !defined(BEOS) && !defined(NETWARE)
  #define AP_NEED_SET_MUTEX_PERMS
  #endif
#endif

// Compatibility with regex on liss than Apache2.1
#if (AP_SERVER_MAJORVERSION_NUMBER >= 2) && \
    (AP_SERVER_MINORVERSION_NUMBER >= 1) && \
    (AP_SERVER_PATCHLEVEL_NUMBER >= 0)
  #if defined(HAVE_AP_REGEX_H) && HAVE_AP_REGEX_H == 1
  #  include <regex.h>
  #else
  #  include <ap_regex.h>
  #endif
#else
  typedef regmatch_t ap_regmatch_t;
  typedef regex_t ap_regex_t;
  #define AP_REG_EXTENDED REG_EXTENDED
  #define AP_REG_ICASE REG_ICASE
#endif

#if !defined(REG_EXTENDED)
  #define REG_EXTENDED AP_REG_EXTENDED
#endif
#if !defined(REG_ICASE)
  #define REG_ICASE AP_REG_ICASE
#endif

// LogLevel on less than apache 2.3.6 (ap_mmn.h) 
#if (AP_SERVER_MAJORVERSION_NUMBER >= 2) && \
    (AP_SERVER_MINORVERSION_NUMBER >= 3) && \
    (AP_SERVER_PATCHLEVEL_NUMBER >= 6)
  #define LOGLEVEL log.level
#else
  #define LOGLEVEL loglevel
#endif

#define EMERGLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, 0, s, MODULE_NAME ": " __VA_ARGS__)
#define ALERTLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, 0, s, MODULE_NAME ": " __VA_ARGS__)
#define CRITLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_CRIT, 0, s, MODULE_NAME ": " __VA_ARGS__)
#define ERRORLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, s, MODULE_NAME ": " __VA_ARGS__)
#define WARNLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, s, MODULE_NAME ": " __VA_ARGS__)
#define NOTICELOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, s, MODULE_NAME ": " __VA_ARGS__)
#define INFOLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, s, MODULE_NAME ": " __VA_ARGS__)
#define DEBUGLOG(...) ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, s, MODULE_NAME ": " __VA_ARGS__)

// Config Struct
// Display File Path Structs
typedef struct {
    char *filepath;
    char *page;
} initfile_s;

// Control Panel Action Structs
typedef struct {
    char *set;
    char *del;
    char *list;
} action_s;

// Control Panel Structs
typedef struct {
    unsigned int action;
    action_s *white;
    action_s *black;
    action_s *wait;
    initfile_s *setfile;
    initfile_s *cplfile;
    initfile_s *listfile;
    unsigned int freetime;
    unsigned int display;
} control_s;

// DoS Detail Structs
typedef struct {
    char *path;
    unsigned int time;
    unsigned int request;
    unsigned int wait;
} detailsdos_s;

// DoS Control Structs
typedef struct {
    unsigned int action;
    unsigned int time;
    unsigned int request;
    unsigned int wait;
    initfile_s *dosfile;
    apr_array_header_t *detailsdos_s;
} dos_s;

// Redis Structs
typedef struct {
    apr_array_header_t *server;
    int history;
    char *requirepass;
    unsigned int timeout_sec;
    unsigned long timeout_msec;
    unsigned int database;
    redisContext *context;
} redis_s;

// Common Structs
typedef struct {
    unsigned int action;
    unsigned int development;
    unsigned int history;
    unsigned int forwarded;
    unsigned int http_service_return;
    apr_array_header_t *ct_ignore;
    apr_array_header_t *ct_regexp;
} common_s;

// Mutex Structs
typedef struct {
    unsigned int action;
    apr_global_mutex_t *mutex;
} mutex_s;

typedef struct {
    mutex_s *mutex;
    common_s *common;
    redis_s *redis;
    dos_s *dos;
    control_s *ctl;
} config_s;

typedef struct {
    unsigned int status;
    unsigned int visit;
} status_s;

// typedef enum area
typedef enum {
    __NORMAL,
    __DOS,
} status_e;

typedef enum {
    __FIRST,
    __VISIT,
    __COMPLETE,
    __ERROR
} visit_e;

