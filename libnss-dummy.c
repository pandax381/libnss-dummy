#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <nss.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef DEBUG
#include <syslog.h>
#define DBG_TRACE syslog(LOG_DEBUG, "dbg_trace: %s (%d)\n", __FILE__, __LINE__)
#else
#define DBG_TRACE
#endif

#define DUMMY_ADDR_IPV4 (htonl(0x7f000002))
#define DUMMY_ADDR_IPV6 &in6addr_loopback
#define DUMMY_INTERFACE "lo"

#define ALIGN(x) (((x+sizeof(void*)-1)/sizeof(void*))*sizeof(void*))

inline size_t ADDRLEN (int proto) {
    return proto == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
}

#define _public_ __attribute__ ((visibility("default")))

enum nss_status
_nss_dummy_gethostbyname4_r (const char *name, struct gaih_addrtuple **pat, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp) _public_;
enum nss_status
_nss_dummy_gethostbyname3_r (const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp) _public_;
enum nss_status
_nss_dummy_gethostbyname2_r (const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop) _public_;
enum nss_status
_nss_dummy_gethostbyname_r  (const char *name, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop) _public_;
enum nss_status
_nss_dummy_gethostbyaddr2_r (const void *addr, socklen_t len, int af, struct hostent *host, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp) _public_;
enum nss_status
_nss_dummy_gethostbyaddr_r  (const void *addr, socklen_t len, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop) _public_;

enum nss_status
_nss_dummy_gethostbyname4_r (const char *name, struct gaih_addrtuple **pat, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)
{
    unsigned index;
    size_t n, offset, size;
    char *hostname;
    struct gaih_addrtuple *tuple, *prev = NULL;

    DBG_TRACE;

    index = if_nametoindex(DUMMY_INTERFACE);

    n = strlen(name) + 1;
    size = ALIGN(n) + ALIGN(sizeof(struct gaih_addrtuple)) * 2;
    if (buflen < size) {
        *errnop = ENOMEM;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    /* hostname */
    hostname = buffer;
    memcpy(hostname, name, n);
    offset = ALIGN(n);

    /* AF_INET6 */
    tuple = (struct gaih_addrtuple*) (buffer + offset);
    tuple->next = prev;
    tuple->name = hostname;
    tuple->family = AF_INET6;
    memcpy(tuple->addr, DUMMY_ADDR_IPV6, ADDRLEN(AF_INET6));
    tuple->scopeid = (uint32_t) index;

    offset += ALIGN(sizeof(struct gaih_addrtuple));
    prev = tuple;

    /* AF_INET */
    tuple = (struct gaih_addrtuple*) (buffer + offset);
    tuple->next = prev;
    tuple->name = hostname;
    tuple->family = AF_INET;
    *(uint32_t*) tuple->addr = DUMMY_ADDR_IPV4;
    tuple->scopeid = (uint32_t) index;

    offset += ALIGN(sizeof(struct gaih_addrtuple));
    prev = tuple;

    *pat = prev;

    if (ttlp)
        *ttlp = 0;

    return NSS_STATUS_SUCCESS;
}

static enum nss_status
fill_in_hostent (const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    size_t n, offset, size;
    char *addr, *hostname, *aliases, *addr_list;
    size_t alen;

    DBG_TRACE;

    alen = ADDRLEN(af);

    n = strlen(name) + 1;
    size = ALIGN(n) + sizeof(char*) + ALIGN(alen) + sizeof(char*) * 2;
    if (buflen < size) {
        *errnop = ENOMEM;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    /* hostname */
    hostname = buffer;
    memcpy(hostname, name, n);
    offset = ALIGN(n);

    /* aliases (empty) */
    aliases = buffer + offset;
    *(char**) aliases = NULL;
    offset += sizeof(char*);

    /* address */
    addr = buffer + offset;
    if (af == AF_INET)
        *(uint32_t*) addr = DUMMY_ADDR_IPV4;
    else
        memcpy(addr, DUMMY_ADDR_IPV6, ADDRLEN(AF_INET6));

    offset += ALIGN(alen);

    /* address list */
    addr_list = buffer + offset;
    ((char**) addr_list)[0] = addr;
    ((char**) addr_list)[1] = NULL;
    offset += sizeof(char*) * 2;

    result->h_name = hostname;
    result->h_aliases = (char**) aliases;
    result->h_addrtype = af;
    result->h_length = alen;
    result->h_addr_list = (char**) addr_list;

    if (ttlp)
        *ttlp = 0;

    if (canonp)
        *canonp = hostname;

    return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_dummy_gethostbyname3_r (const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp, char **canonp)
{
    DBG_TRACE;

    if (af == AF_UNSPEC)
        af = AF_INET;

    if (af != AF_INET && af != AF_INET6) {
        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    return fill_in_hostent(name, af, result, buffer, buflen, errnop, h_errnop, ttlp, canonp);
}

enum nss_status
_nss_dummy_gethostbyname2_r (const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
    DBG_TRACE;

    return _nss_dummy_gethostbyname3_r(name, af, result, buffer, buflen, errnop, h_errnop, NULL, NULL);
}

enum nss_status
_nss_dummy_gethostbyname_r (const char *name, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
    DBG_TRACE;

    return _nss_dummy_gethostbyname2_r(name, AF_UNSPEC, result, buffer, buflen, errnop, h_errnop);
}

enum nss_status
_nss_dummy_gethostbyaddr2_r (const void *addr, socklen_t len, int af, struct hostent *host, char *buffer, size_t buflen, int *errnop, int *h_errnop, int32_t *ttlp)
{
    char hn[HOST_NAME_MAX+1];

    DBG_TRACE;

    if (len != ADDRLEN(af)) {
        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    if (af != AF_INET && af != AF_INET6) {
        *errnop = EAFNOSUPPORT;
        *h_errnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
    }

    memset(hn, 0, sizeof(hn));
    if (gethostname(hn, sizeof(hn)-1) < 0) {
        *errnop = errno;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    return fill_in_hostent(hn, af, host, buffer, buflen, errnop, h_errnop, ttlp, NULL);
}

enum nss_status
_nss_dummy_gethostbyaddr_r (const void *addr, socklen_t len, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
    DBG_TRACE;

    return _nss_dummy_gethostbyaddr2_r(addr, len, af, result, buffer, buflen, errnop, h_errnop, NULL);
}
