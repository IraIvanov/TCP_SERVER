#pragma once
#include "prot_types.h"
#include <arpa/inet.h>
#include <string.h>
#include <zlib.h>

#include <stdio.h>

#define UDP_CLNT_PORT 7000
#define TCP_CLNT_PORT 7000

#define UDP_SRV_PORT 7001
#define TCP_SRV_PORT 7001

#define MAGIK 0xDEADBEEF
#define VERSION 1

typedef enum svc_type_t {
    SRV  = 1,
    CLNT = 2,
} svc_type;

struct svc_engine {
    unsigned svc_version;
    unsigned svc_type;
    unsigned char addr[sizeof(struct in_addr)];
    char *name;
};

#define STATUS_UNINITIALIZED 0
#define STATUS_UNKNWON  0x1
#define STATUS_INACTIVE 0x2
#define STATUS_ACTIVE   0x4
#define STATUS_DEAD     0x8

/* rewrite */
/* add timer into server struct, so we can initialize timer in server and get server as container_of timer */
struct server {
    u32 addr;
    u64 seq_num;
    u8 status;
    int tcp_socket;
    double task_start;
    double task_end;
};

/* MESSAGES */
typedef enum msg_type_t {
    HELLO_REQ  = 1,
    HELLO_RESP = 2,
    CALC_REQ   = 3,
    CALC_RESP  = 4,
} msg_type;

struct __attribute__ ((__packed__)) msg_header {
    u32         version;
    u32         magik;
    msg_type    type;
    u64         chk_sum; /* checksum for whole message */
    u64         seq_num;
};

struct __attribute__ ((__packed__)) hello_msg_req {
    struct msg_header hdr;
    struct sockaddr_in src;
};

struct __attribute__ ((__packed__)) hello_msg_resp {
    struct msg_header hdr;
    struct sockaddr_in src;
    u64 resp_status;
};

struct __attribute__ ((__packed__)) calc_msg_req {
    struct msg_header hdr;
    /* append */
    double start;
    double end;
};

struct __attribute__ ((__packed__)) calc_msg_resp {
    struct msg_header hdr;
    /* append */
    double result;
    u64 resp_status;
};

#define EPOLL_MAX_EVTS  10
#define EPOLL_TOUT      100
#define MAX_MSG_SIZE    128 
#define MAX_SERVERS     256

#define SERVER_BACKLOG 5

static inline void init_addr(struct sockaddr_in* sock, u32 addr, u16 port) {
    memset(sock, 0, sizeof(*sock));
    sock->sin_addr.s_addr = addr;
    sock->sin_family = AF_INET;
    sock->sin_port = port;
}

#define convert_sockaddr_to_addr(sock_addr, addr) \
    memcpy((addr), (sock_addr), sizeof(addr))


#define convert_addr_to_sockaddr(addr, sock_addr) \
    memcpy((sock_addr), (addr), sizeof(sock_addr))


#define ADDR_FMT "%u.%u.%u.%u"

#define ADDR_ARGS(addr) addr[0], addr[1], addr[2], addr[3]

static inline void init_msg_header(struct msg_header *hdr, msg_type type, u64 seq_num) {
    memset(hdr, 0, sizeof(*hdr));
    hdr->version = VERSION;
    hdr->magik = MAGIK;
    hdr->type = type;
    hdr->seq_num = seq_num;
}

static inline void create_hello_req(struct hello_msg_req *req, struct sockaddr_in *src, u64 seq_num) {
    u64 crc = crc32(0L, Z_NULL, 0);
    init_msg_header((struct msg_header *)req, HELLO_REQ, seq_num);
    memcpy(&req->src, src, sizeof(*src));
    crc = crc32(crc, (const unsigned char *)req, sizeof(*req));
    req->hdr.chk_sum = crc;
}

static inline void create_hello_resp(struct hello_msg_resp *resp, struct sockaddr_in *src, u64 seq_num, u64 resp_status) {
    u64 crc = crc32(0L, Z_NULL, 0);
    init_msg_header((struct msg_header *)resp, HELLO_RESP, seq_num);
    memcpy(&resp->src, src, sizeof(*src));
    resp->resp_status = resp_status;
    crc = crc32(crc, (const unsigned char *)resp, sizeof(*resp));
    resp->hdr.chk_sum = crc;
}

static inline void create_calc_req(struct calc_msg_req *req, double start, double end, u64 seq_num) {
    u64 crc = crc32(0L, Z_NULL, 0);
    init_msg_header((struct msg_header *)req, CALC_REQ, seq_num);
    req->start = start;
    req->end = end;
    crc = crc32(crc, (const unsigned char *)req, sizeof(*req));
    req->hdr.chk_sum = crc;
}

static inline void create_calc_resp(struct calc_msg_resp *resp, double result, u64 seq_num, u64 resp_status) {
    u64 crc = crc32(0L, Z_NULL, 0);
    init_msg_header((struct msg_header *)resp, CALC_RESP, seq_num);
    resp->result = result;
    resp->resp_status = resp_status;
    crc = crc32(crc, (const unsigned char *)resp, sizeof(*resp));
    resp->hdr.chk_sum = crc;
}

static inline void init_server(struct server *srv, u32 addr, u64 seq_num) {
    memset(srv, 0, sizeof(*srv));
    srv->addr = addr;
    srv->status = STATUS_UNKNWON;
    srv->seq_num = seq_num;
}

static inline int sock_cmp(struct sockaddr_in sock1, struct sockaddr_in sock2) {
    return sock1.sin_addr.s_addr == sock2.sin_addr.s_addr && sock1.sin_port == sock2.sin_port;
}

int has_alive_servers(struct server *servers, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (servers[i].status == STATUS_ACTIVE || servers[i].status == STATUS_INACTIVE) {
            printf("found alive server\n");
            return 1;
        }
    }
    return 0;
}

int validate_response(char *buf, size_t len, u64 seq_num, msg_type type) {
    if (len < sizeof(struct msg_header))
        return ERR_INVALID;

    struct msg_header *hdr = (struct msg_header *)buf;
    if (hdr->type != type)
        return ERR_INVALID;
    
    if (hdr->magik != MAGIK)
        return ERR_INVALID;
    
    if (hdr->version > VERSION)
        return ERR_INVALID;

    if (hdr->seq_num != seq_num)
        return ERR_INVALID;

    u64 chk_sum = hdr->chk_sum;
    hdr->chk_sum = 0;
    u64 crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const unsigned char *)buf, len);
    hdr->chk_sum = chk_sum;
    if (chk_sum != crc) {
        printf("invalid chk_sum\n");
        return ERR_INVALID;
    }
    
    return ERR_OK;
}