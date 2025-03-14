#include "libhw_svc/svc.h"
#include "libhw_svc/timer.h"
#include "libhw_svc/stdlist.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

/* global parameters */
#define CLI_GREET "[calc_cli]$"

struct svc_engine g_eng = {};

static struct option long_opts[] = {
    {"addr",    required_argument,  0,  'a'},
    {"help",    no_argument,        0,  'h'},
    {0,         0,                  0,   0 }
};

/* add print usage */
void print_usage(int exit_code) {
    printf("    %s: usage\n", g_eng.name);
    printf("    -a (--addr): server addres\n");
    printf("    -h (--help): print this message\n");
    exit(exit_code);
}

int parse_opts(int argc, char **params) {
    while(1) {
        int opt_index = 0;
        int c = getopt_long(argc, params, "ha:", long_opts, &opt_index);

        if (c == -1)
            break;

        switch (c) {
            case 'a':
                int res = inet_pton(AF_INET, optarg, &g_eng.addr);
                if (res <= 0) {
                    print_usage(1);
                }
                break;
            case 'h':
                print_usage(0);
                break;

            default:
                return ERR_OPTS;
        }
    }
    return ERR_OK;
}

int main(int argc, char *argv[]) {
    /* init service engine */    
    memset(&g_eng, 0, sizeof(g_eng));
    g_eng.name = argv[0];

    /* parse arguments */
    if (argc < 2)
        print_usage(1);

    if (parse_opts(argc, argv) != ERR_OK)
        print_usage(1);

    /* init self udp socket */
    struct sockaddr_in my_addr;
    init_addr(&my_addr, *(u32 *)g_eng.addr, htons(UDP_CLNT_PORT));

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (udp_fd < 0) 
        handle_error(strerror(udp_fd));

    int broadcast = 1;
    if (setsockopt(udp_fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0)
        handle_error("setsockopt error : udp_fd");

    if (bind(udp_fd, (struct sockaddr *) &my_addr, sizeof(my_addr)) == -1) 
        handle_error("bind: udp_fd");

    /* init udp broadcast socket */
    struct sockaddr_in other_addr;
    in_addr_t broadcast_addr = 0;
    
    init_addr(&other_addr, INADDR_BROADCAST, htons(UDP_SRV_PORT));
    inet_pton(AF_INET, "127.0.0.3", &broadcast_addr);
    printf("%x\n", broadcast_addr);
    other_addr.sin_addr.s_addr = broadcast_addr;

    struct server servers[MAX_SERVERS] = {};
    memset(servers, 0, sizeof(servers));
    u64 greet_seq_num = 0;

    /* init epoll events */
    struct epoll_event ev, events[EPOLL_MAX_EVTS];
    int epoll_fd = epoll_create1(0);

    ev.data.fd = udp_fd;
    ev.events = EPOLLIN | EPOLLOUT;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, udp_fd, &ev) == -1) 
        handle_error("epoll_ctl : udp_fd");
    
    /* init timer lst */
    struct lst_node *timer_lst = init_timer_lst();
    clock_t start = 0, elapsed = 0;

    /* send hello req flag*/
    u8 hello_send = 1;
    u8 hello_wait = 0;

    double task_start = 0;
    double task_end = 100;
    u8 task_send = 1;
    u8 task_recv = 0;

    /* event loop */
    start = clock();
    while (1) {

        int nfds = epoll_wait(epoll_fd, events, EPOLL_MAX_EVTS, EPOLL_TOUT);
        if (nfds == -1)
            handle_error("epoll_wait : epoll_fd");

        /* iterate trought the fds */
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == udp_fd) {
                /* checking broadcast channel */
                if (events[i].events & EPOLLOUT && hello_send) {
                    struct hello_msg_req req = {};
                    create_hello_req(&req, &my_addr, 0);
                    //fprintf(stdout, "sending broadcast req\n");
                    int r = sendto(udp_fd, &req, sizeof(req), 0,  (struct sockaddr*) &other_addr, sizeof(other_addr));
                    if (r < 0) {
                        perror("sendto : udp_fd");
                        continue;
                    } else {
                        /* add hello expired timer */
                        struct network_timer *timer = malloc(sizeof(struct network_timer));
                       // fprintf(stdout, "creating network timer %p, with %d, %d, %lu\n", timer, hello_send, hello_wait, greet_seq_num);
                        init_get_hello_resp_timer(timer, HELLO_RESP_TOUT, &hello_send, &hello_wait, &greet_seq_num, servers, MAX_SERVERS);
                        /* add timer to the timer list */
                        lst_add_head(timer_lst, &timer->node);
                        hello_send = 0;
                        hello_wait = 1;
                        continue;
                    }
                }

                if (events[i].events & EPOLLIN && hello_wait) {
                    /* get msg and add server */
                    fprintf(stdout, "getting response\n");
                    char buff[MAX_MSG_SIZE] = {};
                    struct sockaddr_in srv_addr;
                    int srv_len = 0;
                    int r = recvfrom(udp_fd, buff, sizeof(buff), 0, (struct sockaddr *) &srv_addr, &srv_len);
                    unsigned char addr[4] = {};
                    convert_sockaddr_to_addr(&srv_addr.sin_addr.s_addr, addr);
                    if (r != sizeof(struct hello_msg_resp)) {
                        fprintf(stderr, CLI_GREET" #hello msg response from " ADDR_FMT " has invalid size\n", ADDR_ARGS(addr));
                        continue;
                    } else {
                        /* add server to the configuration */
                        struct hello_msg_resp *resp = (struct hello_msg_resp *)buff;
                        /* check for resp status */
                        convert_sockaddr_to_addr(&resp->src.sin_addr.s_addr, addr);
                        fprintf(stdout, CLI_GREET " adding srv " ADDR_FMT " in configuration\n", ADDR_ARGS(addr));
                        init_server(&servers[addr[3]], resp->src.sin_addr.s_addr, servers[addr[3]].seq_num);
                        struct server* srv = &servers[addr[3]];
                        srv->status = STATUS_UNKNWON;
                        if (resp->resp_status == ERR_OK && validate_response((char *)resp, sizeof(*resp), greet_seq_num, HELLO_RESP) == ERR_OK) {
                            srv->status = STATUS_INACTIVE;
                            /* open tcp connection */
                            srv->tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                            if (srv->tcp_socket < 0) {
                                fprintf(stderr, CLI_GREET " can't create tcp socket for " ADDR_FMT "\n", ADDR_ARGS(addr));
                                perror("socket: tcp_fd");
                                srv->status = STATUS_UNKNWON;
                                continue;
                            } else {
                                /* set socket options to nonblocking */
                                if (fcntl(srv->tcp_socket, F_SETFL, O_NONBLOCK)) {
                                    fprintf(stderr, CLI_GREET " can't set tcp socket as NONBLOCKING for " ADDR_FMT "\n", ADDR_ARGS(addr));
                                    perror("fcntl: tcp_fd");
                                    srv->status = STATUS_UNKNWON;
                                    close(srv->tcp_socket);
                                    continue;
                                }

                                /* set socket option to kp alive*/
                                int keepalive = 1;
                                if (setsockopt(srv->tcp_socket, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive))) {
                                    fprintf(stderr, CLI_GREET " can't set tcp socket as KEEPALIVE for " ADDR_FMT "\n", ADDR_ARGS(addr));
                                    perror("setsockopt: tcp_fd");
                                    srv->status = STATUS_UNKNWON;
                                    close(srv->tcp_socket);
                                    continue;
                                }

                                if (bind(srv->tcp_socket, (struct sockaddr *) &my_addr, sizeof(my_addr)) == -1) {
                                    fprintf(stderr, CLI_GREET " can't bind tcp socket for " ADDR_FMT "\n", ADDR_ARGS(addr));
                                    perror("bind: tcp_fd");
                                    srv->status = STATUS_UNKNWON;
                                    close(srv->tcp_socket);
                                    continue;
                                }
                                srv_addr.sin_addr.s_addr = srv->addr;
                                srv_addr.sin_family = AF_INET;
                                srv_addr.sin_port = htons(TCP_SRV_PORT);

                                /* TODO: check retcode */
                                int err = 0;
                                if ((err = connect(srv->tcp_socket, (const struct sockaddr*)&srv_addr, sizeof(srv_addr))) != 0 && errno != EINPROGRESS) {
                                    fprintf(stderr, CLI_GREET " can't connect to socket " ADDR_FMT "\n", ADDR_ARGS(addr));
                                    perror("connect: tcp_fd");
                                    srv->status = STATUS_UNKNWON;
                                    close(srv->tcp_socket);
                                    continue;
                                }
                                
                                /*try to add server into epoll */
                                ev.data.fd = srv->tcp_socket;
                                ev.events = EPOLLIN | EPOLLOUT;
                                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, srv->tcp_socket, &ev) == -1) {
                                    fprintf(stderr, CLI_GREET " can't add socket to epoll " ADDR_FMT "\n", ADDR_ARGS(addr));
                                    perror("epoll_ctl: tcp_fd");
                                    srv->status = STATUS_UNKNWON;
                                    close(srv->tcp_socket);
                                    continue;
                                }

                                fprintf(stdout, CLI_GREET " srv " ADDR_FMT " succefully added in configuration\n", ADDR_ARGS(addr));
                            }

                        }
                    }
                }
            } else {
                /* checking tcp channels */
                /* find tcp connection and send task */
                int tcp_fd = events[i].data.fd;
                for (int j = 0; j < MAX_SERVERS; j++) {
                    struct server *srv = &servers[j];
                    //printf("%d : %d\n", srv->tcp_socket, events[i].data.fd);
                    if (srv->tcp_socket == events[i].data.fd) {
                        if (events[i].events & EPOLLOUT && task_send && srv->status == STATUS_INACTIVE) {
                            printf("sending task\n");
                            char buff[MAX_MSG_SIZE] = "test send\0";
                            int err = send(srv->tcp_socket, buff, sizeof(buff), 0);
                            if (err < 0 && errno == EINPROGRESS) {
                                printf("conn in progress, wait\n");
                                break;
                            }
                            if (err < 0) {
                                printf("bad msg\n");
                                perror("send: tcp_fd");
                                break;
                            }
                            srv->status = STATUS_ACTIVE;
                            task_send = 0;
                            task_recv = 1;
                            printf("task sent\n");
                            break;
                        }
                        if (events[i].events & EPOLLIN && task_recv) {
                            printf("recieving response\n");
                            char buff[MAX_MSG_SIZE] = {};
                            recv(srv->tcp_socket, buff, sizeof(buff), 0);
                            printf("%s\n", buff);
                            task_send = 0;
                            task_recv = 0;
                        }
                    }
                }

            }

        }
        elapsed = clock() - start;
        //fprintf(stdout, "event loop takes %u milliseconds to iterate, [%d:%d]\n", convert_to_msec(elapsed), elapsed, start);
        //check_timers(timer_lst, convert_to_msec(elapsed));
        check_timers(timer_lst, elapsed);
        start = clock();
        usleep(EPOLL_TOUT);
    }

    return 0;
}