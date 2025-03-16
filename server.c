#include "libhw_svc/svc.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>

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

/* add check for servers if broadcast timer expired */

int main(int argc, char *argv[]) {
    /* init service engine */    
    memset(&g_eng, 0, sizeof(g_eng));
    g_eng.name = argv[0];

    /* parse arguments */
    if (argc < 2)
        print_usage(1);

    if (parse_opts(argc, argv) != ERR_OK)
        print_usage(1);

    /* init self udp socket for recieving hello reqs */
    struct sockaddr_in my_addr;
    init_addr(&my_addr, *(u32 *)g_eng.addr, htons(UDP_SRV_PORT));
    fprintf(stdout, "SERVER ADDR " ADDR_FMT "\n", ADDR_ARGS(g_eng.addr));

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (udp_fd < 0) 
        handle_error(strerror(udp_fd));

    /*int broadcast = 1;

    if (setsockopt(udp_fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0)
        handle_error("setsockopt error : udp_fd");
    */

    if (bind(udp_fd, (struct sockaddr *) &my_addr, sizeof(my_addr)) == -1) 
        handle_error("bind :udp_fd");

    /* create tcp socket, so it can be used in future */
    int tcp_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (tcp_fd < 0)
        handle_error(strerror(tcp_fd));

    /* bind to my addr, tcp port */
    if (bind(tcp_fd, (struct sockaddr *) &my_addr, sizeof(my_addr)) == -1)
        handle_error("bind: tcp_fd");

    /* listen on tcp connection */
    if (listen(tcp_fd, SERVER_BACKLOG) == -1)
        handle_error("listen: tcp_fd");

    u64 greet_seq_num = 0;
    u64 calc_seq_num = 0;

    /* init epoll events */
    struct epoll_event ev, events[EPOLL_MAX_EVTS];
    int epoll_fd = epoll_create1(0);

    ev.data.fd = udp_fd;
    ev.events = EPOLLIN | EPOLLOUT;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, udp_fd, &ev) == -1) 
        handle_error("epoll_ctl : udp_fd");
    

    /* send hello req flag*/
    u8 hello_resp = 0;
    u8 hello_req = 1;
    
    /* client addres */
    unsigned char cli_addr[4] = {};
    struct sockaddr_in udp_sock = {}, tcp_sock = {};
    udp_sock.sin_port = htons(UDP_CLNT_PORT);
    udp_sock.sin_family = AF_INET;
    tcp_sock.sin_port = htons(TCP_CLNT_PORT);
    tcp_sock.sin_family = AF_INET;

    u8 task_send = 0;
    int connection_fd = -1;
    /* create list if connections */
    /* or leave on connection, but made it reusable */
    /* so if client get task done we can restart client and get it working */

    while (1) {

        int nfds = epoll_wait(epoll_fd, events, EPOLL_MAX_EVTS, EPOLL_TOUT);
        if (nfds == -1)
            handle_error("epoll_wait : epoll_fd");

        //printf("nfds %d\n", nfds);
        /* iterate trought the fds */
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == udp_fd) {
                /* checking broadcast channel */
                if (events[i].events != 4)
                    printf("%d\n", events->events);
                
                if (events[i].events & EPOLLIN && hello_req) {
                    /* get msg and add server */
                    fprintf(stdout, "getting response\n");
                    char buff[MAX_MSG_SIZE] = {};
                    struct sockaddr_in client_addr;
                    int addr_len = 0;
                    int r = recv(udp_fd, buff, sizeof(buff), 0);
                    printf("got response\n");
                    unsigned char *ad = NULL;
                    if (r != sizeof(struct hello_msg_req)) {
                        fprintf(stderr, "#hello msg request from " ADDR_FMT " has invalid size\n", ADDR_ARGS(cli_addr));
                        continue;
                    } else {
                        /* set flag to send response and save client addres */
                        struct hello_msg_req *req = (struct hello_msg_req *)buff;
                        ad = (unsigned char *)(&req->src.sin_addr.s_addr);
                        greet_seq_num = req->hdr.seq_num;
                        fprintf(stdout, "#setting send flag for response to " ADDR_FMT "\n", ADDR_ARGS(ad));
                        udp_sock.sin_addr.s_addr = req->src.sin_addr.s_addr;
                        tcp_sock.sin_addr.s_addr = req->src.sin_addr.s_addr;
                        hello_resp = 1;
                        continue;
                    }
                }
                if (events[i].events & EPOLLOUT && hello_resp) {
                    /* create response and send it to the client */
                    struct hello_msg_resp resp = {};
                    create_hello_resp(&resp, &my_addr, greet_seq_num, ERR_OK);
                    fprintf(stdout, "#sending response to client %x\n", udp_sock.sin_addr.s_addr);
                    int r = sendto(udp_fd, &resp, sizeof(resp), 0,  (struct sockaddr*) &udp_sock, sizeof(udp_sock));
                    if (r < 0) {
                        perror("sendto : udp_fd");
                        continue;
                    } else {
                        /* do nothing as we sent respone to the client */
                        fprintf(stdout, "#respone sent to the clinet\n");
                        hello_resp = 0;
                        /* accept tcp connection */
                        /* TODO: ADD ERROR HANDLING */
                        socklen_t len = sizeof(tcp_sock);
                        connection_fd = accept(tcp_fd, (struct sockaddr *)&tcp_sock, &len);
                        printf("#accept ret code %d, len %u, %d\n", connection_fd, len, tcp_fd);
                        if (connection_fd < 0)
                            perror("#accept: tcp_fd");
                        fprintf(stdout, "#connection accepted\n");
                        /*
                        char buff[MAX_MSG_SIZE] = {};
                        int rec = recv(connection_fd, buff, sizeof(buff), 0);
                        if (rec < 0)
                            perror("#recv tcp_fd");
                        printf("%s\n", buff);
                        */
                        ev.data.fd = connection_fd;
                        ev.events = EPOLLIN | EPOLLOUT;
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connection_fd, &ev) == -1) {
                            fprintf(stderr, "#can't add socket to epoll\n");
                            perror("epoll_ctl: tcp_fd");
                            continue;
                        }
                        printf("fd added into epoll\n");
                    }
                }
            } else {
                /* checking tcp channels */
                if (events[i].data.fd == connection_fd) {
                    if (events[i].events & EPOLLOUT && task_send) {
                        printf("sending response\n");
                        char buff[MAX_MSG_SIZE] = "test from server\0";
                        int sd = send(connection_fd, buff, sizeof(buff), 0);
                        if (sd < 0) {
                            perror("send: connectiond_fd");
                            continue;
                        }
                        printf("data sent\n");
                        task_send = 0;
                    }
                    if (events[i].events & EPOLLIN) {
                        printf("got buffer from cli\n");
                        char buff[MAX_MSG_SIZE] = {};
                        recv(connection_fd, buff, sizeof(buff), 0);
                        printf("%s\n", buff);
                        task_send = 1;
                    }
                }
            }

        }
    }

    return 0;
}