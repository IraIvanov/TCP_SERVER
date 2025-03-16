/* timer should be implemented as in https://stackoverflow.com/questions/17167949/how-to-use-timer-in-c example */
#pragma once

#include "stdlist.h"
#include "prot_types.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include "svc.h"

typedef enum timer_type_t {
    HELLO_MSG_TIMER = 0,
    CALCULATE_MSG_TIMER = 1,
} timer_type;

struct network_timer {
    int timer; /* original time, measured in milliseconds */
    int time_left; /* measured in milliseconds */
    struct lst_node node;
    struct sockaddr_in sock;
    timer_type type;
    void (*handler)(void *);
    void *args;
};

void init_timer (struct network_timer *timer, timer_type type, int time, struct sockaddr_in sock, void (*handler)(void*)) {
    timer->timer = timer->time_left = time;
    memcpy(&timer->sock, &sock, sizeof(sock));
    timer->type = type;
    timer->handler = handler;
}

void check_timers(struct lst_node *timer_lst, int elapsed) {
    struct network_timer *timer = NULL, *next = NULL;
    timer = lst_entry(timer_lst, struct network_timer, node);
    for_each_lst_entry_safe(timer_lst, timer, next, struct network_timer, node) {
        timer->time_left -= elapsed;
        if (timer->time_left < 0) {
           /* call handler and delete expired timer */
           timer->handler(timer->args);
           lst_del(&timer->node);
           free(timer);
        }
    }
}

struct lst_node *init_timer_lst(void) {
    struct network_timer *timer =  (struct network_timer *)malloc(sizeof(struct network_timer));
    memset(timer, 0, sizeof(*timer));
    lst_init(&timer->node);
    return &timer->node;
}

int del_timer_lst(struct lst_node *node) {
    struct network_timer *timer = lst_entry(node, struct network_timer, node);
    if (!lst_is_empty(node))
        return -ERR_INVALID;

    free(timer);
    return ERR_OK;
}

#define convert_to_msec(elapsed) (((elapsed) * 1000) / CLOCKS_PER_SEC)

struct hello_timer_args {
    u8 *hello_send;
    u8 *hello_wait;
    u8 *task_send;
    u64 *seq_num;
    struct server *srv_lst;
    size_t len;
    double start;
    double end;
    u8 *srv_cnt;
};

/* hello timer expired handler */
void hello_timer_handler(void *args) {
    struct hello_timer_args *hello_args = (struct hello_timer_args *)args;
    *hello_args->hello_wait = 0;
    (*hello_args->seq_num)++;
    *hello_args->hello_send = has_alive_servers(hello_args->srv_lst, hello_args->len) ? 0 : 1;
    if (!*hello_args->hello_send)
        *hello_args->task_send = 1;
    else
        goto cleanup;

    /* assign tasks */
    double step = (hello_args->end - hello_args->start) / *hello_args->srv_cnt;
    double loc_start = hello_args->start;
    double loc_end = hello_args->start + step;
    u8 tasks_assigned = 0;
    u8 srv_cnt = *hello_args->srv_cnt;
    for (int i = 0; i < hello_args->len && tasks_assigned < srv_cnt; i++) {
        struct server* srv = &hello_args->srv_lst[i];
        if (srv->status == STATUS_INACTIVE) {
            srv->task_start = loc_start;
            srv->task_end = loc_end;
            loc_start += step;
            loc_end += step;
            tasks_assigned++;
        }
    }
cleanup:
    free(args);
}

void init_get_hello_resp_timer(struct network_timer *timer, int time, u8 *hello_send, u8 *hello_wait, u8 *task_send, u64 *seq_num, struct server *srv_lst, size_t len, 
                                double start, double end, u8 *srv_cnt)
{
    struct sockaddr_in sock = {};
    init_timer(timer, HELLO_MSG_TIMER, time, sock, hello_timer_handler);
    struct hello_timer_args *args = (struct hello_timer_args *)malloc(sizeof(struct hello_timer_args));
    memset(args, 0, sizeof(*args));
    args->hello_send = hello_send;
    args->hello_wait = hello_wait;
    args->seq_num = seq_num;
    args->srv_lst = srv_lst;
    args->len = len;
    args->task_send = task_send;
    args->start = start;
    args->end = end;
    args->srv_cnt = srv_cnt;
    timer->args = (void *)args;
}

#define HELLO_RESP_TOUT 1000 /* 1 sec */

/* create calc timer */
/* as hanlder timer should switch server's state to dead and find new server to do task */
/* if no servers alive create hello send msg */
struct calc_timer_args {
    struct server* srv;
    struct server* srv_lst;
    size_t len;
    u8 *hello_send;
    u8 *task_send;
    u8 *srv_cnt;
};

/* close connection, set status to unknown, increment seq_num*/
void calc_timer_handler(void *args) {
    struct calc_timer_args *calc_args = (struct calc_timer_args *)args;
    calc_args->srv->seq_num++;
    close(calc_args->srv->tcp_socket);
    calc_args->srv->timer = NULL;
    calc_args->srv->status = STATUS_DEAD;
    double task_start = calc_args->srv->task_start;
    double task_end = calc_args->srv->task_end;
    (*calc_args->srv_cnt)--;
    if (!*calc_args->srv_cnt)
        goto cleanup;

    for (size_t i = 0; i < calc_args->len; i++) {
        /* assign task to free server */
        struct server *worker = &calc_args->srv_lst[i];
        if (worker->status == STATUS_INACTIVE) {
            worker->task_start = task_start;
            worker->task_end = task_end;
            *calc_args->task_send = 1;
            break;
        }
    }

cleanup:
    free(args);
}

void init_get_calc_resp_timer(struct network_timer *timer, int time, u8 *hello_send, u8 *task_send, struct server *srv, struct server* srv_lst, size_t len, u8 *srv_cnt) {
    struct sockaddr_in sock = {};
    init_timer(timer, CALCULATE_MSG_TIMER, time, sock, calc_timer_handler);
    struct calc_timer_args *args = (struct calc_timer_args *)malloc(sizeof(struct calc_timer_args));
    memset(args, 0, sizeof(*args));
    args->hello_send = hello_send;
    args->task_send = task_send;
    args->srv = srv;
    args->srv_lst = srv_lst;
    args->len = len;
    args->srv_cnt = srv_cnt;
    timer->args = (void *)args;
}