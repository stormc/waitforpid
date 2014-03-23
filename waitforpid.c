/************************************************************************
 * waitforpid - wait for a (non-child) process' exit using Linux's
 *              PROC_EVENTS and POSIX capabilities.
 *
 * Copyright (C) 2014 Christian Storm <christian.storm@tngtech.com>
 *
 *
 * Inspired by startmon (http://github.com/pturmel/startmon)
 * Copyright (C) 2011 Philip J. Turmel <philip@turmel.org>
 * which was inspired by a blog entry by Scott James Remnant:
 * http://netsplit.com/2011/02/09/the-proc-connector-and-socket-filters/
 *
 *
 * Inspired by exec-notify (http://www.suse.de/~krahmer/exec-notify.c)
 * (C) 2007-2010 Sebastian Krahmer <krahmer@suse.de>
 * which took the original netlink handling from an proc-connector example
 * Copyright (C) Matt Helsley, IBM Corp. 2005
 * Derived from fcctl.c by Guillaume Thouvenin
 * Original copyright notice follows:
 * Copyright (C) 2005 BULL SA.
 * Written by Guillaume Thouvenin <guillaume.thouvenin@bull.net>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 ***********************************************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <fcntl.h>
#include <grp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/capability.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <errno.h>

#define max(x,y) ((y)<(x)?(x):(y))

#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(struct proc_event)))

#define SEND_MESSAGE_SIZE (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE (NLMSG_SPACE(RECV_MESSAGE_LEN))

#define RECEIVING_BUFFER_SIZE (max(max(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))

#define PROC_CN_MCAST_LISTEN (1)
#define PROC_CN_MCAST_IGNORE (2)

#define EXIT_FAIL(...) \
    (void)fprintf(stderr,__VA_ARGS__); \
    exit(EXIT_FAILURE)

#define EXIT_OK() \
    exit(EXIT_SUCCESS)

static int nl_socket = -1;
static cap_t capabilities = NULL;

static void close_socket() {
    if (nl_socket != -1) {
        (void)close(nl_socket);
    }
}

static void free_capabilities() {
    if (capabilities != NULL) {
        (void)cap_free(capabilities);
    }
}

static void signal_handler(const int sig) {
    switch(sig){
        case SIGINT:
        case SIGTERM:
        case SIGQUIT:
            close_socket();
            free_capabilities();
            EXIT_OK();
        default:
            fprintf(stderr, "Received an unhandled signal %d\n", sig);
            break;
    }
}

static void acquire_privileges(char* executablefile) {
    cap_value_t cap_list[1] = { CAP_NET_ADMIN };
    cap_flag_value_t cap_flags_value;

    if (!CAP_IS_SUPPORTED(CAP_NET_ADMIN)) {
        EXIT_FAIL("Capability CAP_NET_ADMIN is not supported\n");
    }

    // Check that being executed without unnecessary suid root flag
    if (geteuid() != getuid() && geteuid() == 0) {
        EXIT_FAIL("eUID=0 != UID=%d, run\n" \
            " chmod a-s %s;\n" \
            " setcap CAP_NET_ADMIN=p %s\n" \
            "and execute as normal user\n", getuid(), executablefile, executablefile);
    }
    if (getegid() != getgid() && getegid() == 0) {
        EXIT_FAIL("eGID=0 != GID=%d, run\n" \
            " chmod a-s %s;\n" \
            " setcap CAP_NET_ADMIN=p %s\n" \
            "and execute as normal user\n", getgid(), executablefile, executablefile);
    }

    capabilities = cap_get_proc();
    if (capabilities == NULL) {
        EXIT_FAIL("Cannot get capabilities\n");
    }

    // Ensure that CAP_NET_ADMIN is permitted
    if (cap_get_flag(capabilities, cap_list[0], CAP_PERMITTED, &cap_flags_value) == -1) {
        EXIT_FAIL("Cannot get CAP_PERMITTED flag value of capability CAP_NET_ADMIN\n");
    }
    if (cap_flags_value == CAP_CLEAR) {
        EXIT_FAIL("Capability CAP_NET_ADMIN is not CAP_PERMITTED, run setcap CAP_NET_ADMIN=p %s\n", executablefile);
    }

    // Test if CAP_NET_ADMIN is effective, else make it effective
    if (cap_get_flag(capabilities, cap_list[0], CAP_EFFECTIVE, &cap_flags_value) == -1) {
        EXIT_FAIL("Cannot get CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
    }
    if (cap_flags_value == CAP_CLEAR) {
        if (cap_set_flag(capabilities, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1) {
            EXIT_FAIL("Cannot set CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
        }
        if (cap_set_proc(capabilities) == -1){
            EXIT_FAIL("Cannot set capability CAP_NET_ADMIN to CAP_EFFECTIVE\n");
        }
        if (cap_get_flag(capabilities, cap_list[0], CAP_EFFECTIVE, &cap_flags_value) == -1) {
            EXIT_FAIL("Cannot get CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
        }
        if (cap_flags_value == CAP_CLEAR) {
            EXIT_FAIL("Failed to set capability CAP_NET_ADMIN to CAP_EFFECTIVE\n");
        }
    }
    (void)cap_free(capabilities);
    capabilities = NULL;
}

static void drop_privileges() {
    cap_value_t cap_list[1] = { CAP_NET_ADMIN };
    cap_flag_value_t cap_flags_value;

    capabilities = cap_get_proc();
    if (capabilities == NULL) {
        EXIT_FAIL("Cannot get capabilities\n");
    }
    if (cap_get_flag(capabilities, cap_list[0], CAP_EFFECTIVE, &cap_flags_value) == -1) {
        EXIT_FAIL("Cannot get CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
    }

    // Drop CAP_NET_ADMIN to permitted if it's effective
    if (cap_flags_value == CAP_SET) {
        if (cap_set_flag(capabilities, CAP_EFFECTIVE, 1, cap_list, CAP_CLEAR) == -1) {
            EXIT_FAIL("Cannot clear CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
        }
        if (cap_set_proc(capabilities) == -1){
            EXIT_FAIL("Cannot set capability CAP_NET_ADMIN to CAP_EFFECTIVE\n");
        }
        if (cap_get_flag(capabilities, cap_list[0], CAP_PERMITTED, &cap_flags_value) == -1) {
            EXIT_FAIL("Cannot get CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
        }
        if (cap_flags_value == CAP_CLEAR) {
            EXIT_FAIL("Failed to drop capability CAP_NET_ADMIN privileges to CAP_PERMITTED\n");
        }
    }
    (void)cap_free(capabilities);
    capabilities = NULL;
}

int main(int argc, char **argv) {
    // register cleanup functions to be called on exit()
    atexit(close_socket);
    atexit(free_capabilities);

    // Ensure that PID is given as parameter and remember its value
    if (argc != 2) {
        EXIT_FAIL("Usage: %s <PID>\n", argv[0]);
    }
    __kernel_pid_t watchpid = strtol(argv[1], NULL , 10);
    if (errno == ERANGE) {
        EXIT_FAIL("Cannot convert parameter to integer: %s\n", strerror(errno));
    }

    // Check that directory /proc/<PID>/ exists
    struct stat sb;
    char *procname = NULL;
    if (asprintf(&procname, "/proc/%d", watchpid) == -1) {
        EXIT_FAIL("Cannot allocate memory\n");
    }
    if (stat(procname, &sb) == -1) {
        free(procname);
        EXIT_FAIL("Cannot determine stat information for /proc/%d: %s\n", watchpid, strerror(errno));
    }
    free(procname);
    if (!S_ISDIR(sb.st_mode)) {
        EXIT_FAIL("PID %d unknown as directory /proc/%d does not exist\n", watchpid, watchpid);
    }

    // Make CAP_NET_ADMIN capability effective
    acquire_privileges(argv[0]);

    // Create the netlink socket
    nl_socket = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
    if (nl_socket == -1) {
        EXIT_FAIL("Unable to open a netlink socket: %s\n", strerror(errno));
    }

    // Attach to the process connector
    struct sockaddr_nl nl_sock_addr;
    memset(&nl_sock_addr, 0, sizeof(nl_sock_addr));
    nl_sock_addr.nl_family = AF_NETLINK;
    nl_sock_addr.nl_groups = CN_IDX_PROC;
    nl_sock_addr.nl_pid = getpid();
    if (bind(nl_socket, (struct sockaddr *)&nl_sock_addr, sizeof(nl_sock_addr)) == -1) {
        EXIT_FAIL("Unable to bind to the process connector: %s\n", strerror(errno));
    }

    // Allocate the receive buffer
    void *rcv_buffer = malloc(RECEIVING_BUFFER_SIZE);
    if (!rcv_buffer) {
        EXIT_FAIL("Unable to allocate receive buffer memory\n");
    }
    memset(rcv_buffer, 0, RECEIVING_BUFFER_SIZE);

    // Send PROC_CN_MCAST_LISTEN to the proc connector
    struct nlmsghdr *nl_msg_header = (struct nlmsghdr *)rcv_buffer;
    nl_msg_header->nlmsg_len = SEND_MESSAGE_LEN;
    nl_msg_header->nlmsg_type = NLMSG_DONE;
    nl_msg_header->nlmsg_flags = 0;
    nl_msg_header->nlmsg_seq = 0;
    nl_msg_header->nlmsg_pid = getpid();

    struct cn_msg *cn_msg_header = (struct cn_msg *)NLMSG_DATA(nl_msg_header);
    cn_msg_header->id.idx = CN_IDX_PROC;
    cn_msg_header->id.val = CN_VAL_PROC;
    cn_msg_header->seq = 0;
    cn_msg_header->ack = 0;
    cn_msg_header->len = sizeof(enum proc_cn_mcast_op);

    enum proc_cn_mcast_op *cn_msg_mcast_op = (enum proc_cn_mcast_op*)&cn_msg_header->data[0];

    *cn_msg_mcast_op = PROC_CN_MCAST_LISTEN;
    if (send(nl_socket, nl_msg_header, nl_msg_header->nlmsg_len, 0) != nl_msg_header->nlmsg_len) {
        EXIT_FAIL("Failed to send PROC_CN_MCAST_LISTEN: %s\n", strerror(errno));
    }
    if (*cn_msg_mcast_op == PROC_CN_MCAST_IGNORE) {
        EXIT_FAIL("Got PROC_CN_MCAST_IGNORE\n");
    }

    // Drop CAP_NET_ADMIN capability
    drop_privileges();

    // Install signal handler
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (   (sigaction(SIGINT,  &sa, NULL) == -1) \
        || (sigaction(SIGTERM, &sa, NULL) == -1) \
        || (sigaction(SIGQUIT, &sa, NULL) == -1) ) {
        EXIT_FAIL("Cannot install signal handler: %s", strerror(errno));
    }

    // Message loop
    while (1) {
        socklen_t nl_sock_len = sizeof(nl_sock_addr);
        ssize_t rcv_msg_len = recvfrom(nl_socket, rcv_buffer, RECEIVING_BUFFER_SIZE, 0, (struct sockaddr *)&nl_sock_addr, &nl_sock_len);
        switch (rcv_msg_len) {
            case -1:
                EXIT_FAIL("Error while receiving message: %s\n", strerror(errno));
            case 0:
                EXIT_FAIL("Peer has shut down\n");
        }
        if (nl_sock_addr.nl_pid != 0) { continue; }
        for (nl_msg_header=rcv_buffer; NLMSG_OK(nl_msg_header, rcv_msg_len); nl_msg_header=NLMSG_NEXT(nl_msg_header, rcv_msg_len)) {
            switch (nl_msg_header->nlmsg_type) {
                case NLMSG_ERROR:
                case NLMSG_NOOP:
                case NLMSG_OVERRUN:
                    continue;
            }
            cn_msg_header = NLMSG_DATA(nl_msg_header);
            if (cn_msg_header->id.idx != CN_IDX_PROC || cn_msg_header->id.val != CN_VAL_PROC) { continue; }
            struct proc_event *pe = (struct proc_event *)cn_msg_header->data;
            if (pe->what == PROC_EVENT_EXIT && pe->event_data.exit.process_pid == watchpid) {
                printf("PID=%d\nEXITCODE=%d\nSIGNAL=%d\n",
                    pe->event_data.exit.process_pid,
                    pe->event_data.exit.exit_code,
                    pe->event_data.exit.exit_signal);
                EXIT_OK();
            }
        }
    }
}
