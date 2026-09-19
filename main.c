/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Brian J. Downs
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <logger.h>
#include <papago.h>
#include <rattler.h>

#include "db.h"
#include "manager.h"
#include "worker.h"

#define STR1(x) #x
#define STR(x) STR1(x)

enum {
    LEGION_CMD_MANAGER = 0,
    LEGION_CMD_WORKER,
} ;

static int legion_cmd = -1;

static void
manager_cmd(rattler_cmd *cmd, int argc, char **argv)
{
    RATTLER_UNUSED(cmd);

    if (argc < 1) {
        manager_init();
        manager_start();

        return;
    }

    const char *sub_cmd = argv[0];

    if (strcmp(sub_cmd, "init") == 0) {
        s_log(S_LOG_INFO, 
            s_log_string("msg", "bootstrapping legion manager"));

        manager_bootstrap();
    } else {
        fprintf(stderr, "error: unknown subcommand: %s\n", sub_cmd);
    }
}

static void
worker_cmd(rattler_cmd *cmd, int argc, char **argv)
{
    const char *port = rattler_flag_string(cmd, "port");
    if (port == NULL || port[0] == '\0') {
        fprintf(stderr, "error: manager port is required\n");
        exit(1);
    }

    const char *server = rattler_flag_string(cmd, "server");
    if (server == NULL || server[0] == '\0') {
        fprintf(stderr, "error: manager address is required\n");
        exit(1);
    }

    const char *token = rattler_flag_string(cmd, "token");
    if (token == NULL || token[0] == '\0') {
        fprintf(stderr, "error: token is required\n");
        exit(1);
    }

    const char *listen_addr = rattler_flag_string(cmd, "listen-addr");
    if (port == NULL || port[0] == '\0') {
        fprintf(stderr, "error: worker listen address is required\n");
        exit(1);
    }

    worker_config_t config = {
        .server = (char*)server,
        .port = (char*)port,
        .token = (char*)token,
        .listen_addr = (char*)listen_addr
    };

    if (argc < 1) {
        worker_start(&config);
        return;
    }

    const char *sub_cmd = argv[0];

    if (strcmp(sub_cmd, "join") == 0) {
        s_log(S_LOG_INFO, 
            s_log_string("msg", "bootstrapping legion worker"));

        worker_bootstrap(&config);

        // POST token to manager and get CA if not exists
        // start http server
        // open websocket to manager over mTLS 
    } else {
        fprintf(stderr, "error: unknown subcommand: %s\n", sub_cmd);
    }
}

/**
 * Signal handler for graceful shutdown
 */
static void
signal_handler(int sig)
{
    (void)sig;

    if (legion_cmd == LEGION_CMD_MANAGER) {
        manager_stop();
    } else if (legion_cmd == LEGION_CMD_WORKER) {
        worker_stop();
    }

    exit(0);
}

int
main(int argc, char **argv)
{
    // setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    s_log_init(stdout);

    rattler_cmd *root = rattler_new_command(
        "legion [command]", "rattler feature demo", "");
    rattler_set_version(root, STR(legion_version));
    rattler_persistent_bool(root, "verbose", 'v', false, "verbose output");

    rattler_cmd *manager = rattler_new_command(
        "manager [init]",
        "Manage the legion system",
        "manager runs the legion manager daemon.\n"
        "Some commands require additional arguments, such as init.\n");
    manager->cmd = manager_cmd;
    rattler_add_command(root, manager);

    rattler_cmd *worker = rattler_new_command(
        "worker [join]",
        "Run a legion worker",
        "worker runs the legion worker daemon.\n"
        "Some commands require additional arguments, such as join.\n");
    worker->cmd = worker_cmd;
    rattler_flags_string(worker, "listen-addr", 'l', "", "listen address");
    rattler_flags_string(worker, "port", 'p', "", "manager port");
    rattler_flags_string(worker, "server", 's', "", "manager address");
    rattler_flags_string(worker, "token", 't', "", "legion join token");
    rattler_add_command(root, worker);

    rattler_execute(root, argc, argv);
    rattler_free(root);

    return 0;
}
