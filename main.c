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

#include "agent.h"
#include "db.h"
#include "server.h"

#define STR1(x) #x
#define STR(x) STR1(x)

enum {
    LEGION_CMD_SERVER = 0,
    LEGION_CMD_AGENT,
};

static int legion_cmd = -1;

static void
server_cmd(rattler_cmd *cmd, int argc, char **argv)
{
    RATTLER_UNUSED(cmd);

    if (argc < 1) {
        server_init();
        server_start();

        return;
    }

    const char *sub_cmd = argv[0];

    if (strcmp(sub_cmd, "init") == 0) {
        s_log(S_LOG_INFO, 
            s_log_string("msg", "bootstrapping legion server"));

        server_bootstrap();
    } else {
        s_log(S_LOG_ERROR, s_log_string("msg", "unknown subcommand"),
              s_log_string("cmd", sub_cmd));
    }
}

static void
agent_cmd(rattler_cmd *cmd, int argc, char **argv)
{
    const char *port = rattler_flag_string(cmd, "port");
    if (port == NULL || port[0] == '\0') {
        fprintf(stderr, "error: server port is required\n");
        exit(1);
    }

    const char *server = rattler_flag_string(cmd, "server");
    if (server == NULL || server[0] == '\0') {
        fprintf(stderr, "error: server address is required\n");
        exit(1);
    }

    const char *listen_addr = rattler_flag_string(cmd, "listen-addr");
    if (listen_addr == NULL || listen_addr[0] == '\0') {
        fprintf(stderr, "error: agent listen address is required\n");
        exit(1);
    }

    if (argc < 1) {
        const char *cacert = rattler_flag_string(cmd, "ca-cert");
        if (cacert == NULL || cacert[0] == '\0') {
            fprintf(stderr, "error: ca-cert required\n");
            exit(1);
        }

        const char *cert = rattler_flag_string(cmd, "cert");
        if (cert == NULL || cert[0] == '\0') {
            fprintf(stderr, "error: cert required\n");
            exit(1);
        }

        const char *key = rattler_flag_string(cmd, "key");
        if (key == NULL || key[0] == '\0') {
            fprintf(stderr, "error: key required\n");
            exit(1);
        }

        agent_config_t config = {
            .cacert = (char*)cacert,
            .cert = (char*)cert,
            .key = (char*)key,
            .server = (char*)server,
            .port = (char*)port,
            .listen_addr = (char*)listen_addr
        };

        agent_start(&config);
        return;
    }

    const char *sub_cmd = argv[0];

    if (strcmp(sub_cmd, "join") == 0) {
        const char *token = rattler_flag_string(cmd, "token");
        if (token == NULL || token[0] == '\0') {
            fprintf(stderr, "error: token is required\n");
            exit(1);
        }

        agent_config_t config = {
            .server = (char*)server,
            .port = (char*)port,
            .token = (char*)token,
            .listen_addr = (char*)listen_addr
        };

        agent_bootstrap(&config);
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

    if (legion_cmd == LEGION_CMD_SERVER) {
        server_stop();
    } else if (legion_cmd == LEGION_CMD_AGENT) {
        agent_stop();
    }

    exit(0);
}

int
main(int argc, char **argv)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    s_log_init(stdout);

    rattler_cmd *root = rattler_new_command(
        "legion [command]", "rattler feature demo", "");
    rattler_set_version(root, STR(legion_version));
    rattler_persistent_bool(root, "verbose", 'v', false, "verbose output");

    rattler_cmd *server = rattler_new_command(
        "server [init]",
        "Manage the legion system",
        "server runs the legion server daemon.\n"
        "Some commands require additional arguments, such as init.\n");
    server->cmd = server_cmd;
    rattler_add_command(root, server);

    rattler_cmd *agent = rattler_new_command(
        "agent [join]",
        "Run a legion agent",
        "agent runs the legion agent daemon.\n"
        "Some commands require additional arguments, such as join.\n");
    agent->cmd = agent_cmd;
    rattler_flags_string(agent, "ca-cert", 'C', "", "cert");
    rattler_flags_string(agent, "cert", 'c', "", "cert");
    rattler_flags_string(agent, "key", 'k', "", "key");
    rattler_flags_string(agent, "listen-addr", 'l', "", "listen address");
    rattler_flags_string(agent, "port", 'p', "", "server port");
    rattler_flags_string(agent, "server", 's', "", "server address");
    rattler_flags_string(agent, "token", 't', "", "legion join token (only on join)");
    rattler_add_command(root, agent);

    rattler_execute(root, argc, argv);
    rattler_free(root);

    return 0;
}
