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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "rattler.h"

#define STR1(x) #x
#define STR(x) STR1(x)

static void
service_cmd(rattler_cmd *cmd, int argc, char **argv)
{
    RATTLER_UNUSED(cmd);

    if (argc < 1) {
        // run the manager daemon
        return;
    }

    const char *sub_cmd = argv[0];

    if (strcmp(sub_cmd, "create") == 0) {
        // 
    } else if (strcmp(sub_cmd, "ls") == 0) {
        //
    } else if (strcmp(sub_cmd, "inspect") == 0) {
        //
    } else if (strcmp(sub_cmd, "rm") == 0) {
        //
    } else if (strcmp(sub_cmd, "scale") == 0) {
        //
    } else {
        fprintf(stderr, "error: unknown subcommand: %s\n", sub_cmd);
    }
}

static void
node_cmd(rattler_cmd *cmd, int argc, char **argv)
{
    RATTLER_UNUSED(cmd);

    if (argc < 1) {
        // run the worker daemon
        return;
    }

    const char *sub_cmd = argv[0];

    if (strcmp(sub_cmd, "ls") == 0) {
        // 
    } else {
        fprintf(stderr, "error: unknown subcommand: %s\n", sub_cmd);
    }
}

int
main(int argc, char **argv)
{
    rattler_cmd *root = rattler_new_command(
        "legion [command]", "rattler feature demo", "");
    rattler_set_version(root, STR(legion_version));
    rattler_persistent_bool(root, "verbose", 'v', false, "verbose output");

    rattler_cmd *service = rattler_new_command(
        "service [create|ls]",
        "Manage the legion services",
        "service manages the legion services.\n"
        "Some commands require additional arguments, such as create or ls.\n");
    service->cmd = service_cmd;
    rattler_add_command(root, service);

    rattler_cmd *node = rattler_new_command(
        "node [ls]",
        "Manage the legion nodes",
        "node manages the legion nodes.\n"
        "Some commands require additional arguments, such as ls.\n");
    node->cmd = node_cmd;
    rattler_add_command(root, node);

    rattler_execute(root, argc, argv);
    rattler_free(root);

    return 0;
}
