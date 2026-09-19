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

#ifndef __NODE_H
#define __NODE_H

#include <sys/stat.h>

#define TOKEN_ID_CHARS 6
#define TOKEN_SECRET_CHARS 16
#define TOKEN_MAX_LEN 256  // K10 + 64 hex + "::server:" + id.secret
#define SHA256_HEX_LEN  64  // 32 bytes hex-encoded

#define FILE_EXISTS(f) ({ \
    struct stat buffer; \
    (stat(f, &buffer) == 0); \
})

#define DATA_DIR "/usr/local/var/lib/legion"

#define TOKEN_CHARSET "abcdefghijklmnopqrstuvwxyz0123456789"
#define TOKEN_HEADER "X-Legion-Token"

/**
 * node_capacity_t
 */
typedef struct {
    int cpu_cores;
    double load_avg_1m;
    double load_avg_5m;
    double load_avg_15m;
    uint64_t mem_total_bytes;
    uint64_t mem_available_bytes;
    uint64_t disk_total_bytes;
    uint64_t disk_available_bytes;
} node_capacity_t;

/**
 * Create the given directory path.
 */
int
node_create_path(const char *path, mode_t mode);

/**
 * node_token_generate
 */
int
node_token_generate(const char *ca_cert_path);

/**
 * node_token_verify
 */
int
node_token_verify(const char *token);

/**
 * node_token_verify_ca_hash
 */
int
node_token_verify_ca_hash(const char *token, const char *ca_cert_path);

#endif /** end __NODE_H */
