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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vmmeter.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "node.h"

#define DIGITS "0123456789abcdef"

int
node_create_path(const char *path, mode_t mode)
{
    char *tmp = strdup(path);
    if (tmp == NULL) {
        return 1;
    }

    size_t len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                free(tmp);
                return 1;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        free(tmp);
        return 1;
    }

    free(tmp);

    return 0;
}

/**
 * Fills buf (nchars + 1 bytes) with nchars random characters drawn
 * from TOKEN_CHARSET, nul-terminated. Matches k3s's bootstrap token
 * shape of [a-z0-9]{n}.
 */
static int
random_charset_string(char *buf, int nchars)
{
    unsigned char rand_buf[TOKEN_SECRET_CHARS];

    if (nchars > (int)sizeof(rand_buf)) {
        return 1;
    }

    if (RAND_bytes(rand_buf, nchars) != 1) {
        return 1;
    }

    for (int i = 0; i < nchars; i++) {
        buf[i] = TOKEN_CHARSET[rand_buf[i] % (sizeof(TOKEN_CHARSET) - 1)];
    }

    buf[nchars] = '\0';

    return 0;
}

static void
hex_encode(const unsigned char *in, size_t in_len, char *out)
{
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2] = DIGITS[(in[i] >> 4) & 0xf];
        out[i * 2 + 1] = DIGITS[in[i] & 0xf];
    }

    out[in_len * 2] = '\0';
}

/**
 * Computes the SHA-256 hash of an in-memory string (used for the
 * secret half of the id.secret pair -- never the file path version,
 * since the secret only ever exists in memory).
 */
static int
sha256_string_hex(const char *s, char *out_hex)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return 1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, s, strlen(s)) == 1 &&
        EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1) {
        hex_encode(digest, digest_len, out_hex);
    }

    EVP_MD_CTX_free(ctx);

    return 0;
}


/**
 * Computes the SHA-256 hash of a file's raw contents (used both for
 * the CA cert hash embedded in the token, and for hashing a
 * presented secret before storage/comparison).
 */
static int
sha256_file_hex(const char *path, char *out_hex)
{
    unsigned char buf[4096];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    
    int rc = 1;

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        perror(path);
        return rc;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL) {
        fclose(fp);
        return rc;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        goto out;
    }

    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            goto out;
        }
    }

    if (ferror(fp)) {
        perror(path);
        goto out;
    }

    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        goto out;
    }

    hex_encode(digest, digest_len, out_hex);
    rc = 0;

out:
    EVP_MD_CTX_free(ctx);
    fclose(fp);

    return rc;
}

int
node_token_generate(const char *ca_cert_path)
{
    char ca_hash_hex[SHA256_HEX_LEN + 1];
    char token_id[TOKEN_ID_CHARS + 1];
    char token_secret[TOKEN_SECRET_CHARS + 1];
    char secret_hash_hex[SHA256_HEX_LEN + 1];

    if (sha256_file_hex(ca_cert_path, ca_hash_hex) != 0) {
        return 1;
    }

    if (random_charset_string(token_id, TOKEN_ID_CHARS) != 0) {
        return 1;
    }

    if (random_charset_string(token_secret, TOKEN_SECRET_CHARS) != 0) {
        return 1;
    }

    if (sha256_string_hex(token_secret, secret_hash_hex) != 0) {
        return 1;
    }

    char token[TOKEN_MAX_LEN];
    snprintf(token, TOKEN_MAX_LEN, "K10%s::server:%s.%s", ca_hash_hex,
        token_id, token_secret);

    FILE *fp = fopen(DATA_DIR "/node/token", "w");
    if (fp == NULL) {
        return 1;
    }
    
    if (fwrite(token, 1, strlen(token), fp) != strlen(token)) {
        fclose(fp);
        return 1;
    }
    fclose(fp);

    return 0;
}

/**
 * parse_token splits a presented token into its ca_hash, id, and secret parts.
 * Each out buffer must be large enough for its field (ca_hash: 65, id:
 * TOKEN_ID_CHARS+1, secret: TOKEN_SECRET_CHARS+1).
 */
static int
parse_token(const char *token, char *out_ca_hash, char *out_id,
            char *out_secret)
{
    const char *p = token;
    const char *server_prefix = "::server:";

    if (strncmp(p, "K10", 3) != 0) {
        return 1;
    }

    p += 3;

    const char *sep = strstr(p, server_prefix);
    if (sep == NULL) {
        return 1;
    }

    size_t ca_hash_len = (size_t)(sep - p);

    if (ca_hash_len != SHA256_HEX_LEN) {
        return 1;
    }

    memcpy(out_ca_hash, p, ca_hash_len);
    out_ca_hash[ca_hash_len] = '\0';

    p = sep + strlen(server_prefix);

    const char *dot = strchr(p, '.');
    if (dot == NULL) {
        return 1;
    }

    size_t id_len = (size_t)(dot - p);
    if (id_len != TOKEN_ID_CHARS) {
        return 1;
    }

    memcpy(out_id, p, id_len);
    out_id[id_len] = '\0';

    p = dot + 1;
    size_t secret_len = strlen(p);
    if (secret_len != TOKEN_SECRET_CHARS) {
        return 1;
    }

    memcpy(out_secret, p, secret_len);
    out_secret[secret_len] = '\0';

    return 0;
}

/**
 * node_token_verify
 */
int
node_token_verify(const char *token)
{
    char ca_hash[SHA256_HEX_LEN + 1];
    char token_id[TOKEN_ID_CHARS + 1];
    char token_secret[TOKEN_SECRET_CHARS + 1];
    char secret_hash_hex[SHA256_HEX_LEN + 1];

    if (parse_token(token, ca_hash, token_id, token_secret) != 0) {
        return 1;
    }

    if (sha256_string_hex(token_secret, secret_hash_hex) != 0) {
        return 1;
    }

    return 0;
}

/**
 * node_token_verify_ca_hash
 */
int
node_token_verify_ca_hash(const char *token, const char *ca_cert_path)
{
    char embedded_ca_hash[SHA256_HEX_LEN + 1];
    char token_id[TOKEN_ID_CHARS + 1];
    char token_secret[TOKEN_SECRET_CHARS + 1];
    char actual_ca_hash[SHA256_HEX_LEN + 1];

    if (parse_token(token, embedded_ca_hash, token_id, token_secret) != 0) {
        return 1;
    }

    if (sha256_file_hex(ca_cert_path, actual_ca_hash) != 0) {
        return 1;
    }

    return strcmp(embedded_ca_hash, actual_ca_hash) == 0 ? 1 : 0;
}

/**
 * collect_cpu_cores gets the total number of cores for the system.
 */
static int
collect_cpu_cores(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (int)n : 1;
}

/**
 * collect_load_avg gets the load averages for 1m, 5m, and 15m ranges.
 */
static int
collect_load_avg(double *avg1, double *avg5, double *avg15)
{
    double loads[3];
    if (getloadavg(loads, 3) < 0) {
        *avg1 = *avg5 = *avg15 = 0.0;
        return 1;
    }

    *avg1 = loads[0];
    *avg5 = loads[1];
    *avg15 = loads[2];

    return 0;
}


static int
collect_memory(uint64_t *total, uint64_t *available)
{
    u_long physmem = 0;
    size_t len = sizeof(physmem);

    if (sysctlbyname("hw.physmem", &physmem, &len, NULL, 0) != 0) {
        return 1;
    }
    *total = (uint64_t)physmem;

    // Approximate "available" as free + inactive + cache pages.
    // v_page_size and the vm.stats.vm.* counters give page counts.
    u_int page_size = 0;
    len = sizeof(page_size);

    sysctlbyname("vm.stats.vm.v_page_size", &page_size, &len, NULL, 0);
    if (page_size == 0) {
        page_size = (u_int)getpagesize();
    }

    u_int free_count = 0, inactive_count = 0, cache_count = 0;
    len = sizeof(free_count);
    sysctlbyname("vm.stats.vm.v_free_count", &free_count, &len, NULL, 0);
    len = sizeof(inactive_count);
    sysctlbyname("vm.stats.vm.v_inactive_count", &inactive_count, &len, NULL, 0);
    len = sizeof(cache_count);
    sysctlbyname("vm.stats.vm.v_cache_count", &cache_count, &len, NULL, 0);

    uint64_t reclaimable_pages = (uint64_t)free_count + inactive_count +
        cache_count;
    *available = reclaimable_pages * (uint64_t)page_size;

    return 0;
}

static int
collect_disk(const char *path, uint64_t *total, uint64_t *available)
{
    struct statvfs vfs;
    if (statvfs(path, &vfs) != 0) {
        return 1;
    }

    *total = (uint64_t)vfs.f_blocks * vfs.f_frsize;
    *available = (uint64_t)vfs.f_bavail * vfs.f_frsize; /* unprivileged-usable space */

    return 0;
}

/**
 * collect_node_capacity
 */ 
int
collect_node_capacity(node_capacity_t *cap, const char *podman_storage_path)
{
    memset(cap, 0, sizeof(*cap));

    cap->cpu_cores = collect_cpu_cores();

    if (collect_load_avg(&cap->load_avg_1m, &cap->load_avg_5m,
            &cap->load_avg_15m) != 0) {
        fprintf(stderr, "warning: getloadavg failed: %s\n", strerror(errno));
    }

    if (collect_memory(&cap->mem_total_bytes, &cap->mem_available_bytes) != 0) {
        fprintf(stderr, "warning: memory sysctl failed\n");
    }

    if (collect_disk(podman_storage_path, &cap->disk_total_bytes,
            &cap->disk_available_bytes) != 0) {
        fprintf(stderr, "warning: statvfs(%s) failed: %s\n",
            podman_storage_path, strerror(errno));
    }

    return 0;
}

