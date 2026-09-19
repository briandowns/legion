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

#include <papago.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <jansson.h>
#include <logger.h>

#include "db.h"
#include "node.h"
#include "worker.h"

#define TOKEN_POST_PAYLOAD "{\"token\": \"%s\"}"

CURL *curl;

int
worker_init(void)
{
    return 0;
}

int
worker_start(const worker_config_t *config)
{
    (void)config;
    // put webserver here

    return 0;
}

int
worker_stop(void)
{
    curl_global_cleanup();

    return 0;
}

static int
verify_ca(const char *manager_addr, const char *token,
          const char *ca_path)
{
    s_log(S_LOG_INFO,
        s_log_string("msg", "verifying CA hash from manager"),
        s_log_string("manager_addr", manager_addr));

    int hash_ok = node_token_verify_ca_hash(token, ca_path);
    if (hash_ok < 0) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "failed to verify CA hash"),
            s_log_string("manager_addr", manager_addr));
        unlink(ca_path);
        return 1;
    }

    s_log(S_LOG_INFO,
        s_log_string("msg", "CA hash verified, manager identity confirmed"),
        s_log_string("manager_addr", manager_addr));

    return 0;
}

static size_t
write_to_file_cb(void *data, size_t size, size_t nmemb, void *userp)
{
    FILE *fp = (FILE*)userp;

    return fwrite(data, size, nmemb, fp);
}

int
worker_bootstrap(const worker_config_t *config)
{
    mode_t mode = 0750;
    if (node_create_path(DATA_DIR "/worker/tls", mode) != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "failed to create directory path"),
            s_log_string("path", DATA_DIR "/worker/tls"));
        return 1;
    }

    if (!FILE_EXISTS(DATA_DIR "/worker/tls/ca.crt")) {
        curl = curl_easy_init();
        if (curl == NULL) {
            s_log(S_LOG_ERROR,
                s_log_string("msg", "failed to initialize curl"));
            return 1;
        }

        char url[256];
        snprintf(url, sizeof(url), "https://%s:%s/api/v1/register",
            config->server, config->port);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");

        char token_header[TOKEN_MAX_LEN + sizeof(TOKEN_HEADER) - 1];
        snprintf(token_header, sizeof(token_header), TOKEN_HEADER ": %s", config->token);
        headers = curl_slist_append(headers, token_header);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_file_cb);

        FILE *fp = fopen(DATA_DIR "/worker/tls/ca.crt", "wb");
        if (fp == NULL) {
            s_log(S_LOG_ERROR,
                s_log_string("msg", "failed to open file for writing"),
                s_log_string("path", DATA_DIR "/worker/tls/ca.crt"));
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)fp);

        char hostname[HOST_NAME_MAX + 1]; 

        if (gethostname(hostname, sizeof(hostname)) != 0) {
            s_log(S_LOG_ERROR,
                s_log_string("msg", "failed to get hostname"));
            fclose(fp);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }

        json_error_t error;
        json_t *post_json = json_pack_ex(&error, 0, 
            "{s:s, s:s, s:i, s:s, s:s, s:i}",
            "hostname", hostname,
            "listen_addr", config->listen_addr,
            "status", NODE_READY,
            "podman_version", "4.0.0",
            "labels", "region=us-east env=prod",
            "label_count", 2);

        if (post_json == NULL) {
            s_log(S_LOG_ERROR,
                s_log_string("msg", "failed to create JSON payload"),
                s_log_string("error", error.text),
                s_log_int("line", error.line));
            fclose(fp);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }
        char *post_fields = json_dumps(post_json, 0);
        if (post_fields == NULL) {
            s_log(S_LOG_ERROR,
                s_log_string("msg", "failed to serialize JSON payload"));
            json_decref(post_json);
            fclose(fp);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
        json_decref(post_json);

        CURLcode res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            s_log(S_LOG_ERROR,
                s_log_string("msg", "failed to perform curl request"),
                s_log_string("error", curl_easy_strerror(res)));
            fclose(fp);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }
        fclose(fp);

        int ret = verify_ca(config->server, config->token,
            DATA_DIR "/worker/tls/ca.crt");
        if (ret != 0) {
            s_log(S_LOG_ERROR,
                s_log_string("msg", "failed to verify CA hash"),
                s_log_string("manager_addr", config->server));
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return 0;
}
