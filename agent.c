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

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>
#include <jansson.h>
#include <logger.h>
#include <papago.h>

#include "agent.h"
#include "db.h"
#include "node.h"

#define TOKEN_POST_PAYLOAD "{\"token\": \"%s\"}"

static int kq;
CURL *curl;

void*
run_healthcheck(void *data)
{
    (void)data;

    struct kevent event;
    struct kevent fired;

    EV_SET(&event, 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, 10000, NULL);

    if (kevent(kq, &event, 1, NULL, 0, NULL) == -1) {
        perror("kevent");
        close(kq);
        return NULL;
    }

    while (true) {
        if (kevent(kq, NULL, 0, &fired, 1, NULL) == -1) {
            perror("kevent");
            break;
        }

        node_capacity_t node_cap;
        char err[1024];
        int ret = node_capacity(&node_cap, err, 1024);
        if (ret != 0) {
            s_log(S_LOG_ERROR, s_log_string("msg", err));
            break;
        }
    }

    close(kq);

    return NULL;
}

int
agent_start(const agent_config_t *config)
{
    (void)config;
    kq = kqueue();
    if (kq == -1) {
        perror("kqueue");
        return 1;
    }

    pthread_t healthcheck_thread;
    if (pthread_create(&healthcheck_thread, NULL, run_healthcheck, NULL) != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "failed to create healthcheck_thread thread"));
        return 1;
    }

    FILE *fp = fopen(DATA_DIR "/node/id", "r");
    if (fp == NULL) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    char node_id[NODE_ID_LEN];

    if (fgets(node_id, NODE_ID_LEN, fp) == NULL) {
        printf("The file is empty or an error occurred.\n");
        return EXIT_FAILURE;
    }
    fclose(fp);

    char url[256];
    snprintf(url, sizeof(url), "https://%s:%s/api/v1/node/%s/heartbeat",
        config->server, config->port, node_id);

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

    char hostname[HOST_NAME_MAX + 1]; 
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("component", "agent"),
            s_log_string("msg", "failed to get hostname"));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return 1;
    }
    node_capacity_t node_cap;
    char err[1024];
    if (node_capacity(&node_cap, err, 1024) != 0) {
        s_log(S_LOG_ERROR, s_log_string("component", "agent"),
            s_log_string("msg", err));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return 1;
    }

    json_error_t error;
    json_t *post_json = json_pack_ex(&error, 0,
        "{s:i, s:f, s:f, s:f, s:i, s:i, s:i, s:i}",
            "cpu_cores", node_cap.cpu_cores,
            "load_avg_1m", node_cap.load_avg_1m,
            "load_avg_5m", node_cap.load_avg_5m,
            "load_avg_15m", node_cap.load_avg_15m,
            "mem_total_bytes", node_cap.mem_total_bytes,
            "mem_available_bytes", node_cap.mem_available_bytes,
            "disk_total_bytes", node_cap.disk_total_bytes,
            "disk_available_bytes", node_cap.disk_available_bytes);
    if (post_json == NULL) {
        s_log(S_LOG_ERROR,
            s_log_string("component", "agent"),
            s_log_string("msg", "failed to create JSON payload"),
            s_log_string("error", error.text),
            s_log_int("line", error.line));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return 1;
    }

    char *post_fields = json_dumps(post_json, 0);
    if (post_fields == NULL) {
        s_log(S_LOG_ERROR,
            s_log_string("component", "agent"),
            s_log_string("msg", "failed to serialize JSON payload"));
        json_decref(post_json);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return 1;
    }

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
    json_decref(post_json);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        s_log(S_LOG_ERROR,
            s_log_string("component", "agent"),
            s_log_string("msg", "failed to perform curl request"),
            s_log_string("error", curl_easy_strerror(res)));
        json_decref(post_json);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return 1;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    pthread_join(healthcheck_thread, NULL);

    return 0;
}

int
agent_stop(void)
{
    close(kq);
    curl_global_cleanup();

    return 0;
}

static int
verify_ca(const char *server_addr, const char *token,
          const char *ca_path)
{
    s_log(S_LOG_INFO,
        s_log_string("msg", "verifying CA hash from server"),
        s_log_string("server_addr", server_addr));

    int hash_ok = node_token_verify_ca_hash(token, ca_path);
    if (hash_ok < 0) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "failed to verify CA hash"),
            s_log_string("server_addr", server_addr));
        unlink(ca_path);
        return 1;
    }

    s_log(S_LOG_INFO,
        s_log_string("msg", "CA hash verified, server identity confirmed"),
        s_log_string("server_addr", server_addr));

    return 0;
}

static size_t
write_to_file_cb(void *data, size_t size, size_t nmemb, void *userp)
{
    FILE *fp = (FILE*)userp;

    return fwrite(data, size, nmemb, fp);
}

int
agent_bootstrap(const agent_config_t *config)
{
    mode_t mode = 0750;
    if (node_create_path(DATA_DIR "/agent/tls", mode) != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "failed to create directory path"),
            s_log_string("path", DATA_DIR "/agent/tls"));
        return 1;
    }
    
    if (!FILE_EXISTS(DATA_DIR "/agent/tls/ca.crt")) {
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

        FILE *fp = fopen(DATA_DIR "/agent/tls/ca.crt", "wb");
        if (fp == NULL) {
            s_log(S_LOG_ERROR,
                s_log_string("component", "agent"),
                s_log_string("msg", "failed to open ca.crt for writing"),
                s_log_string("path", DATA_DIR "/agent/tls/ca.crt"));
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)fp);

        char hostname[HOST_NAME_MAX + 1]; 

        if (gethostname(hostname, sizeof(hostname)) != 0) {
            s_log(S_LOG_ERROR,
                s_log_string("component", "agent"),
                s_log_string("msg", "failed to get hostname"));
            fclose(fp);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }
        node_capacity_t node_cap;
        char err[1024];
        if (node_capacity(&node_cap, err, 1024) != 0) {
            s_log(S_LOG_ERROR, s_log_string("component", "agent"),
                s_log_string("msg", err));
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }

        json_error_t error;
        json_t *labels = json_pack("[s, s]", "region=us-east", "env=prod");

        json_t *post_json = json_pack_ex(&error, 0,
            "{s:s, s:s, s:i, s:s, s:O, s:i, s:{s:i, s:f, s:f, s:f, s:i, s:i, s:i, s:i}}",
            "hostname", hostname,
            "listen_addr", config->listen_addr,
            "status", NODE_READY,
            "podman_version", "4.0.0",
            "labels", labels,
            "label_count", 2,
            "capacity", 
            "cpu_cores", node_cap.cpu_cores,
            "load_avg_1m", node_cap.load_avg_1m,
            "load_avg_5m", node_cap.load_avg_5m,
            "load_avg_15m", node_cap.load_avg_15m,
            "mem_total_bytes", node_cap.mem_total_bytes,
            "mem_available_bytes", node_cap.mem_available_bytes,
            "disk_total_bytes", node_cap.disk_total_bytes,
            "disk_available_bytes", node_cap.disk_available_bytes);
        if (post_json == NULL) {
            s_log(S_LOG_ERROR,
                s_log_string("component", "agent"),
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
                s_log_string("component", "agent"),
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
        if (res != CURLE_OK) {
            s_log(S_LOG_ERROR,
                s_log_string("component", "agent"),
                s_log_string("msg", "failed to perform curl request"),
                s_log_string("error", curl_easy_strerror(res)));
            json_decref(post_json);
            fclose(fp);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }
        fclose(fp);

        int ret = verify_ca(config->server, config->token,
            DATA_DIR "/agent/tls/ca.crt");
        if (ret != 0) {
            s_log(S_LOG_ERROR,
                s_log_string("component", "agent"),
                s_log_string("msg", "failed to verify CA hash"),
                s_log_string("server_addr", config->server));
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }

        struct curl_header *type;
        CURLHcode hres = curl_easy_header(curl, "X-Legion-Node-ID", 0, CURLH_HEADER, -1, &type);
        if (hres != CURLHE_OK) {
            printf("Failed to fetch header. Error code: %d\n", hres);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }

        FILE *nidfp = fopen(DATA_DIR "/node/id", "w");
        if (nidfp == NULL) {
            s_log(S_LOG_ERROR, s_log_string("msg", "failed to open file"),
                s_log_string("component", "agent"),
                s_log_string("file", DATA_DIR "/node/id"));
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return 1;
        }
        fprintf(nidfp, "%s\n", type->value);
        fclose(nidfp);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return 0;
}
