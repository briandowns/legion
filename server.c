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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>

#include <jansson.h>
#include <logger.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <papago.h>

#include "db.h"
#include "server.h"
#include "node.h"
#include "pki.h"

#define API_URL_BASE "/api/v1"
#define ERR_INTERNAL_SERVER "{\"error\":\"internal server error\"}"
#define ERR_BAD_REQUEST "{\"error\":\"bad request\"}"
#define ERR_UNAUTHORIZED "{\"error\":\"unauthorized\"}"

static int kq;
static papago_t *register_server = NULL;
static papago_t *primary_server = NULL;

typedef struct {
    char *type;
    node_t payload;
} register_msg_t;

int
server_init(void)
{
    kq = kqueue();
    if (kq == -1) {
        perror("kqueue");
        return 1;
    }

    db_init(DATA_DIR "/server/legion.db");

    return 0;
}

int
server_bootstrap(void)
{
    mode_t mode = 0750;
    if (node_create_path(DATA_DIR "/server/tls", mode) == 0) {
        s_log(S_LOG_INFO, s_log_string("msg", "created directory path"),
            s_log_string("component", "server"),
            s_log_string("path", DATA_DIR "/server/tls"));
    } else {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "failed to create directory path"),
            s_log_string("component", "server"),
            s_log_string("path", DATA_DIR "/server/tls"));
        return 1;
    }

    if (node_create_path(DATA_DIR "/node", mode) == 0) {
        s_log(S_LOG_INFO, s_log_string("msg", "created directory path"),
            s_log_string("component", "server"),
            s_log_string("path", DATA_DIR "/server/node"));
    } else {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "failed to create directory path"),
            s_log_string("component", "server"),
            s_log_string("path", DATA_DIR "/server/node"));
        return 1;
    }

    int ret = 0;
    if (!FILE_EXISTS(DATA_DIR "/server/tls/ca.key") ||
        !FILE_EXISTS(DATA_DIR "/server/tls/ca.crt")) {
            s_log(S_LOG_INFO, 
                s_log_string("msg", "generating CA certificate and key"),
                s_log_string("component", "server"));

        ret = pki_generate_ca(DATA_DIR "/server/tls/ca.key",
            DATA_DIR "/server/tls/ca.crt", 10);
        if (ret != 0) {
            s_log(S_LOG_ERROR,
                s_log_string("msg", "error generating CA certificate"),
                s_log_string("component", "server"));
            return 1;
        }

        s_log(S_LOG_INFO, 
            s_log_string("msg", "generating server certificate and key"));
            s_log_string("component", "server"),

        ret = pki_generate_cert_and_key(DATA_DIR "/server/tls/ca.key",
            DATA_DIR "/server/tls/ca.crt", "legion-server", NULL, 3650,
            DATA_DIR "/server/tls/server.key",
            DATA_DIR "/server/tls/server.crt");
        if (ret != 0) {
            s_log(S_LOG_ERROR,
                s_log_string("msg", "error generating server certificate and key"),
                s_log_string("component", "server"));
            return 1;
        }
    }

    if (!FILE_EXISTS(DATA_DIR "/node/token")) {
        s_log(S_LOG_INFO, 
            s_log_string("msg", "generating server join token"),
            s_log_string("component", "server"));

        if (node_token_generate(DATA_DIR "/server/tls/ca.crt") != 0) {
            s_log(S_LOG_ERROR,
                s_log_string("msg", "error generating server join token"),
                s_log_string("component", "server"));
            return 1;
        }
    }

    return 0;
}

void*
run_timer(void *data)
{
    (void)data;

    struct kevent event;
    struct kevent fired;

    EV_SET(&event, 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, 30000, NULL);

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

        // s_log(S_LOG_INFO, s_log_string("msg", "timer event fired"));
    }

    close(kq);

    return NULL;
}

static void
register_handler(papago_request_t *req, papago_response_t *res,
                 void *user_data)
{
    PAPAGO_UNUSED(user_data);

    const char *token = papago_req_header(req, TOKEN_HEADER);
    if (token == NULL || token[0] == '\0') {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "missing token header"));
            s_log_string("component", "server"),
        papago_res_set_status(res, PAPAGO_STATUS_UNAUTHORIZED);
        papago_res_send(res, ERR_UNAUTHORIZED);
        return;
    }

    char expected_token[TOKEN_MAX_LEN + 1];
    FILE *token_file = fopen(DATA_DIR "/node/token", "r");
    if (token_file == NULL) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "failed to open token file"));
            s_log_string("component", "server"),
        papago_res_set_status(res, PAPAGO_STATUS_INTERNAL_ERROR);
        papago_res_send(res, ERR_INTERNAL_SERVER);
        return;
    }
    if (fgets(expected_token, sizeof(expected_token), token_file) == NULL) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "failed to read token from file"));
            s_log_string("component", "server"),
        fclose(token_file);
        papago_res_set_status(res, PAPAGO_STATUS_INTERNAL_ERROR);
        papago_res_send(res, ERR_INTERNAL_SERVER);
        return;
    }
    fclose(token_file);

    // remove trailing newline from expected_token
    size_t len = strlen(expected_token);
    if (len > 0 && expected_token[len - 1] == '\n') {
        expected_token[len - 1] = '\0';
    }

    if (strcmp(token, expected_token) != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "invalid token header"));
            s_log_string("component", "server"),
        papago_res_set_status(res, PAPAGO_STATUS_UNAUTHORIZED);
        papago_res_send(res, ERR_UNAUTHORIZED);
        return;
    }

    json_error_t error;
    json_t *root = json_loads(papago_req_body(req), JSON_DISABLE_EOF_CHECK, &error);
    if (root == NULL) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "failed parsing JSON message"),
            s_log_string("component", "server"),
            s_log_string("error", error.text));
        return;
    }

    if (!json_is_object(root)) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "root element is not a JSON object"));
            s_log_string("component", "server"),
        json_decref(root);
        return;
    }

    register_msg_t reg_msg;
    node_capacity_t node_capacity;
    memset(&reg_msg, 0, sizeof(register_msg_t));
    memset(&node_capacity, 0, sizeof(node_capacity_t));

    const char *hostname_tmp = NULL;
    const char *listen_addr_tmp = NULL;
    const char *podman_version_tmp = NULL;

    json_t *labels_array = NULL;
    int ret = json_unpack_ex(root, &error, 0,
        "{s:s, s:s, s:i, s:s, s:O, s:i, s:{s:i, s:f, s:f, s:f, s:i, s:i, s:i, s:i}}",
            "hostname", &hostname_tmp,
            "listen_addr", &listen_addr_tmp,
            "status", &reg_msg.payload.status,
            "podman_version", &podman_version_tmp,
            "labels", &labels_array,
            "label_count", &reg_msg.payload.label_count,
            "capacity", 
            "cpu_cores", &node_capacity.cpu_cores,
            "load_avg_1m", &node_capacity.load_avg_1m,
            "load_avg_5m", &node_capacity.load_avg_5m,
            "load_avg_15m", &node_capacity.load_avg_15m,
            "mem_total_bytes", &node_capacity.mem_total_bytes,
            "mem_available_bytes", &node_capacity.mem_available_bytes,
            "disk_total_bytes", &node_capacity.disk_total_bytes,
            "disk_available_bytes", &node_capacity.disk_available_bytes);
    if (ret != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", "json_unpack failed to map all register fields"),
            s_log_string("component", "server"),
            s_log_int("status", ret), s_log_string("error", error.text),
            s_log_int("line", error.line), s_log_int("column", error.column));
        papago_res_set_status(res, PAPAGO_STATUS_INTERNAL_ERROR);
        papago_res_send(res, ERR_INTERNAL_SERVER);
        return;
    }
    strncpy(reg_msg.payload.hostname, hostname_tmp,
        sizeof(reg_msg.payload.hostname) - 1);
    strncpy(reg_msg.payload.listen_addr, listen_addr_tmp,
        sizeof(reg_msg.payload.listen_addr) - 1);
    strncpy(reg_msg.payload.podman_version, podman_version_tmp,
        sizeof(reg_msg.payload.podman_version) - 1);

    if (json_is_array(labels_array)) {
        size_t index;
        json_t *value;

        json_array_foreach(labels_array, index, value) {
            if (index >= MAX_LABELS) {
                break;
            }
            if (json_is_string(value)) {
                strncpy(reg_msg.payload.labels[index], json_string_value(value), LABEL_LEN - 1);
                reg_msg.payload.labels[index][LABEL_LEN - 1] = '\0';
            }
        }
        json_decref(labels_array);
    }

    s_log(S_LOG_INFO, s_log_string("msg", "received register message"),
        s_log_string("component", "server"),
        s_log_string("hostname", reg_msg.payload.hostname),
        s_log_int("label_count", reg_msg.payload.label_count),
        s_log_string("podman_version", reg_msg.payload.podman_version));

    reg_msg.payload.status = NODE_READY;
    reg_msg.payload.last_heartbeat_at = time(NULL);

    char node_id[NODE_ID_LEN];
    if (db_node_create(&reg_msg.payload, node_id) != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("component", "server"),
            s_log_string("msg", "failed to create node in database"));
        papago_res_set_status(res, PAPAGO_STATUS_INTERNAL_ERROR);
        papago_res_send(res, ERR_INTERNAL_SERVER);
        return;
    }

    node_t node;
    if (db_node_get(node_id, &node) != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("component", "server"),
            s_log_string("msg", "failed to add node capacity in database"));
        papago_res_set_status(res, PAPAGO_STATUS_INTERNAL_ERROR);
        papago_res_send(res, ERR_INTERNAL_SERVER);
        return;
    }

    if (db_node_create_heartbeat(node_id, &node_capacity) != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("component", "server"),
            s_log_string("msg", "failed to store heartbeat")); 
        return;
    }
    s_log(S_LOG_INFO,
        s_log_string("msg", "node registered successfully"),
        s_log_string("component", "server"),
        s_log_string("hostname", reg_msg.payload.hostname));

    json_decref(root);

    papago_res_header(res, "X-Legion-Node-ID", node_id);
    papago_res_header(res, PAPAGO_REQUEST_HEADER_CONTENT_TYPE, "application/x-pem-file");
    papago_res_sendfile(register_server, res, DATA_DIR "/server/tls/ca.crt");
}

// static void
// node_heartbeat_handler(papago_request_t *req, papago_response_t *res,
//                        void *user_data)
// {
//     PAPAGO_UNUSED(user_data);
//
//     const char *id = papago_req_param(req, "id");
//     if (id == NULL || id[0] == '\0') {
//         papago_res_set_status(res, PAPAGO_STATUS_BAD_REQUEST);
//         papago_res_send(res, "");
//         return;
//     }
//
//     node_t node;
//     int ret = db_node_get(id, &node);
//     if (ret != 0) {
//         papago_res_set_status(res, PAPAGO_STATUS_INTERNAL_ERROR);
//         papago_res_send(res, ERR_INTERNAL_SERVER);
//         return;
//     }
//
//     json_error_t error;
//     json_t *root = json_loads(papago_req_body(req), JSON_DISABLE_EOF_CHECK, &error);
//     if (root == NULL) {
//         s_log(S_LOG_ERROR, s_log_string("msg", "failed parsing JSON message"),
//             s_log_string("error", error.text));
//         return;
//     }
//
//     if (!json_is_object(root)) {
//         s_log(S_LOG_ERROR, s_log_string("msg",
//             "root element is not a JSON object"));
//         json_decref(root);
//         return;
//     }
//
//     node_capacity_t node_capacity;
//     memset(&node_capacity, 0, sizeof(node_capacity_t));
//
//     ret = json_unpack(root,
//         "{s:i, s:f, s:f, s:f, s:i, s:i, s:i, s:i}", 
//             "cpu_cores", &node_capacity.cpu_cores,
//             "load_avg_1m", &node_capacity.load_avg_1m,
//             "load_avg_5m", &node_capacity.load_avg_5m,
//             "load_avg_15m", &node_capacity.load_avg_15m,
//             "mem_total_bytes", &node_capacity.mem_total_bytes,
//             "mem_available_bytes", &node_capacity.mem_available_bytes,
//             "disk_total_bytes", &node_capacity.disk_total_bytes,
//             "disk_available_bytes", &node_capacity.disk_available_bytes);
//     if (ret != 0) {
//         s_log(S_LOG_ERROR, s_log_string("msg",
//             "json_unpack failed to map all fields"));
//         return;
//     }
//
//     ret = db_node_create_heartbeat(id, &node_capacity);
//     if (ret != 0) {
//         s_log(S_LOG_ERROR, s_log_string("msg", "failed to store heartbeat")); 
//         return;
//     }
// }
//
void
ws_on_connect(papago_ws_connection_t *conn)
{
    s_log(S_LOG_INFO,\
        s_log_string("msg", "client connected"),
        s_log_string("ip", papago_ws_get_client_ip(conn)));

	papago_ws_send(conn, "");
}

void
ws_on_message(papago_ws_connection_t *conn, const char *message,
              size_t length, bool is_binary)
{
	PAPAGO_UNUSED(length);
	PAPAGO_UNUSED(is_binary);

    json_error_t error;
    json_t *root = json_loads(message, JSON_DISABLE_EOF_CHECK, &error);
    if (root == NULL) {
        s_log(S_LOG_ERROR, s_log_string("msg", "failed parsing JSON message"),
            s_log_string("error", error.text));
	    papago_ws_send(conn, "{\"error\": \"failed parsing JSON message\"}");
        return;
    }

    if (!json_is_object(root)) {
        s_log(S_LOG_ERROR, s_log_string("msg",
            "root element is not a JSON object"));
        json_decref(root);
	    papago_ws_send(conn, "{\"error\": \"object not JSON\"}");
        return;
    }

    const msg_type_t msg_type = MSG_TYPE_UNKNOWN;
    const char *node_id;
    json_t payload;

    int ret = json_unpack(root, "{s:s, s:s, s:O}",
        "type", &msg_type, "node_id", &node_id, "payload", &payload);
    if (ret != 0) {
        s_log(S_LOG_ERROR, s_log_string("msg", "failed to map all fields"));
	    papago_ws_send(conn, "{\"error\": \"failed to map all fields\"}");
        json_decref(root);
        return;
    }

    switch (msg_type) {
        case MSG_TYPE_HB:
            node_capacity_t node_capacity;
            memset(&node_capacity, 0, sizeof(node_capacity_t));

            ret = json_unpack(&payload,
                    "{s:i, s:f, s:f, s:f, s:i, s:i, s:i, s:i}", 
                        "cpu_cores", &node_capacity.cpu_cores,
                        "load_avg_1m", &node_capacity.load_avg_1m,
                        "load_avg_5m", &node_capacity.load_avg_5m,
                        "load_avg_15m", &node_capacity.load_avg_15m,
                        "mem_total_bytes", &node_capacity.mem_total_bytes,
                        "mem_available_bytes", &node_capacity.mem_available_bytes,
                        "disk_total_bytes", &node_capacity.disk_total_bytes,
                        "disk_available_bytes", &node_capacity.disk_available_bytes);
            if (ret != 0) {
                s_log(S_LOG_ERROR, s_log_string("msg",
                    "json_unpack failed to map all fields"));
                return;
            }

            ret = db_node_create_heartbeat(node_id, &node_capacity);
            if (ret != 0) {
                s_log(S_LOG_ERROR,
                    s_log_string("msg", "failed to store heartbeat")); 
                return;
            }

            papago_ws_send(conn, "");
            break;
        default:
            s_log(S_LOG_ERROR, s_log_string("msg", "unrecognized msg type"));
	        papago_ws_send(conn, "{\"error\": \"unrecognized msg type\"}");
            return;
    }

}

void
ws_on_close(papago_ws_connection_t *conn)
{
    s_log(S_LOG_INFO, s_log_string("msg", "disconnected"),
        s_log_string("ip", papago_ws_get_client_ip(conn)));
}

void
ws_on_error(papago_ws_connection_t *conn, const char *error)
{
    s_log(S_LOG_ERROR, s_log_string("msg", error));
        s_log_string("ip", papago_ws_get_client_ip(conn));
}

static bool
logger_before(papago_request_t *req, papago_response_t *res, void *user_data)
{
    PAPAGO_UNUSED(req);
    PAPAGO_UNUSED(res);
    PAPAGO_UNUSED(user_data);

    return true;
}

static void
logger_after(papago_request_t *req, papago_response_t *res, void *user_data)
{
    PAPAGO_UNUSED(user_data);

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double duration_ms = (now.tv_sec  - papago_req_start_time(req).tv_sec) 
        * 1000.0
        + (now.tv_nsec - papago_req_start_time(req).tv_nsec) / 1.0e6;

    fprintf(stdout,
        "{\"remote\":\"%s\",\"method\":\"%s\",\"path\":\"%s\","
        "\"version\":\"%s\",\"host\":\"%s\",\"user_agent\":\"%s\","
        "\"status\":%d,\"duration_ms\":%.3f}\n",
        papago_req_client_ip(req) != NULL ? papago_req_client_ip(req) : "-",
        papago_req_method(req) != NULL ? papago_req_method(req) : "-",
        papago_req_path(req) != NULL ? papago_req_path(req) : "-",
        papago_req_version(req) != NULL ? papago_req_version(req) : "-",
        papago_req_host(req) != NULL ? papago_req_host(req) : "-",
        papago_req_user_agent(req) != NULL ? papago_req_user_agent(req) : "-",
        papago_res_status(res),
        duration_ms);
}

struct server {
    papago_config_t *config;
    papago_t *server;
};

void*
start_server(void *user_data)
{
    struct server *svr = (struct server*)user_data;

    if (papago_start(svr->server, svr->config) != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("msg", papago_error()),
            s_log_string("component", "server"));
        papago_destroy(svr->server);
    }

    return NULL;
}

void*
run_http_server(void *user_data)
{
    PAPAGO_UNUSED(user_data);

    register_server = papago_new();
    primary_server = papago_new();

    papago_config_t register_config = papago_default_config();
    register_config.http_port = 8080;
    register_config.enable_compression = true;
    register_config.require_client_cert = false;
    register_config.enable_ssl = true;
    register_config.ca_cert_file = DATA_DIR "/server/tls/ca.crt";
    register_config.cert_file = DATA_DIR "/server/tls/server.crt";
    register_config.key_file = DATA_DIR "/server/tls/server.key";

    papago_config_t primary_config = papago_default_config();
    primary_config.http_port = 8181;
    primary_config.ws_port = 8282;
    primary_config.enable_ssl = true;
    primary_config.require_client_cert = true;
    primary_config.ca_cert_file = DATA_DIR "/server/tls/ca.crt";
    primary_config.cert_file = DATA_DIR "/server/tls/server.crt";
    primary_config.key_file = DATA_DIR "/server/tls/server.key";

    papago_route(register_server, PAPAGO_POST, API_URL_BASE "/register", register_handler, NULL);

    pthread_t register_http_thread, primary_http_thread;

    struct server servers[2] = {
        {
            .config = &register_config,
            .server = register_server
        },
        {
            .config = &primary_config,
            .server = primary_server
        }
    };

    for (int i = 0; i < 2; i++) {
        papago_middleware_t structured_logger = {
            .before    = logger_before,
            .after     = logger_after,
            .user_data = NULL,
        };
        papago_middleware_add(servers[i].server, &structured_logger);

        if (i == 0) {
            if (pthread_create(&register_http_thread, NULL, start_server, &servers[i]) != 0) {
                s_log(S_LOG_ERROR,
                    s_log_string("component", "server"),
                    s_log_string("msg", "failed to register http thread"));
                return NULL;
            }
        } else {
            if (pthread_create(&primary_http_thread, NULL, start_server, &servers[i]) != 0) {
                s_log(S_LOG_ERROR,
                    s_log_string("component", "server"),
                    s_log_string("msg", "failed to create primary http thread"));
                return NULL;
            }

        }
    }

    pthread_join(register_http_thread, NULL);
    pthread_join(primary_http_thread, NULL);

    return NULL;
}

int
server_start(void)
{
    s_log(S_LOG_INFO, 
        s_log_string("component", "server"),
        s_log_string("msg", "starting legion server"));

    pthread_t timer_thread, http_thread;

    if (pthread_create(&timer_thread, NULL, run_timer, NULL) != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("component", "server"),
            s_log_string("msg", "failed to create timer thread"));
        return 1;
    }

    if (pthread_create(&http_thread, NULL, run_http_server, NULL) != 0) {
        s_log(S_LOG_ERROR,
            s_log_string("component", "server"),
            s_log_string("msg", "failed to create HTTP server thread"));
        return 1;
    }

    pthread_join(timer_thread, NULL);
    pthread_join(http_thread, NULL);

    return 0;
}

int
server_stop(void)
{
    close(kq);
    papago_destroy(register_server);
    papago_destroy(primary_server);

    return 0;
}
