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

#ifndef __DB_H
#define __DB_H

#include <sys/param.h>
#include <time.h>

#include <sqlite3.h>

#include "node.h"

#define TASK_ID_LEN 37 // UUID + NULL
#define NODE_ID_LEN 37
#define SERVICE_ID_LEN 37
#define IMAGE_LEN 256
#define LABEL_LEN 128
#define MAX_LABELS 16
#define HOST_NAME_MAX 255

typedef enum {
	NODE_READY = 0,
	NODE_DOWN,
	NODE_DRAINING
} node_status_t;

typedef enum {
	TASK_DESIRED_RUNNING = 0,
	TASK_DESIRED_SHUTDOWN
} task_desired_t;

typedef enum {
	TASK_PENDING = 0,
	TASK_STARTING,
	TASK_RUNNING,
	TASK_FAILED,
	TASK_SHUTDOWN
} task_observed_t;

typedef struct {
	char id[NODE_ID_LEN];
    char hostname[MAXHOSTNAMELEN + 1];
    char listen_addr[64];
	node_status_t status;
    char podman_version[32];
	time_t last_heartbeat_at;
    char labels[MAX_LABELS][LABEL_LEN];
    int label_count;
} node_t;

typedef struct {
    char node_id[NODE_ID_LEN];
    char label[LABEL_LEN];
} node_labels_t;

typedef struct {
	char id[SERVICE_ID_LEN];
	char image[IMAGE_LEN];
	int replicas;

    // empty = no constraint, v0: single label
	char constraint_label[LABEL_LEN];
} service_t;

typedef struct {
	char id[TASK_ID_LEN];
	char service_id[SERVICE_ID_LEN];
    
    // empty = unassigned
    char node_id[NODE_ID_LEN];
	task_desired_t desired_state;
	task_observed_t observed_state;

    char labels[MAX_LABELS][LABEL_LEN];
    int label_count;
} task_t;

int
db_init(const char *path);

void
db_close(void);

/**
 * db_node_create creates a new node in the database based on the data given in
 * node_t. If id isn't NULL, the ID generated for that node is copied into this
 * user defined buffer.
 */
int
db_node_create(const node_t *node, char *id);

int
db_node_create_heartbeat(const char *id, const node_capacity_t *cap);

int
db_node_get(const char *id, node_t *out_node);

int
db_node_update(const node_t *node);

int
db_node_delete(const char *id);

int
db_node_list(node_t **out_nodes, int *out_count);

int
db_service_create(const service_t *svc);

int
db_service_get(const char *id, service_t *out_svc);

int
db_service_update(const service_t *svc);

int
db_service_delete(const char *id);

int
db_service_list(service_t **out_services, int *out_count);

int
db_task_create(const task_t *task);

int
db_task_get(const char *id, task_t *out_task);

int
db_task_update(const task_t *task);

int
db_task_delete(const char *id);

int
db_task_list(const char *service_id_filter, const char *node_id_filter,
             task_t **out_tasks, int *out_count);

#endif /** end __DB_H */
