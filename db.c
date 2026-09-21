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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>
#include <uuid/uuid.h>

#include "db.h"

static sqlite3 *db;

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS heartbeats ("
    "  node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,"
    "  received_at INTEGER NOT NULL,"
    "  cpu_logical_cores INTEGER NOT NULL,"
    "  load_avg_1m REAL,"
    "  load_avg_5m REAL,"
    "  load_avg_15m REAL,"
    "  mem_total_bytes INTEGER,"
    "  mem_available_bytes INTEGER,"
    "  disk_total_bytes INTEGER,"
    "  disk_available_bytes INTEGER"
    ");"

    "CREATE TABLE IF NOT EXISTS nodes ("
    "  id TEXT PRIMARY KEY,"
    "  hostname TEXT NOT NULL UNIQUE,"
    "  listen_addr TEXT NOT NULL,"
    "  status INTEGER NOT NULL DEFAULT 0,"
    "  last_heartbeat_at INTEGER NOT NULL DEFAULT 0"
    ");"

    "CREATE TABLE IF NOT EXISTS node_labels ("
    "  node_id TEXT NOT NULL,"
    "  label TEXT NOT NULL,"
    "  PRIMARY KEY (node_id, label)"
    ");"

    "CREATE TABLE IF NOT EXISTS services ("
    "  id TEXT PRIMARY KEY,"
    "  image TEXT NOT NULL,"
    "  replicas INTEGER NOT NULL DEFAULT 1,"
    "  constraint_label TEXT NOT NULL DEFAULT ''"
    ");"

    "CREATE TABLE IF NOT EXISTS tasks ("
    "  id TEXT PRIMARY KEY,"
    "  service_id TEXT NOT NULL,"
    "  node_id TEXT NOT NULL DEFAULT '',"
    "  desired_state INTEGER NOT NULL DEFAULT 0,"
    "  observed_state INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS tasks_service_idx ON tasks(service_id);"
    "CREATE INDEX IF NOT EXISTS tasks_node_idx ON tasks(node_id);"

    "CREATE TABLE IF NOT EXISTS task_labels ("
    "  task_id TEXT NOT NULL,"
    "  label TEXT NOT NULL,"
    "  PRIMARY KEY (task_id, label)"
    ");";

static void
id_gen_uuid(char *out)
{
    uuid_t u;

    uuid_generate_random(u);
    uuid_unparse_lower(u, out);
}

static int
create_schema(void)
{
    char *errmsg = NULL;
    if (sqlite3_exec(db, SCHEMA_SQL, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "error: create_schema: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    return 0;
}

int
db_init(const char *path)
{
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        fprintf(stderr, "error: db_open: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    if (create_schema() != 0) {
        sqlite3_close(db);
        db = NULL;
        return 1;
    }

    return 0;
}

void
db_close(void)
{
    if (db != NULL) {
        sqlite3_close(db);
        db = NULL;
    }
}

static int
node_labels_replace(const node_t *node)
{
    const char *del_sql = "DELETE FROM node_labels WHERE node_id = ?;";
    const char *ins_sql =
        "INSERT INTO node_labels (node_id, label) VALUES (?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, del_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 1;
    }

    sqlite3_bind_text(stmt, 1, node->id, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);

    if (sqlite3_prepare_v2(db, ins_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 1;
    }

    for (int i = 0; i < node->label_count && i < MAX_LABELS; i++) {
        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, node->id, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, node->labels[i], -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            return 1;
        }
    }

    sqlite3_finalize(stmt);

    return 0;
}


static int
node_labels_load(node_t *node)
{
    const char *sql = "SELECT label FROM node_labels WHERE node_id = ?;";

    node->label_count = 0;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 1;
    }

    sqlite3_bind_text(stmt, 1, node->id, -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW &&
           node->label_count < MAX_LABELS) {
        strncpy(node->labels[node->label_count],
            (const char *)sqlite3_column_text(stmt, 0),
            LABEL_LEN - 1);
        node->labels[node->label_count][LABEL_LEN - 1] = '\0';
        node->label_count++;
    }

    sqlite3_finalize(stmt);

    return 0;
}

int
db_node_create(const node_t *node, char *id)
{
    const char *sql =
        "INSERT INTO nodes (id, hostname, listen_addr, status, last_heartbeat_at) "
        "VALUES (?, ?, ?, ?, ?);";

    id_gen_uuid((char*)node->id);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "error: node_create: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, node->id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, node->hostname, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, node->listen_addr, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, node->status);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)node->last_heartbeat_at);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "error: node_create: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }
    sqlite3_finalize(stmt);

    if (id != NULL) {
        memset(id, 0, NODE_ID_LEN);
        snprintf(id, NODE_ID_LEN, "%s", node->id);
    }

    return node_labels_replace(node);
}

int
db_node_create_heartbeat(const char *id, const node_capacity_t *cap)
{
    const char *upsert_heartbeat_sql =
        "INSERT INTO heartbeats "
        "(node_id, received_at, cpu_logical_cores, "
        " load_avg_1m, load_avg_5m, load_avg_15m, "
        " mem_total_bytes, mem_available_bytes, "
        " disk_total_bytes, disk_available_bytes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(node_id) DO UPDATE SET "
        "    received_at = excluded.received_at, "
        "    cpu_logical_cores = excluded.cpu_logical_cores, "
        "    load_avg_1m = excluded.load_avg_1m, "
        "    load_avg_5m = excluded.load_avg_5m, "
        "    load_avg_15m = excluded.load_avg_15m, "
        "    mem_total_bytes = excluded.mem_total_bytes, "
        "    mem_available_bytes = excluded.mem_available_bytes, "
        "    disk_total_bytes = excluded.disk_total_bytes, "
        "    disk_available_bytes = excluded.disk_available_bytes;";

    const char *update_node_sql =
        "UPDATE nodes SET last_seen_at = ? WHERE id = ?;";

    sqlite3_stmt *stmt = NULL;
    time_t now = time(NULL);

    if (id == NULL || strlen(id) == 0) {
        fprintf(stderr, "store_heartbeat: missing node_id\n");
        return 1;
    }

    int rc = sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "store_heartbeat: BEGIN failed: %s\n",
            sqlite3_errmsg(db));
        return 1;
    }

    rc = sqlite3_prepare_v2(db, upsert_heartbeat_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "store_heartbeat: prepare failed: %s\n",
            sqlite3_errmsg(db));
        goto ROLLBACK;
    }

    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);
    sqlite3_bind_int(stmt, 3, cap->cpu_cores);
    sqlite3_bind_double(stmt, 4, cap->load_avg_1m);
    sqlite3_bind_double(stmt, 5, cap->load_avg_5m);
    sqlite3_bind_double(stmt, 6, cap->load_avg_15m);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)cap->mem_total_bytes);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)cap->mem_available_bytes);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)cap->disk_total_bytes);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)cap->disk_available_bytes);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    stmt = NULL;

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "store_heartbeat: upsert failed: %s\n",
            sqlite3_errmsg(db));
        goto ROLLBACK;
    }

    rc = sqlite3_prepare_v2(db, update_node_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "store_heartbeat: prepare (node update) failed: %s\n",
            sqlite3_errmsg(db));
        goto ROLLBACK;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
    sqlite3_bind_text(stmt, 2, id, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    stmt = NULL;

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "store_heartbeat: node update failed: %s\n",
            sqlite3_errmsg(db));
        goto ROLLBACK;
    }

    if (sqlite3_changes(db) == 0) {
        fprintf(stderr, "store_heartbeat: unknown node_id %s\n", id);
        goto ROLLBACK;
    }

    rc = sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "store_heartbeat: COMMIT failed: %s\n",
            sqlite3_errmsg(db));
        return 1;
    }

    return 0;

ROLLBACK:
    if (stmt) {
        sqlite3_finalize(stmt);
    }
    sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);

    return 1;
}

static void
node_from_row(sqlite3_stmt *stmt, node_t *out_node)
{
    strncpy(out_node->id, (const char*)sqlite3_column_text(stmt, 0),
        sizeof(out_node->id) - 1);
    out_node->id[sizeof(out_node->id) - 1] = '\0';

    strncpy(out_node->hostname, (const char*)sqlite3_column_text(stmt, 1),
        sizeof(out_node->hostname) - 1);
    out_node->hostname[sizeof(out_node->hostname) - 1] = '\0';

    out_node->status = (node_status_t)sqlite3_column_int(stmt, 2);
    out_node->last_heartbeat_at = (time_t)sqlite3_column_int64(stmt, 3);
}

int
db_node_get(const char *id, node_t *out_node)
{
    const char *sql =
        "SELECT id, hostname, status, last_heartbeat_at FROM nodes WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "node_get: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 1;
    }

    node_from_row(stmt, out_node);

    sqlite3_finalize(stmt);

    return node_labels_load(out_node);
}

int
db_node_update(const node_t *node)
{
    const char *sql =
        "UPDATE nodes SET status = ?, last_heartbeat_at = ? "
        "WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "error: node_update: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_int(stmt, 1, node->status);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)node->last_heartbeat_at);
    sqlite3_bind_text(stmt, 3, node->id, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "error: node_update: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);

    return node_labels_replace(node);
}

int
node_delete(const char *id)
{
    const char *del_labels_sql =
        "DELETE FROM node_labels WHERE node_id = ?;";
    const char *del_node_sql = "DELETE FROM nodes WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, del_labels_sql, -1, &stmt, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "error: db_node_delete: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (sqlite3_prepare_v2(db, del_node_sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "error: db_node_delete: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "error: db_node_delete: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);

    return 0;
}

int
db_node_list(node_t **out_nodes, int *out_count)
{
    const char *sql =
        "SELECT id, status, last_heartbeat_at FROM nodes;";
    node_t *nodes = NULL;
    int cap = 0;
    int count = 0;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "error: node_list: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count == cap) {
            cap = cap == 0 ? 16 : cap * 2;
            node_t *tmp = realloc(nodes, (size_t)cap * sizeof(*tmp));

            if (tmp == NULL) {
                free(nodes);
                sqlite3_finalize(stmt);
                return 1;
            }

            nodes = tmp;
        }

        node_from_row(stmt, &nodes[count]);
        count++;
    }

    sqlite3_finalize(stmt);

    for (int i = 0; i < count; i++) {
        if (node_labels_load(&nodes[i]) != 0) {
            free(nodes);
            return 1;
        }
    }

    *out_nodes = nodes;
    *out_count = count;

    return 0;
}

int
db_service_create(const service_t *svc)
{
    const char *sql =
        "INSERT INTO services (id, image, replicas, constraint_label) "
        "VALUES (?, ?, ?, ?);";

    id_gen_uuid((char*)svc->id);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "error: service_create: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, svc->id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, svc->image, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, svc->replicas);
    sqlite3_bind_text(stmt, 4, svc->constraint_label, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "error: service_create: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);

    return 0;
}


static void
service_from_row(sqlite3_stmt *stmt, service_t *out_svc)
{
    strncpy(out_svc->id, (const char *)sqlite3_column_text(stmt, 0),
        sizeof(out_svc->id) - 1);
    out_svc->id[sizeof(out_svc->id) - 1] = '\0';

    strncpy(out_svc->image, (const char *)sqlite3_column_text(stmt, 1),
        sizeof(out_svc->image) - 1);
    out_svc->image[sizeof(out_svc->image) - 1] = '\0';

    out_svc->replicas = sqlite3_column_int(stmt, 2);

    strncpy(out_svc->constraint_label,
        (const char *)sqlite3_column_text(stmt, 3),
        sizeof(out_svc->constraint_label) - 1);
    out_svc->constraint_label[sizeof(out_svc->constraint_label) - 1] = '\0';
}


int
db_service_get(const char *id, service_t *out_svc)
{
    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT id, image, replicas, constraint_label "
        "FROM services WHERE id = ?;";
    int rc = -1;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "error: service_get: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        service_from_row(stmt, out_svc);
        rc = 0;
    }

    sqlite3_finalize(stmt);

    return rc;
}


int
db_service_update(const service_t *svc)
{
    const char *sql =
        "UPDATE services SET image = ?, replicas = ?, "
        "constraint_label = ? WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "error: service_update: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, svc->image, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, svc->replicas);
    sqlite3_bind_text(stmt, 3, svc->constraint_label, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, svc->id, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "error: service_update: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);

    return 0;
}


int
db_service_delete(const char *id)
{
    const char *sql = "DELETE FROM services WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "error: service_delete: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "error: service_delete: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);

    return 0;
}


int
db_service_list(service_t **out_services, int *out_count)
{
    const char *sql =
        "SELECT id, image, replicas, constraint_label FROM services;";

    service_t *services = NULL;
    int cap = 0;
    int count = 0;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "error: service_list: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count == cap) {
            cap = cap == 0 ? 16 : cap * 2;
            service_t *tmp = realloc(services, (size_t)cap * sizeof(*tmp));

            if (tmp == NULL) {
                free(services);
                sqlite3_finalize(stmt);
                return 1;
            }

            services = tmp;
        }

        service_from_row(stmt, &services[count]);
        count++;
    }

    sqlite3_finalize(stmt);

    *out_services = services;
    *out_count = count;

    return 0;
}

static int
task_labels_replace(const task_t *task)
{
    const char *del_sql = "DELETE FROM task_labels WHERE task_id = ?;";
    const char *ins_sql =
        "INSERT INTO task_labels (task_id, label) VALUES (?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, del_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 1;
    }

    sqlite3_bind_text(stmt, 1, task->id, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);

    if (sqlite3_prepare_v2(db, ins_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 1;
    }

    for (int i = 0; i < task->label_count && i < MAX_LABELS; i++) {
        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, task->id, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, task->labels[i], -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            return 1;
        }
    }

    sqlite3_finalize(stmt);

    return 0;
}


static int
task_labels_load(task_t *task)
{
    const char *sql = "SELECT label FROM task_labels WHERE task_id = ?;";

    task->label_count = 0;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 1;
    }

    sqlite3_bind_text(stmt, 1, task->id, -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW &&
           task->label_count < MAX_LABELS) {
        strncpy(task->labels[task->label_count],
            (const char*)sqlite3_column_text(stmt, 0), LABEL_LEN - 1);
        task->labels[task->label_count][LABEL_LEN - 1] = '\0';
        task->label_count++;
    }

    sqlite3_finalize(stmt);

    return 0;
}


int
task_create(const task_t *task)
{
    const char *sql =
        "INSERT INTO tasks "
        "(id, service_id, node_id, desired_state, observed_state) "
        "VALUES (?, ?, ?, ?, ?);";

    id_gen_uuid((char*)task->id);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "error: task_create: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, task->id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, task->service_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, task->node_id, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, task->desired_state);
    sqlite3_bind_int(stmt, 5, task->observed_state);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "error: task_create: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }
        
    sqlite3_finalize(stmt);

    return task_labels_replace(task);
}


static void
task_from_row(sqlite3_stmt *stmt, task_t *out_task)
{
    strncpy(out_task->id, (const char *)sqlite3_column_text(stmt, 0),
        sizeof(out_task->id) - 1);
    out_task->id[sizeof(out_task->id) - 1] = '\0';

    strncpy(out_task->service_id,
        (const char *)sqlite3_column_text(stmt, 1),
        sizeof(out_task->service_id) - 1);
    out_task->service_id[sizeof(out_task->service_id) - 1] = '\0';

    strncpy(out_task->node_id, (const char *)sqlite3_column_text(stmt, 2),
        sizeof(out_task->node_id) - 1);
    out_task->node_id[sizeof(out_task->node_id) - 1] = '\0';

    out_task->desired_state = (task_desired_t)sqlite3_column_int(stmt, 3);
    out_task->observed_state = (task_observed_t)sqlite3_column_int(stmt, 4);
}


int
task_get(const char *id, task_t *out_task)
{
    const char *sql =
        "SELECT id, service_id, node_id, desired_state, observed_state "
        "FROM tasks WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "task_get: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 1;
    }
    task_from_row(stmt, out_task);

    sqlite3_finalize(stmt);
    return 0;
}


int
task_update(const task_t *task)
{
    const char *sql =
        "UPDATE tasks SET service_id = ?, node_id = ?, "
        "desired_state = ?, observed_state = ? WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "task_update: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, task->service_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, task->node_id, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, task->desired_state);
    sqlite3_bind_int(stmt, 4, task->observed_state);
    sqlite3_bind_text(stmt, 5, task->id, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "task_update: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);

    return task_labels_replace(task);
}


int
task_delete(const char *id)
{
    sqlite3_stmt *stmt;
    const char *del_labels_sql =
        "DELETE FROM task_labels WHERE task_id = ?;";
    const char *del_task_sql = "DELETE FROM tasks WHERE id = ?;";

    if (sqlite3_prepare_v2(db, del_labels_sql, -1, &stmt, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "error: task_delete: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (sqlite3_prepare_v2(db, del_task_sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "error: task_delete: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "error: task_delete: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);

    return 0;
}


int
task_list(const char *service_id_filter, const char *node_id_filter,
          task_t **out_tasks, int *out_count)
{
    char sql[512];
    int has_service = service_id_filter != NULL && service_id_filter[0] != '\0';
    int has_node = node_id_filter != NULL && node_id_filter[0] != '\0';
    task_t *tasks = NULL;
    int cap = 0;
    int count = 0;
    int bind_idx = 1;
    int i;

    snprintf(sql, sizeof(sql),
        "SELECT id, service_id, node_id, desired_state, observed_state "
        "FROM tasks WHERE (? = 0 OR service_id = ?) "
        "AND (? = 0 OR node_id = ?);");

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "task_list: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_int(stmt, bind_idx++, has_service ? 1 : 0);
    sqlite3_bind_text(stmt, bind_idx++,
        has_service ? service_id_filter : "", -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, bind_idx++, has_node ? 1 : 0);
    sqlite3_bind_text(stmt, bind_idx++,
        has_node ? node_id_filter : "", -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count == cap) {
            cap = cap == 0 ? 16 : cap * 2;
            task_t *tmp = realloc(tasks, (size_t)cap * sizeof(*tmp));

            if (tmp == NULL) {
                free(tasks);
                sqlite3_finalize(stmt);
                return 1;
            }

            tasks = tmp;
        }

        task_from_row(stmt, &tasks[count]);
        count++;
    }

    sqlite3_finalize(stmt);

    for (i = 0; i < count; i++) {
        if (task_labels_load(&tasks[i]) != 0) {
            free(tasks);
            return 1;
        }
    }

    *out_tasks = tasks;
    *out_count = count;

    return 0;
}
