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

#ifndef __PKI_H
#define __PKI_H

/*
 * Generates an RSA CA keypair and self-signed certificate, valid for
 * `years` years, written to ca_key_path/ca_cert_path.
 *
 * Returns 0 on success, 1 on failure (errors printed via
 * ERR_print_errors_fp -- never exits, safe to call from a running
 * daemon).
 */
int
pki_generate_ca(const char *ca_key_path, const char *ca_cert_path, int years);

/*
 * Generates a leaf keypair and certificate signed by the CA at
 * ca_key_path/ca_cert_path, valid for `days` days.
 *
 * common_name becomes both the certificate CN and the primary DNS
 * SAN entry. san_ip is optional (pass NULL to skip) and adds an IP
 * SAN entry -- useful when the node is addressed by IP rather than
 * a resolvable hostname.
 *
 * The certificate carries both serverAuth and clientAuth extended
 * key usage so the same cert works for the manager's listener and
 * the worker's outbound mTLS connection.
 *
 * Returns 0 on success, 1 on failure.
 */
int
pki_generate_cert_and_key(const char *ca_key_path, const char *ca_cert_path,
                          const char *common_name, const char *san_ip,
                          int days, const char *key_path,
                          const char *cert_path);

#endif /** end __PKI_H */
