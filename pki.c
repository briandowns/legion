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
#include <sys/stat.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "pki.h"

#define CA_KEY_BITS 4096
#define LEAF_KEY_BITS 2048
#define SERIAL_BYTES 16

static void
openssl_error(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
}


/**
 * Generate an RSA private key of the given bit size. Returns NULL
 * on failure.
 */
static EVP_PKEY*
generate_key(int bits)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        openssl_error("EVP_PKEY_CTX_new_id failed");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        openssl_error("EVP_PKEY_keygen_init failed");
        goto out;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        openssl_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
        goto out;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        openssl_error("EVP_PKEY_keygen failed");
        pkey = NULL;
    }

out:
    EVP_PKEY_CTX_free(ctx);

    return pkey;
}


/**
 * Write a private key to PEM, mode 0600 (key material must never be
 * group/world readable -- this is the cluster's trust root or a
 * node's identity).
 */
static int
write_private_key(const char *filename, EVP_PKEY *pkey)
{
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        perror(filename);
        return 1;
    }

    chmod(filename, 0600);

    if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        openssl_error("PEM_write_PrivateKey failed");
        fclose(fp);
        return 1;
    }
    fclose(fp);

    return 0;
}


/**
 * Write an X509 certificate to PEM.
 */
static int
write_certificate(const char *filename, X509 *cert)
{
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        perror(filename);
        return 1;
    }

    if (PEM_write_X509(fp, cert) != 1) {
        openssl_error("PEM_write_X509 failed");
        fclose(fp);
        return 1;
    }
    fclose(fp);

    return 0;
}


/**
 * Assigns a cryptographically random serial number to cert. Fixed
 * serials (1, 2, ...) work for a single demo cert but collide the
 * moment a second leaf is issued from the same CA -- every node
 * join needs its own serial.
 */
static int
set_random_serial(X509 *cert)
{
    unsigned char buf[SERIAL_BYTES];
    ASN1_INTEGER *serial;

    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        openssl_error("RAND_bytes failed");
        return 1;
    }

    BIGNUM *bn = BN_bin2bn(buf, sizeof(buf), NULL);
    if (bn == NULL) {
        openssl_error("BN_bin2bn failed");
        return 1;
    }

    serial = X509_get_serialNumber(cert);

    if (BN_to_ASN1_INTEGER(bn, serial) == NULL) {
        openssl_error("BN_to_ASN1_INTEGER failed");
        return 1;
    }

    BN_free(bn);

    return 0;
}


/**
 * Adds an extension to cert using the standard X509V3_CTX dance.
 * issuer_cert is the CA cert for leaf certs, or cert itself for a
 * self-signed CA cert.
 */
static int
add_extension(X509 *issuer_cert, X509 *cert, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer_cert, cert, NULL, NULL, 0);

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (ext == NULL) {
        openssl_error("X509V3_EXT_conf_nid failed");
        return 1;
    }

    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    return 0;
}


/**
 * Create a self-signed CA certificate for the given key. Returns
 * NULL on failure.
 */
static X509*
create_ca_certificate(EVP_PKEY *ca_key, int years)
{
    X509 *cert = X509_new();
    if (cert == NULL) {
        openssl_error("X509_new failed");
        return NULL;
    }

    if (X509_set_version(cert, 2) != 1) {
        openssl_error("X509_set_version failed");
        goto FAIL;
    }

    if (set_random_serial(cert) != 0) {
        goto FAIL;
    }

    // valid from now for `years` years.
    if (X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL) {
        openssl_error("X509_gmtime_adj notBefore failed");
        goto FAIL;
    }

    if (X509_gmtime_adj(X509_getm_notAfter(cert),
            (long)years * 365L * 24L * 60L * 60L) == NULL) {
        openssl_error("X509_gmtime_adj notAfter failed");
        goto FAIL;
    }

    // Subject: O=swarmd, CN=swarmd-ca. Self-signed, so issuer = subject.
    X509_NAME *name = X509_get_subject_name(cert);

    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        (unsigned char *)"legiond", -1, -1, 0);

    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (unsigned char *)"legiond-ca", -1, -1, 0);

    if (X509_set_issuer_name(cert, name) != 1) {
        openssl_error("X509_set_issuer_name failed");
        goto FAIL;
    }

    if (X509_set_pubkey(cert, ca_key) != 1) {
        openssl_error("X509_set_pubkey failed");
        goto FAIL;
    }

    if (add_extension(cert, cert, NID_basic_constraints,
            "critical,CA:TRUE") != 0)
        goto FAIL;

    if (add_extension(cert, cert, NID_key_usage,
            "critical,keyCertSign,cRLSign") != 0) {
        goto FAIL;
    }

    if (X509_sign(cert, ca_key, EVP_sha256()) <= 0) {
        openssl_error("X509_sign CA certificate failed");
        goto FAIL;
    }

    return cert;

FAIL:
    X509_free(cert);
    return NULL;
}


/**
 * Create a leaf certificate signed by the CA, usable for both TLS
 * server auth (the server's listener) and TLS client auth (a
 * node's outbound mTLS connection). Returns NULL on failure.
 */
static X509*
create_leaf_certificate(EVP_PKEY *key, EVP_PKEY *ca_key, X509 *ca_cert,
                        const char *common_name, const char *san_ip, int days)
{
    char san_value[512];

    X509 *cert = X509_new();
    if (cert == NULL) {
        openssl_error("X509_new failed");
        return NULL;
    }

    X509_set_version(cert, 2);

    if (set_random_serial(cert) != 0)
        goto FAIL;

    if (X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL) {
        openssl_error("notBefore failed");
        goto FAIL;
    }

    if (X509_gmtime_adj(X509_getm_notAfter(cert),
            (long)days * 24L * 60L * 60L) == NULL) {
        openssl_error("notAfter failed");
        goto FAIL;
    }

    // Subject: O=legiond, CN=<common_name> (node hostname or id).
    X509_NAME *subject = X509_get_subject_name(cert);

    X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
        (unsigned char *)"legiond", -1, -1, 0);

    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
        (unsigned char *)common_name, -1, -1, 0);

    if (X509_set_issuer_name(cert, X509_get_subject_name(ca_cert)) != 1) {
        openssl_error("X509_set_issuer_name failed");
        goto FAIL;
    }

    if (X509_set_pubkey(cert, key) != 1) {
        openssl_error("X509_set_pubkey failed");
        goto FAIL;
    }

    if (add_extension(ca_cert, cert, NID_basic_constraints,
            "critical,CA:FALSE") != 0) {
        goto FAIL;
    }

    if (add_extension(ca_cert, cert, NID_key_usage,
            "critical,digitalSignature,keyEncipherment") != 0) {
        goto FAIL;
    }

    // both serverAuth and clientAuth: the server uses this cert
    // to listen, the agent uses the same shape of cert to dial
    // out over mTLS.
    if (add_extension(ca_cert, cert, NID_ext_key_usage,
            "serverAuth,clientAuth") != 0) {
        goto FAIL;
    }

    // Subject Alternative Name. Modern TLS clients validate the
    // SAN rather than CN, so this has to carry the real hostname
    // (and optionally IP) the peer will be dialed as.
    if (san_ip != NULL && san_ip[0] != '\0') {
        snprintf(san_value, sizeof(san_value), "DNS:%s,IP:%s",
            common_name, san_ip);
    } else {
        snprintf(san_value, sizeof(san_value), "DNS:%s", common_name);
    }

    if (add_extension(ca_cert, cert, NID_subject_alt_name, san_value) != 0) {
        goto FAIL;
    }

    if (X509_sign(cert, ca_key, EVP_sha256()) <= 0) {
        openssl_error("X509_sign failed");
        goto FAIL;
    }

    return cert;

FAIL:
    X509_free(cert);
    return NULL;
}


int
pki_generate_ca(const char *ca_key_path, const char *ca_cert_path,int years)
{
    EVP_PKEY *ca_key;
    X509 *ca_cert;

    ca_key = generate_key(CA_KEY_BITS);

    if (ca_key == NULL)
        return 1;

    ca_cert = create_ca_certificate(ca_key, years);

    if (ca_cert == NULL) {
        EVP_PKEY_free(ca_key);
        return 1;
    }

    if (write_private_key(ca_key_path, ca_key) != 0 ||
        write_certificate(ca_cert_path, ca_cert) != 0) {
        return 1;
    }

    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);

    return 0;
}


int
pki_generate_cert_and_key(const char *ca_key_path, const char *ca_cert_path,
                          const char *common_name, const char *san_ip,
                          int days, const char *key_path,
                          const char *cert_path)
{
    EVP_PKEY *leaf_key = NULL;
    X509 *leaf_cert = NULL;
    int rc = 1;

    FILE *fp = fopen(ca_key_path, "r");
    if (fp == NULL) {
        perror(ca_key_path);
        return rc;
    }
    EVP_PKEY *ca_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (ca_key == NULL) {
        openssl_error("PEM_read_PrivateKey (CA) failed");
        return rc;
    }

    fp = fopen(ca_cert_path, "r");
    if (fp == NULL) {
        perror(ca_cert_path);
        EVP_PKEY_free(ca_key);
        return rc;
    }
    X509 *ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (ca_cert == NULL) {
        openssl_error("PEM_read_X509 (CA) failed");
        goto out;
    }

    leaf_key = generate_key(LEAF_KEY_BITS);
    if (leaf_key == NULL) {
        goto out;
    }

    leaf_cert = create_leaf_certificate(leaf_key, ca_key, ca_cert, common_name,
        san_ip, days);
    if (leaf_cert == NULL) {
        goto out;
    }

    if (write_private_key(key_path, leaf_key) == 0 &&
        write_certificate(cert_path, leaf_cert) == 0) {
        rc = 0;
    }

out:
    X509_free(leaf_cert);
    EVP_PKEY_free(leaf_key);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);

    return rc;
}
