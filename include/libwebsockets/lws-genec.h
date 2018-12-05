/*
 * libwebsockets - Generic Elliptic Curve Encryption
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * included from libwebsockets.h
 */

/* include/libwebsockets/lws-jwk.h must be included before this */

struct lws_genecdh_ctx {
#if defined(LWS_WITH_MBEDTLS)
	mbedtls_ecdh_context *ctx;
#else
	EVP_PKEY_CTX *ctx;
	EVP_PKEY_CTX *ctx_peer;
#endif
	struct lws_context *context;
	const struct lws_ec_curves *curve_table;
};

#if defined(LWS_WITH_MBEDTLS)
enum enum_lws_dh_side {
	LDHS_OURS = MBEDTLS_ECDH_OURS,
	LDHS_THEIRS = MBEDTLS_ECDH_THEIRS
};
#else
enum enum_lws_dh_side {
	LDHS_OURS,
	LDHS_THEIRS
};
#endif

struct lws_ec_curves {
	const char *name;
	int tls_lib_nid;
	short key_bytes;
};

/** lws_genecdh_create() - Create a genec and public / private key
 *
 * \param ctx: your genecdh context
 * \param context: your lws_context (for RNG access)
 * \param curve_table: NULL, enabling P-256, P-384 and P-521, or a replacement
 *		       struct lws_ec_curves array, terminated by an entry with
 *		       .name = NULL, of curves you want to whitelist
 *
 * Initializes a genecdh
 */
LWS_VISIBLE int
lws_genecdh_create(struct lws_genecdh_ctx *ctx, struct lws_context *context,
		   const struct lws_ec_curves *curve_table);

/** lws_genecdh_set_key() - Apply an EC key to our or theirs side
 *
 * \param ctx: your genecdh context
 * \param el: your key elements
 * \param side: LDHS_OURS or LDHS_THEIRS
 *
 * Applies an EC key to one side or the other of an ECDH ctx
 */
LWS_VISIBLE LWS_EXTERN int
lws_genecdh_set_key(struct lws_genecdh_ctx *ctx, struct lws_jwk_elements *el,
		    enum enum_lws_dh_side side);

LWS_VISIBLE LWS_EXTERN void
lws_genecdh_destroy(struct lws_genecdh_ctx *ctx);

LWS_VISIBLE LWS_EXTERN void
lws_jwk_destroy_genec_elements(struct lws_jwk_elements *el);

LWS_VISIBLE LWS_EXTERN int
lws_genec_dump(struct lws_jwk_elements *el);

/** lws_genecdh_new_keypair() - Create a genec with a new public / private key
 *
 * \param ctx: your genec context
 * \param curve_name: an EC curve name, like "P-256"
 * \param el: array pf LWS_COUNT_EC_KEY_ELEMENTS key elements to take the new key
 * \param curve_table: NULL, enabling P-256, P-384 and P-521, or a replacement
 *		       struct lws_ec_curves array, terminated by an entry with
 *		       .name = NULL, of curves you want to whitelist
 * \param context: your lws_context (for RNG access)
 *
 * Creates a genec with a newly minted EC public / private key
 */
LWS_VISIBLE LWS_EXTERN int
lws_genecdh_new_keypair(struct lws_genecdh_ctx *ctx, enum enum_lws_dh_side side,
		        const char *curve_name, struct lws_jwk_elements *el);
