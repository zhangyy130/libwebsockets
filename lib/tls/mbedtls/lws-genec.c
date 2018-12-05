/*
 * libwebsockets - generic EC api hiding the backend - mbedtls implementation
 *
 * Copyright (C) 2017 - 2018 Andy Green <andy@warmcat.com>
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
 *  lws_genec provides an EC abstraction api in lws that works the
 *  same whether you are using openssl or mbedtls crypto functions underneath.
 */
#include "core/private.h"

const struct lws_ec_curves lws_ec_curves[] = {
	/*
	 * These are the curves we are willing to use by default...
	 *
	 * The 3 recommended+ (P-256) and optional curves in RFC7518 7.6
	 *
	 * Specific keys lengths from RFC8422 p20
	 */
	{ "P-256", MBEDTLS_ECP_DP_SECP256R1, 32 },
	{ "P-384", MBEDTLS_ECP_DP_SECP384R1, 48 },
	{ "P-521", MBEDTLS_ECP_DP_SECP521R1, 66 },

	{ NULL, 0, 0 }
};

static int
lws_genecdh_keypair_import(struct lws_genecdh_ctx *ctx_dh,
			   enum enum_lws_dh_side side,
			   struct lws_jwk_elements *el)
{
	const struct lws_ec_curves *curve;
	mbedtls_ecdh_context *ctx = ctx_dh->ctx;
	mbedtls_ecp_keypair kp;

	if (el[JWK_EC_KEYEL_CRV].len < 4) {
		lwsl_notice("%s: crv '%s' (%d)\n", __func__,
			    el[JWK_EC_KEYEL_CRV].buf ?
				    (char *)el[JWK_EC_KEYEL_CRV].buf : "null",
			    el[JWK_EC_KEYEL_CRV].len);
		return -21;
	}

	curve = lws_genec_curve(ctx_dh->curve_table,
				(char *)el[JWK_EC_KEYEL_CRV].buf);
	if (!curve)
		return -22;

	if (el[JWK_EC_KEYEL_D].len != curve->key_bytes ||
	    el[JWK_EC_KEYEL_X].len != curve->key_bytes ||
	    el[JWK_EC_KEYEL_Y].len != curve->key_bytes)
		return -23;

	mbedtls_ecp_keypair_init(&kp);
	if (mbedtls_ecp_group_load(&kp.grp, curve->tls_lib_nid))
		goto bail1;

	/* d (the private key) is directly an mpi */

	if (mbedtls_mpi_read_binary(&kp.d, el[JWK_EC_KEYEL_D].buf,
				    el[JWK_EC_KEYEL_D].len))
		goto bail1;

	mbedtls_ecp_set_zero(&kp.Q);

	if (mbedtls_mpi_read_binary(&kp.Q.X, el[JWK_EC_KEYEL_X].buf,
				    el[JWK_EC_KEYEL_X].len))
		goto bail1;

	if (mbedtls_mpi_read_binary(&kp.Q.Y, el[JWK_EC_KEYEL_Y].buf,
				    el[JWK_EC_KEYEL_Y].len))
		goto bail1;

	if (mbedtls_ecdh_get_params (ctx, &kp, side))
		goto bail1;

	mbedtls_ecp_keypair_free(&kp);

	return 0;

bail1:
	mbedtls_ecp_keypair_free(&kp);

	return -1;
}

LWS_VISIBLE int
lws_genecdh_create(struct lws_genecdh_ctx *ctx, struct lws_context *context,
		   const struct lws_ec_curves *curve_table)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->curve_table = curve_table;

	ctx->ctx = lws_zalloc(sizeof(*ctx->ctx), "genec");
	if (!ctx->ctx)
		return 1;

	mbedtls_ecdh_init(ctx->ctx);

	return 0;
}

LWS_VISIBLE int
lws_genecdh_set_key(struct lws_genecdh_ctx *ctx, struct lws_jwk_elements *el,
		    enum enum_lws_dh_side side)
{
	return lws_genecdh_keypair_import(ctx, side, el);
}

LWS_VISIBLE void
lws_genecdh_destroy(struct lws_genecdh_ctx *ctx)
{
	if (ctx->ctx) {
		mbedtls_ecdh_free(ctx->ctx);
		lws_free(ctx->ctx);
		ctx->ctx = NULL;
	}
}

LWS_VISIBLE int
lws_genecdh_new_keypair(struct lws_genecdh_ctx *ctx, enum enum_lws_dh_side side,
			const char *curve_name, struct lws_jwk_elements *el)
{
	const struct lws_ec_curves *curve;
	mbedtls_ecdsa_context ecdsa;
	mbedtls_ecp_keypair *kp;
	mbedtls_mpi *mpi[3];
	int n;

	curve = lws_genec_curve(ctx->curve_table, curve_name);
	if (!curve) {
		lwsl_err("%s: curve '%s' not supported\n",
			 __func__, curve_name);

		return -22;
	}

	mbedtls_ecdsa_init(&ecdsa);
	n = mbedtls_ecdsa_genkey(&ecdsa, curve->tls_lib_nid, lws_genec_rngf,
				 ctx->context);
	if (n) {
		lwsl_err("mbedtls_ecdsa_genkey failed 0x%x\n", -n);
		goto bail1;
	}

	kp = (mbedtls_ecp_keypair *)&ecdsa;

	n = mbedtls_ecdh_get_params(ctx->ctx, kp, side);
	if (n) {
		lwsl_err("mbedtls_ecdh_get_params failed 0x%x\n", -n);
		goto bail1;
	}

	/*
	 * we need to capture the individual element BIGNUMs into
	 * lws_jwk_elements, so they can be serialized, used in jwk etc
	 */

	mpi[0] = &kp->Q.X;
	mpi[1] = &kp->d;
	mpi[2] = &kp->Q.Y;

	el[JWK_EC_KEYEL_CRV].len = strlen(curve_name) + 1;
	el[JWK_EC_KEYEL_CRV].buf = lws_malloc(el[JWK_EC_KEYEL_CRV].len, "ec");
	if (!el[JWK_EC_KEYEL_CRV].buf)
		goto bail1;
	strcpy((char *)el[JWK_EC_KEYEL_CRV].buf, curve_name);

	for (n = JWK_EC_KEYEL_X; n < LWS_COUNT_EC_KEY_ELEMENTS; n++) {
		el[n].len = curve->key_bytes;
		el[n].buf = lws_malloc(curve->key_bytes, "ec");
		if (!el[n].buf)
			goto bail2;

		if (mbedtls_mpi_write_binary(mpi[n - 1], el[n].buf,
					     curve->key_bytes))
			goto bail2;
	}

	mbedtls_ecdsa_free(&ecdsa);

	return 0;

bail2:
	for (n = 0; n < LWS_COUNT_EC_KEY_ELEMENTS; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
bail1:
	mbedtls_ecdsa_free(&ecdsa);

	lws_free(ctx->ctx);

	return -1;
}
#if 0
LWS_VISIBLE int
lws_genec_public_decrypt(struct lws_genecdh_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_max)
{
	size_t olen = 0;
	int n;

	ctx->ctx->len = in_len;
	n = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(ctx->ctx, NULL, NULL,
						MBEDTLS_RSA_PUBLIC,
						&olen, in, out, out_max);
	if (n) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return olen;
}

LWS_VISIBLE int
lws_genec_public_encrypt(struct lws_genecdh_ctx *ctx, const uint8_t *in,
			  size_t in_len, uint8_t *out)
{
	int n;

	//ctx->ctx->len = in_len; // ???
	ctx->ctx->padding = MBEDTLS_RSA_PKCS_V15;
	n = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(ctx->ctx, _rngf, ctx->context,
						MBEDTLS_RSA_PRIVATE,
						in_len, in, out);
	if (n) {
		lwsl_notice("%s: -0x%x: in_len: %d\n", __func__, -n,
				(int)in_len);

		return -1;
	}

	return 0;
}

static int
lws_genec_genec_hash_to_mbed_hash(enum lws_genhash_types hash_type)
{
	int h = -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1:
		h = MBEDTLS_MD_SHA1;
		break;
	case LWS_GENHASH_TYPE_SHA256:
		h = MBEDTLS_MD_SHA256;
		break;
	case LWS_GENHASH_TYPE_SHA384:
		h = MBEDTLS_MD_SHA384;
		break;
	case LWS_GENHASH_TYPE_SHA512:
		h = MBEDTLS_MD_SHA512;
		break;
	}

	return h;
}

LWS_VISIBLE int
lws_genec_public_verify(struct lws_genecdh_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, const uint8_t *sig,
			 size_t sig_len)
{
	int n, h = lws_genec_genec_hash_to_mbed_hash(hash_type);

	if (h < 0)
		return -1;

	n = mbedtls_rsa_rsassa_pkcs1_v15_verify(ctx->ctx, NULL, NULL,
						MBEDTLS_RSA_PUBLIC,
						h, 0, in, sig);
	if (n < 0) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return n;
}

LWS_VISIBLE int
lws_genec_public_sign(struct lws_genecdh_ctx *ctx, const uint8_t *in,
		       enum lws_genhash_types hash_type, uint8_t *sig,
		       size_t sig_len)
{
	int n, h = lws_genec_genec_hash_to_mbed_hash(hash_type);

	if (h < 0)
		return -1;

	/*
	 * The "sig" buffer must be as large as the size of ctx->N
	 * (eg. 128 bytes if RSA-1024 is used).
	 */
	if (sig_len < ctx->ctx->len)
		return -1;

	n = mbedtls_rsa_rsassa_pkcs1_v15_sign(ctx->ctx, NULL, NULL,
					      MBEDTLS_RSA_PRIVATE, h, 0, in,
					      sig);
	if (n < 0) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return ctx->ctx->len;
}

LWS_VISIBLE int
lws_genec_render_pkey_asn1(struct lws_genecdh_ctx *ctx, int _private,
			    uint8_t *pkey_asn1, size_t pkey_asn1_len)
{
	uint8_t *p = pkey_asn1, *totlen, *end = pkey_asn1 + pkey_asn1_len - 1;
	mbedtls_mpi *mpi[LWS_COUNT_RSA_KEY_ELEMENTS] = {
		&ctx->ctx->N, &ctx->ctx->E, &ctx->ctx->D, &ctx->ctx->P,
		&ctx->ctx->Q, &ctx->ctx->DP, &ctx->ctx->DQ,
		&ctx->ctx->QP,
	};
	int n;

	/* 30 82  - sequence
	 *   09 29  <-- length(0x0929) less 4 bytes
	 * 02 01 <- length (1)
	 *  00
	 * 02 82
	 *  02 01 <- length (513)  N
	 *  ...
	 *
	 *  02 03 <- length (3) E
	 *    01 00 01
	 *
	 * 02 82
	 *   02 00 <- length (512) D P Q EXP1 EXP2 COEFF
	 *
	 *  */

	*p++ = 0x30;
	*p++ = 0x82;
	totlen = p;
	p += 2;

	*p++ = 0x02;
	*p++ = 0x01;
	*p++ = 0x00;

	for (n = 0; n < LWS_COUNT_RSA_KEY_ELEMENTS; n++) {
		int m = mbedtls_mpi_size(mpi[n]);
		uint8_t *elen;

		*p++ = 0x02;
		elen = p;
		if (m < 0x7f)
			*p++ = m;
		else {
			*p++ = 0x82;
			*p++ = m >> 8;
			*p++ = m & 0xff;
		}

		if (p + m > end)
			return -1;

		mbedtls_mpi_write_binary(mpi[n], p, m);
		if (p[0] & 0x80) {
			p[0] = 0x00;
			mbedtls_mpi_write_binary(mpi[n], &p[1], m);
			m++;
		}
		if (m < 0x7f)
			*elen = m;
		else {
			*elen++ = 0x82;
			*elen++ = m >> 8;
			*elen = m & 0xff;
		}
		p += m;
	}

	n = lws_ptr_diff(p, pkey_asn1);

	*totlen++ = (n - 4) >> 8;
	*totlen = (n - 4) & 0xff;

	return n;
}
#endif
