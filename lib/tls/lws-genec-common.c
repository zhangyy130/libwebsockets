/*
 * libwebsockets - generic EC api hiding the backend - common parts
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

int
lws_genec_rngf(void *context, unsigned char *buf, size_t len)
{
	if ((size_t)lws_get_random(context, buf, len) == len)
		return 0;

	return -1;
}

const struct lws_ec_curves *
lws_genec_curve(const struct lws_ec_curves *table, const char *name)
{
	const struct lws_ec_curves *c = lws_ec_curves;

	if (table)
		c = table;

	while (c->name) {
		if (!strcmp(name, c->name))
			return c;
		c++;
	}

	return NULL;
}

LWS_VISIBLE void
lws_jwk_destroy_genec_elements(struct lws_jwk_elements *el)
{
	int n;

	for (n = 0; n < LWS_COUNT_EC_KEY_ELEMENTS; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
}

static const char *enames[] = { "crv", "x", "d", "y" };

LWS_VISIBLE int
lws_genec_dump(struct lws_jwk_elements *el)
{
	int n;

	lwsl_info("  genec %p: crv: '%s'\n", el, !!el[JWK_EC_KEYEL_CRV].buf ?
			(char *)el[JWK_EC_KEYEL_CRV].buf: "no curve name");

	for (n = JWK_EC_KEYEL_X; n < LWS_COUNT_EC_KEY_ELEMENTS; n++) {
		lwsl_info("  e: %s\n", enames[n]);
		lwsl_hexdump_info(el[n].buf, el[n].len);
	}

	lwsl_info("\n");

	return 0;
}
