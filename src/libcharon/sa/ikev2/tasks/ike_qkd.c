/*
 * Copyright (C) 2009 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/*
 * Copyright (C) 2016 Thomas Egerer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "ike_qkd.h"

#include <daemon.h>
#include <encoding/payloads/qkd_payload.h>

typedef struct private_ike_qkd_t private_ike_qkd_t;

/**
 * Private data of an ike_qkd_t object.
 */
struct private_ike_qkd_t {

	/**
	 * Public ike_qkd_t interface.
	 */
	ike_qkd_t public;

	/**
	 * Associated IKE_SA
	 */
	ike_sa_t *ike_sa;

	/**
	 * Are we the initiator of this task
	 */
	bool initiator;
};

/**
 * QKD data
 */
typedef struct {
	/* qkd ID string */
	char *id;
    /* qkd ID string */
	char *key;
} qkd_data_t;

/**
 * Get the data of a qkd ID as a chunk
 */
static inline chunk_t get_qkd_data(qkd_data_t *data)
{
	return chunk_create(data->id, strlen(data->id));
}


METHOD(task_t, build, status_t,
	private_ike_qkd_t *this, message_t *message)
{
    DBG1(DBG_IKE, "\t\t**********Me están llamando desde build:ike_qkd.c (%d)", PLV2_QKD);
	/*qkd_payload_t *qkd;
    char *id = "id de prueba";
    qkd_data_t data = { id, id };
    qkd = qkd_payload_create(PLV2_QKD);
    message->add_payload(message, &qkd->payload_interface);*/
    DBG1(DBG_IKE, "\t\t**********Me están llamando desde build:ike_qkd.c [FIN]");
	return this->initiator ? NEED_MORE : SUCCESS;
}

/**
 * Check if the given known qkd ID matches a received VID or its prefix
 */
static inline bool known_qkd_id(qkd_data_t *qkd, chunk_t data)
{
	chunk_t known = get_qkd_data(qkd);

	if (qkd->id)
	{
		data.len = min(data.len, known.len);
	}
	return chunk_equals(known, data);
}

METHOD(task_t, process, status_t,
	private_ike_qkd_t *this, message_t *message)
{

	return this->initiator ? SUCCESS : NEED_MORE;
}

METHOD(task_t, migrate, void,
	private_ike_qkd_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

METHOD(task_t, get_type, task_type_t,
	private_ike_qkd_t *this)
{
	return TASK_IKE_QKD_KE;
}

METHOD(task_t, destroy, void,
	private_ike_qkd_t *this)
{
	free(this);
}

/**
 * See header
 */
ike_qkd_t *ike_qkd_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_qkd_t *this;

	INIT(this,
		.public = {
			.task = {
				.build = _build,
				.process = _process,
				.migrate = _migrate,
				.get_type = _get_type,
				.destroy = _destroy,
			},
		},
		.initiator = initiator,
		.ike_sa = ike_sa,
	);

	return &this->public;
}


