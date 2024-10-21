/*
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

/**
 * @defgroup qkd_payload qkd_payload
 * @{ @ingroup payloads
 */

#ifndef QKD_PAYLOAD_H_
#define QKD_PAYLOAD_H_

typedef struct qkd_payload_t qkd_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>

/**
 * Class representing an IKEv1/IKEv2 VENDOR ID payload.
 *
 * The VENDOR ID payload format is described in RFC section 3.12.
 */
struct qkd_payload_t {

	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Get the VID data.
	 *
	 * @return		VID data, pointing to an internal chunk_t
	 */
	chunk_t (*get_data)(qkd_payload_t *this);

	/**
	 * Destroy Vendor ID payload.
	 */
	void (*destroy)(qkd_payload_t *this);
};

/**
 * Creates an empty Vendor ID payload for IKEv1 or IKEv2.
 *
 * @@param type		PLV2_qkd or PLV1_qkd
 * @return			vendor ID payload
 */
qkd_payload_t *qkd_payload_create(payload_type_t type);

/**
 * Creates a vendor ID payload using a chunk of data
 *
 * @param type		PLV2_qkd or PLV1_qkd
 * @param data		data to use in vID key qkd payload, gets owned by payload
 * @return			vendor ID payload
 */
qkd_payload_t *qkd_payload_create_data(payload_type_t type,
												   chunk_t data);

#endif /** qkd_PAYLOAD_H_ @}*/
