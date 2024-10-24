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

/**
 * @defgroup ike_qkd ike_qkd
 * @{ @ingroup tasks_v2
 */

#ifndef IKE_QKD_H_
#define IKE_QKD_H_

typedef struct ike_qkd_t ike_qkd_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/task.h>

/**
 * Vendor ID processing task.
 */
struct ike_qkd_t {

	/**
	 * Implements task interface.
	 */
	task_t task;
};

/**
 * Create a ike_qkd instance.
 *
 * @param ike_sa		IKE_SA this task works for
 * @param initiator		TRUE if task is the original initiator
 */
ike_qkd_t *ike_qkd_create(ike_sa_t *ike_sa, bool initiator);

#endif /** IKE_QKD_H_ @}*/
