/*
 *   Copyright (c) 2024
 *   Canonical Ltd. (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */

#include "cond_expr.h"
#include "parser.h"

cond_expr::cond_expr(bool result):
	result(result)
{
}

cond_expr::cond_expr(const char *var, bool defined)
{
	char *var_name = process_var(var);

	if (!defined) {
		int ret = get_boolean_var(var_name);
		if (ret < 0) {
			/* FIXME check for set var */
			free(var_name);
			yyerror(_("Unset boolean variable %s used in if-expression"), var);
		}
		result = ret;
	} else {
		void *set_value = get_set_var(var_name);
		PDEBUG("Matched: defined set expr %s value %lx\n", var_name, (long) set_value);
		result = !! (long) set_value;
	}
	free(var_name);
}
