/*
 *   Copyright (c) 2023
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
 *   along with this program; if not, contact Canonical Ltd.
 */

#ifndef __AA_ALL_H
#define __AA_ALL_H

#include "rule.h"

#define AA_IO_URING_OVERRIDE_CREDS AA_MAY_APPEND
#define AA_IO_URING_SQPOLL AA_MAY_CREATE

#define AA_VALID_IO_URING_PERMS (AA_IO_URING_OVERRIDE_CREDS | \
				 AA_IO_URING_SQPOLL)

class all_rule: public prefix_rule_t {
	void move_conditionals(struct cond_entry *conds);
public:
	char *label;

	all_rule(void): prefix_rule_t(RULE_TYPE_ALL) { }

	virtual bool valid_prefix(const prefixes &p, const char *&error) {
		if (p.owner) {
			error = _("owner prefix not allowed on all rules");
			return false;
		}
		return true;
	};

	int expand_variables(void)
	{
		return 0;
	}
	virtual ostream &dump(ostream &os) {
		prefix_rule_t::dump(os);

		os << "all";

		return os;
	}
	virtual bool is_mergeable(void) { return true; }
	virtual int cmp(rule_t const &rhs) const
	{
		return prefix_rule_t::cmp(rhs);
	};

	virtual void add_implied_rules(Profile &prof);

	virtual int gen_policy_re(Profile &prof unused) { return RULE_OK; };

protected:
  virtual void warn_once(const char *name unused, const char *msg unused) { };
  virtual void warn_once(const char *name unused)  { };
};

#endif /* __AA_ALL_H */
