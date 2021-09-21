/*
 *   Copyright (c) 2014
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
#ifndef __AA_RULE_H
#define __AA_RULE_H

#include <list>
#include <ostream>

#include "policydb.h"

using namespace std;

class Profile;

#define RULE_NOT_SUPPORTED 0
#define RULE_ERROR -1
#define RULE_OK 1

#define RULE_TYPE_RULE		0
#define RULE_TYPE_PREFIX	1
#define RULE_TYPE_PERMS		2
// RULE_TYPE_CLASS needs to be last because various class follow it
#define RULE_TYPE_CLASS		3


class rule_t {
public:
	int rule_type;

	rule_t(int t): rule_type(t) { }
	virtual ~rule_t() { };

	bool is_type(int type) { return rule_type == type; }

	//virtual bool operator<(rule_t const &rhs)const = 0;
	virtual std::ostream &dump(std::ostream &os) = 0;

	// Follow methods in order of being called by the parse

	// called when profile is finished parsing
	virtual void post_parse_profile(Profile &prof __attribute__ ((unused))) { };

	// called before final expansion of variables. So implied rules
	// can reference variables
	virtual void add_implied_rules(Profile &prof __attribute__ ((unused))) { };

	// currently only called post parse
	// needs to change to being interatively called during parse
	// to support expansion in include names and profile names
	virtual int expand_variables(void) = 0;

	// called late frontend to generate data for regex backend
	virtual int gen_policy_re(Profile &prof) = 0;

protected:
	const char *warned_name = NULL;
	virtual void warn_once(const char *name, const char *msg);
	virtual void warn_once(const char *name) = 0;


};

std::ostream &operator<<(std::ostream &os, rule_t &rule);

typedef std::list<rule_t *> RuleList;

/* Not classes so they can be used in the bison front end */
typedef uint32_t perms_t;
typedef enum { AUDIT_UNSPECIFIED, AUDIT_FORCE, AUDIT_QUIET } audit_t;
typedef enum { RULE_UNSPECIFIED, RULE_ALLOW, RULE_DENY } rule_mode_t;

/* NOTE: we can not have a constructor for class prefixes. This is
 * because it will break bison, and we would need to transition to
 * the C++ bison bindings. Instead get around this by using a
 * special rule class that inherits prefixes and handles the
 * contruction
 */
class prefixes {
public:
	audit_t audit;
	rule_mode_t rule_mode;
	int owner;

	ostream &dump(ostream &os)
	{
		bool output = true;

		switch (audit) {
		case AUDIT_FORCE:
			os << "audit";
			break;
		case AUDIT_QUIET:
			os << "quiet";
			break;
		default:
			output = false;
		}

		switch (rule_mode) {
		case RULE_DENY:
			if (output)
				os << " ";

			os << "deny";
			output = true;
			break;
		default:
			break;
		}

		if (owner) {
			if (output)
				os << " ";
			os << "owner";
			output = true;
		}

		if (output)
			os << " ";

		return os;
	}
};

class prefix_rule_t: public rule_t, public prefixes {
public:
	prefix_rule_t(int t = RULE_TYPE_PREFIX) : rule_t(t)
	{
		/* Must construct prefix here see note on prefixes */
		audit = AUDIT_UNSPECIFIED;
		rule_mode = RULE_UNSPECIFIED;
		owner = 0;
	};

	virtual bool valid_prefix(const prefixes &p, const char *&error) = 0;

	virtual bool add_prefix(const prefixes &p, const char *&error) {
		if (!valid_prefix(p, error))
			return false;
		/* audit conflicts */
		if (p.audit != AUDIT_UNSPECIFIED) {
			if (audit != AUDIT_UNSPECIFIED &&
			    audit != p.audit) {
				error = "conflicting audit prefix";
				return false;
			}
//			audit = p.audit;
		}

		/* allow deny conflicts */
		if (p.rule_mode != RULE_UNSPECIFIED) {
			if (rule_mode != RULE_UNSPECIFIED &&
			    rule_mode != p.rule_mode) {
				error = "conflicting mode prefix";
				return false;
			}
			rule_mode = p.rule_mode;
		}

		/* owner !owner conflicts */
		if (p.owner) {
			if (owner && owner != p.owner) {
				error = "conflicting owner prefix";
				return false;
			}
			owner = p.owner;
		}

		/* does the prefix imply a modifier */
		if (p.rule_mode == RULE_DENY && p.audit == AUDIT_FORCE) {
			rule_mode = RULE_DENY;
		} else if (p.rule_mode == RULE_DENY) {
			rule_mode = RULE_DENY;
			audit = AUDIT_FORCE;
		} else if (p.audit != AUDIT_UNSPECIFIED) {
			audit = p.audit;
		}

		return true;
	}

	virtual ostream &dump(ostream &os) {
		prefixes::dump(os);

		return os;
	}

};

/* NOTE: rule_type is RULE_TYPE_CLASS + AA_CLASS */
class class_rule_t: public prefix_rule_t {
public:
	class_rule_t(int c): prefix_rule_t(RULE_TYPE_CLASS + c) { }

	int aa_class(void) { return rule_type - RULE_TYPE_CLASS; }

	virtual ostream &dump(ostream &os) {
		prefix_rule_t::dump(os);

		os << aa_class_table[aa_class()];

		return os;
	}

};

class perms_rule_t: public class_rule_t {
public:
	perms_rule_t(int c): class_rule_t(c), perms(0) { };

	/* defaut perms, override/mask off if none default used */
	virtual ostream &dump(ostream &os) {

		return os;
	}

	perms_t perms;

};

#endif /* __AA_RULE_H */

