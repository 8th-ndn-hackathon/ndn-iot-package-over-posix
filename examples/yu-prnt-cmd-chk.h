#ifndef YU_PRNT_CMD_CHK_H
#define YU_PRNT_CMD_CHK_H

#include "ndn-lite/encode/name.h"
#include "ndn-lite/ndn-error-code.h"
#include "ndn-lite/security/ndn-trust-schema.h"
#include "ndn-lite/encode/trust-schema/ndn-trust-schema-pattern-component.h"
#include "ndn-lite/encode/trust-schema/ndn-trust-schema-pattern.h"
#include "ndn-lite/encode/trust-schema/ndn-trust-schema-rule.h"
#include "ndn-lite/encode/ndn-rule-storage.h"
#include "ndn-lite/encode/signed-interest.h"
#include "ndn-lite/encode/interest.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/security/ndn-lite-ecc.h"

#define yu_prnt_cmd_string "/ndn/SD/Yu/print/hello_world"
#define yu_rule_data_pattern_string "<ndn><SD><Yu><print><><>"
#define yu_rule_key_pattern_string "<ndn><Yu><KEY><>"

extern ndn_trust_schema_rule_t yu_rule;

int init_yu_prnt_cmd_chk(void);

int check_interest(ndn_interest_t *interest, ndn_trust_schema_rule_t *rule, ndn_ecc_pub_t *pub_key);

#endif // YU_PRNT_CMD_CHK_H
