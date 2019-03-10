#include "yu-prnt-cmd-chk.h"

ndn_trust_schema_rule_t yu_rule;

ndn_name_t yu_print_interest_name;

const char init_pref[] = "init_yu_prnt_cmd_chk_interest";

int init_yu_prnt_cmd_chk(void) {

  int ret_val = -1;
  
  ret_val = ndn_trust_schema_rule_from_strings(&yu_rule,
					       yu_rule_data_pattern_string, sizeof(yu_rule_data_pattern_string),
					       yu_rule_key_pattern_string, sizeof(yu_rule_key_pattern_string));
  if (ret_val != 0) {
    printf("%sndn_trust_schema_rule_from_strings failed, error code: %d\n", init_pref, ret_val);
    return ret_val;
  }

  ret_val = ndn_name_from_string(&yu_print_interest_name, yu_prnt_cmd_string, sizeof(yu_prnt_cmd_string));
  if (ret_val != 0) {
    printf("%sndn_name_from_string failed, error code: %d.\n", init_pref, ret_val);
    return ret_val;
  }

  return 0;
  
}

int _check_interest_signature(ndn_interest_t *interest, ndn_ecc_pub_t *pub_key) {
  return ndn_signed_interest_ecdsa_verify(interest, pub_key);
}

int _check_interest_names(ndn_interest_t *interest, ndn_trust_schema_rule_t *rule) {

  int ret_val = -1;
  
  printf("Number of name components in name of interest being checked: %d\n", interest->name.components_size);
  printf("Name of interest being checked: ");
  for (uint32_t i = 0; i < interest->name.components_size; i++) {
    printf("/%.*s", interest->name.components[i].size, interest->name.components[i].value);
  }
  printf("\n");

  printf("Number of name components in key locator of interest being checked: %d\n", interest->signature.key_locator_name.components_size);
  printf("Name of key locator of interest being checked: ");
  for (uint32_t i = 0; i < interest->signature.key_locator_name.components_size; i++) {
    printf("/%.*s", interest->signature.key_locator_name.components[i].size, interest->signature.key_locator_name.components[i].value);
  }
  printf("\n");
  
  ret_val = ndn_trust_schema_verify_data_name_key_name_pair(rule, &interest->name, &interest->signature.key_locator_name);
  if (ret_val != 0) return ret_val;

  return 0;
  
}

int check_interest(ndn_interest_t *interest, ndn_trust_schema_rule_t *rule, ndn_ecc_pub_t *pub_key) {

  int ret_val = -1;

  printf("check_interest was used to check interest with name (nuber of name components: %d):\n", interest->name.components_size);
  for (uint32_t i = 0; i < interest->name.components_size; i++) {
    printf("/%.*s", interest->name.components[i].size, interest->name.components[i].value);
  }
  printf("\n");

  ret_val = _check_interest_signature(interest, pub_key);
  if (ret_val != 0) return ret_val;

  if (interest->name.components_size >= yu_print_interest_name.components_size &&
      ndn_name_compare_sub_names(&interest->name, 0, yu_print_interest_name.components_size,
				 &yu_print_interest_name, 0, yu_print_interest_name.components_size)) {
    printf("In check_interest, found that the interest passed in was an interest to access printing service.\n");
    if (rule == NULL) {
      printf("In check_interest, found that an interest was supposed to be checked against schema, but no rule was passed in.\n");
      return -1;
      
    }
    ret_val = _check_interest_names(interest, rule);
    if (ret_val != 0) return ret_val;
  }
  else {
    printf("In check_interest, found that the interest passed in was not an interest to access printing service.\n");
    return 0;
  }

  return 0;
  
}
