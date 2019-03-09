/*
 * Copyright (C) 2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite/app-support/access-control.h"
#include "ndn-lite/encode/signed-interest.h"
#include "ndn-lite/encode/key-storage.h"
#include "../ndn-riot-tests/print-helpers.h"
#include <stdio.h>

const uint8_t prv[] = {
  0x5D, 0xC7, 0x6B, 0xAB, 0xEE, 0xD4, 0xEB, 0xB7, 0xBA, 0xFC,
  0x64, 0xE7, 0x8B, 0xDB, 0x22, 0xE1, 0xF4, 0x37, 0x10, 0xC2,
  0xEA, 0xE9, 0xDD, 0xAF, 0xF4, 0x74, 0xB3, 0x18, 0x08, 0x56,
  0x5E, 0x4C
};

const uint8_t pub[] = {
  0x36, 0xF7, 0xEF, 0x7C, 0x05, 0x10, 0x68, 0xC4, 0x6C, 0x67,
  0x63, 0x2A, 0xF5, 0x82, 0x1D, 0x14, 0xBA, 0xCC, 0x50, 0x12,
  0x73, 0x73, 0xED, 0xDE, 0x7D, 0x23, 0x5D, 0x20, 0xA8, 0x5E,
  0xD1, 0x83, 0x3C, 0x0F, 0xB7, 0xD2, 0x6E, 0xB2, 0x0F, 0x8B,
  0x09, 0x1D, 0xD0, 0xF3, 0xB9, 0xAA, 0x56, 0x11, 0x1D, 0x15,
  0x0C, 0xAC, 0xE4, 0xFA, 0x9F, 0x6C, 0x61, 0xB4, 0xFF, 0x41,
  0xE8, 0xBA, 0x21, 0x89
};

ndn_ecc_pub_t* pub_key = NULL;
ndn_ecc_prv_t* prv_key = NULL;

void
print_error(const char *test_name, const char *fnct_name, const char *funct_failed, int err_code) {
  printf("In %s test, within call to %s, call to %s failed, error code: %d\n",
         test_name, fnct_name, funct_failed, err_code);
}

int
on_data(const uint8_t* data, uint32_t data_size)
{
  printf("Get DK Data\n");

  // parse response Data
  ndn_data_t response;
  int ret_val = ndn_data_tlv_decode_ecdsa_verify(&response, data, data_size, pub_key);
  if (ret_val != 0) {
    print_error("producer", "on_data", "ndn_data_tlv_decode_ecdsa_verify", ret_val);
  }

  // update ac state
  ret_val = ndn_ac_on_ek_response_process(&response);
  if (ret_val != 0) {
    print_error("producer", "on_data", "ndn_ac_on_ek_response", ret_val);
  }

  return 0;
}

int
main(void)
{
  // init security
  ndn_security_init();

  // set home prefix
  ndn_name_t home_prefix;
  char* home_prefix_str = "/ndn";
  int ret_val = ndn_name_from_string(&home_prefix, home_prefix_str, sizeof(home_prefix_str));
  if (ret_val != 0) {
    print_error("consumer", "set home prefix", "ndn_name_from_string", ret_val);
    return -1;
  }

  // set identity name
  char comp_consumer[] = "consumer";
  name_component_t component_consumer;
  ret_val = name_component_from_string(&component_consumer, comp_consumer, sizeof(comp_consumer));
  if (ret_val != 0) {
    print_error("consumer", "set identity name", "name_component_from_string", ret_val);
    return -1;
  }
  ndn_name_t consumer_identity = home_prefix;
  ret_val = ndn_name_append_component(&consumer_identity, &component_consumer);
  if (ret_val != 0) {
    print_error("consumer", "set identity name", "ndn_name_append_component", ret_val);
    return -1;
  }

  // init keys
  ndn_key_storage_init();
  ndn_key_storage_get_empty_ecc_key(&pub_key, &prv_key);
  ret_val = ndn_ecc_prv_init(prv_key, prv, sizeof(prv),
                             NDN_ECDSA_CURVE_SECP256R1, 123);
  if (ret_val != 0) {
    print_error("consumer", "init keys", "ndn_ecc_prv_init", ret_val);
    return -1;
  }
  ret_val = ndn_ecc_pub_init(pub_key, pub, sizeof(pub),
                             NDN_ECDSA_CURVE_SECP256R1, 123);
  if (ret_val != 0) {
    print_error("consumer", "init keys", "ndn_ecc_pub_init", ret_val);
    return -1;
  }

  // init ac state
  ndn_ac_state_init(&consumer_identity, pub_key, prv_key);

  // prepare DK Interest
  uint8_t buffer[1024];
  ndn_encoder_t interest_encoder;
  encoder_init(&interest_encoder, buffer, sizeof(buffer));
  ret_val = ndn_ac_prepare_key_request_interest(&interest_encoder, &home_prefix,
                                                &component_consumer, 100, prv_key, 0);
  if (ret_val != 0) {
    print_error("consumer", "prepare DK Interest", "ndn_ac_prepare_key_request", ret_val);
    return -1;
  }

  // set up face and connection

  return 0;
}