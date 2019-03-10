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
#include "ndn-lite/forwarder/forwarder.h"
#include "ndn-lite/face/direct-face.h"
#include "adaptation/udp-multicast/ndn-udp-multicast-face.h"
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
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
char* defaultaddr = "225.0.0.37";
in_addr_t multicast_ip;
uint8_t receiving_buff[4096] = {0};
ndn_udp_multicast_face_t* udp_face;
uint8_t buffer[4096];

int
parseArgs(int argc, char *argv[]) {
  char *sz_addr;

  if (argc < 2) {
    sz_addr = defaultaddr;
  }
  else
    sz_addr = argv[1];

  if (sizeof(sz_addr) <= 0) {
    fprintf(stderr, "ERROR: wrong arguments.\n");
    return 1;
  }

  multicast_ip = inet_addr(sz_addr);
  return 0;
}

void
print_error(const char *test_name, const char *fnct_name, const char *funct_failed, int err_code) {
  printf("In %s test, within call to %s, call to %s failed, error code: %d\n",
         test_name, fnct_name, funct_failed, err_code);
}

int
on_time_data(const uint8_t* data, uint32_t data_size)
{
  printf("data:\n");
  // parse response Data
  ndn_data_t response;
  int ret_val = ndn_data_tlv_decode_digest_verify(&response, data, data_size);
  if (ret_val != 0) {
    printf("producer", "on_data", "ndn_data_tlv_decode_digest_verify", ret_val);
  }

  printf("The current time is: %s\n", response.content_value);

  return 0;
}

void
send_time_request()
{
  ndn_name_t interest_name;
  char interest_name_str[] = "/ndn/SD/erynn/time/now";
  int ret_val = ndn_name_from_string(&interest_name, interest_name_str, strlen(interest_name_str));

  ndn_interest_t interest;
  ndn_interest_from_name(&interest, &interest_name);
  ndn_encoder_t encoder;
  encoder_init(&encoder, buffer, 4096);

  //construct interest without signature
  ndn_interest_tlv_encode(&encoder, &interest);

  //send interest
  ndn_direct_face_express_interest(&interest_name, encoder.output_value, encoder.offset,
                                   on_time_data, NULL);
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

  send_time_request();
  return 0;
}

int
main(int argc, char *argv[])
{
  int ret_val = -1;
  if ((ret_val = parseArgs(argc, argv)) != 0) {
    return ret_val;
  }

  // init security
  ndn_security_init();

  // set home prefix
  ndn_name_t home_prefix;
  char home_prefix_str[] = "/ndn";
  ret_val = ndn_name_from_string(&home_prefix, home_prefix_str, strlen(home_prefix_str));
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

  // set up direct face and forwarder
  ndn_forwarder_init();
  ndn_direct_face_construct(666);

  // add routes to the network
  udp_face = ndn_udp_multicast_face_construct(667, INADDR_ANY, 6363, multicast_ip);
  char prefix_string[] = "/ndn";
  ndn_name_t prefix;
  ret_val = ndn_name_from_string(&prefix, prefix_string, sizeof(prefix_string));
  if (ret_val != 0) {
    print_error("consumer", "add routes", "ndn_name_from_string", ret_val);
  }
  ndn_forwarder_fib_insert(&prefix, &udp_face->intf, 0);

  // prepare DK Interest for AC
  ndn_encoder_t interest_encoder;
  encoder_init(&interest_encoder, buffer, sizeof(buffer));
  ret_val = ndn_ac_prepare_key_request_interest(&interest_encoder, &home_prefix,
                                                &component_consumer, 100, prv_key, 0);
  if (ret_val != 0) {
    print_error("consumer", "prepare DK Interest", "ndn_ac_prepare_key_request", ret_val);
    return -1;
  }

  // send out Interest to the AC controller
  ndn_interest_t interest;
  ndn_interest_from_block(&interest, interest_encoder.output_value, interest_encoder.offset);
  ndn_direct_face_express_interest(&interest.name, interest_encoder.output_value,
                                   interest_encoder.offset, on_data, NULL);

  int count = 0;
  while (count < 10000) {
    ndn_udp_multicast_face_recv(udp_face);
    usleep(10);
    count++;
  }

  return 0;
}
