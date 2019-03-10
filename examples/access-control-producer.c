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
#include <sys/time.h>
#include <time.h>

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

const uint8_t iv[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

ndn_ecc_pub_t* pub_key = NULL;
ndn_ecc_prv_t* prv_key = NULL;
ndn_aes_key_t* aes_key = NULL;
uint8_t buffer[4096] = {0};
char defaultaddr[] = "225.0.0.37";
in_addr_t multicast_ip;
ndn_udp_multicast_face_t* udp_face;

int
parseArgs(int argc, char *argv[]) {
  char *sz_addr;

  if (argc < 2) {
    sz_addr = defaultaddr;
  }
  else
    sz_addr = argv[1];

  if (strlen(sz_addr) <= 0) {
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
on_data(const uint8_t* data, uint32_t data_size)
{
  printf("Get EK Data\n");

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

  // check whether the key is in the key storage
  ndn_key_storage_get_aes_key(100, &aes_key);
  if (aes_key == NULL) {
    print_error("producer", "on_data", "ndn_key_storage_get_aes_key", ret_val);
  }
  return 0;
}

int
on_interest1(const uint8_t* interest, uint32_t interest_size)
{
  return 0;
}


int
on_interest2(const uint8_t* interest, uint32_t interest_size)
{
  int ret_val = -1;
  ndn_encoder_t encoder;
  struct timeval tv;

  printf("Inside the on_interest function\n");

  ndn_interest_t interest1;
  ndn_interest_from_block(&interest1, interest, interest_size);

  ndn_name_t name1 = interest1.name;

  for (int i=0; i < name1.components_size; i++) {
    printf("/%.*s", name1.components[i].size, name1.components[i].value);
  }
  printf("\n");
  printf("components_size: %d\n", name1.components_size);

  printf("is_SignedInterest = %d\n", interest1.is_SignedInterest);

  if (interest1.is_SignedInterest > 0) {
    if (ndn_signed_interest_digest_verify(&interest1) != 0) {
      printf("invalid signature.\n");
      return 1;
    } else {
      printf("valid signature.\n");
    }
  } else {
    printf("no signature\n");
  }

  // send data
  gettimeofday(&tv, NULL);
  char data_string[50];

  struct tm *current_time = localtime(&(tv.tv_sec));
  strftime(data_string, 50, "the time is %H:%M:%S\n", current_time);

  ndn_data_t data;
  data.name = interest1.name;

  // encrypt the content
  if (aes_key == NULL) {
    char keyid_string[] = "/ndn/SD/erynn/time/KEY/100";
    ndn_name_t keyid;
    ret_val = ndn_name_from_string(&keyid, keyid_string, sizeof(keyid_string));
    ndn_data_set_encrypted_content(&data, (uint8_t*)data_string, strlen(data_string),
                                   &keyid, iv, aes_key);
  }
  else {
    ndn_data_set_content(&data, data_string, strlen(data_string));
  }

  ndn_metainfo_init(&data.metainfo);
  ndn_metainfo_set_content_type(&data.metainfo, NDN_CONTENT_TYPE_BLOB);
  encoder_init(&encoder, buffer, 4096);
  ndn_data_tlv_encode_digest_sign(&encoder, &data);
  ndn_forwarder_on_incoming_data(ndn_forwarder_get_instance(),
                                 &udp_face->intf, &data.name,
                                 encoder.output_value, encoder.offset);

  return NDN_SUCCESS;
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
  ret_val = ndn_name_from_string(&home_prefix, home_prefix_str, sizeof(home_prefix_str));
  if (ret_val != 0) {
    print_error("producer", "set home prefix", "ndn_name_from_string", ret_val);
    return -1;
  }

  // set identity name
  char comp_producer[] = "producer";
  name_component_t component_producer;
  ret_val = name_component_from_string(&component_producer, comp_producer, sizeof(comp_producer));
  if (ret_val != 0) {
    print_error("producer", "set identity name", "name_component_from_string", ret_val);
    return -1;
  }
  ndn_name_t producer_identity = home_prefix;
  ret_val = ndn_name_append_component(&producer_identity, &component_producer);
  if (ret_val != 0) {
    print_error("producer", "set identity name", "ndn_name_append_component", ret_val);
    return -1;
  }

  // init keys
  ndn_key_storage_init();
  ndn_key_storage_get_empty_ecc_key(&pub_key, &prv_key);
  ret_val = ndn_ecc_prv_init(prv_key, prv, sizeof(prv),
                             NDN_ECDSA_CURVE_SECP256R1, 123);
  if (ret_val != 0) {
    print_error("producer", "init keys", "ndn_ecc_prv_init", ret_val);
    return -1;
  }
  ret_val = ndn_ecc_pub_init(pub_key, pub, sizeof(pub),
                             NDN_ECDSA_CURVE_SECP256R1, 123);
  if (ret_val != 0) {
    print_error("producer", "init keys", "ndn_ecc_pub_init", ret_val);
    return -1;
  }

  // init AC state
  ndn_ac_state_init(&producer_identity, pub_key, prv_key);

  // set up direct face and forwarder
  ndn_forwarder_init();
  ndn_direct_face_construct(666);
  udp_face = ndn_udp_multicast_face_construct(667, INADDR_ANY, 6363, multicast_ip);

  // add route to the network
  char prefix_string[] = "/ndn";
  ndn_name_t fib_prefix;
  ret_val = ndn_name_from_string(&fib_prefix, prefix_string, sizeof(prefix_string));
  if (ret_val != 0) {
    print_error("consumer", "add route", "ndn_name_from_string", ret_val);
  }
  ndn_forwarder_fib_insert(&fib_prefix, &udp_face->intf, 0);

  // register prefix 1 for SD
  char prefix1_string[] = "/ndn/SD/erynn/QUERY";
  ndn_name_t prefix1;
  ret_val = ndn_name_from_string(&prefix1, prefix1_string, sizeof(prefix1_string));
  if (ret_val != 0) {
    print_error("controller", "query register prefix", "ndn_name_from_string", ret_val);
  }
  ret_val = ndn_direct_face_register_prefix(&prefix1, on_interest1);
  if (ret_val != 0) {
    print_error("controller", "query register prefix", "ndn_direct_face_register_prefix", ret_val);
  }

  // register prefix 1 for SD
  char prefix2_string[] = "/ndn/SD/erynn/time";
  ndn_name_t prefix2;
  ret_val = ndn_name_from_string(&prefix2, prefix2_string, sizeof(prefix2_string));
  if (ret_val != 0) {
    print_error("controller", "time service register prefix", "ndn_name_from_string", ret_val);
  }
  ret_val = ndn_direct_face_register_prefix(&prefix2, on_interest2);
  if (ret_val != 0) {
    print_error("controller", "time service register prefix", "ndn_direct_face_register_prefix", ret_val);
  }

  // prepare EK Interest for AC
  ndn_encoder_t interest_encoder;
  encoder_init(&interest_encoder, buffer, sizeof(buffer));
  ret_val = ndn_ac_prepare_key_request_interest(&interest_encoder, &home_prefix, &component_producer,
                                                100, prv_key, 1);
  if (ret_val != 0) {
    print_error("producer", "prepare EK Interest", "ndn_ac_prepare_key_request", ret_val);
  }

  // send out Interest to AC controller
  ndn_interest_t interest;
  ndn_interest_from_block(&interest, interest_encoder.output_value, interest_encoder.offset);
  ndn_direct_face_express_interest(&interest.name, interest_encoder.output_value,
                                   interest_encoder.offset, on_data, NULL);

  while (true) {
    ndn_udp_multicast_face_recv(udp_face);
    usleep(10);
  }

  return 0;
}
