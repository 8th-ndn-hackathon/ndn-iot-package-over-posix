/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include "adaptation/udp-unicast/ndn-udp-unicast-face.h"
#include "ndn-lite/forwarder/forwarder.h"
#include "ndn-lite/face/direct-face.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/signed-interest.h"

in_port_t port1, port2;
in_addr_t server_ip;
ndn_name_t name_prefix;
uint8_t buf[4096];
ndn_udp_unicast_face_t *face;
bool running;

int parseArgs(int argc, char *argv[]){
  char *sz_port1, *sz_port2, *sz_addr;
  uint32_t ul_port;
  struct hostent * host_addr;
  struct in_addr ** paddrs;

  if(argc < 4){
    fprintf(stderr, "ERROR: wrong arguments.\n");
    printf("Usage: <local-port> <remote-ip> <remote-port>\n");
    return 1;
  }
  sz_port1 = argv[1];
  sz_addr = argv[2];
  sz_port2 = argv[3];
  //sz_prefix = argv[4];
  //data_need = argv[5];

  if(strlen(sz_port1) <= 0 || strlen(sz_addr) <= 0 || strlen(sz_port2) <= 0){
    fprintf(stderr, "ERROR: wrong arguments.\n");
    return 1;
  }

  host_addr = gethostbyname(sz_addr);
  if(host_addr == NULL){
    fprintf(stderr, "ERROR: wrong hostname.\n");
    return 2;
  }

  paddrs = (struct in_addr **)host_addr->h_addr_list;
  if(paddrs[0] == NULL){
    fprintf(stderr, "ERROR: wrong hostname.\n");
    return 2;
  }
  server_ip = paddrs[0]->s_addr;

  ul_port = strtoul(sz_port1, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port1 = htons((uint16_t) ul_port);

  ul_port = strtoul(sz_port2, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port2 = htons((uint16_t) ul_port);

  return 0;
}

int on_interest(const uint8_t* interest, uint32_t interest_size){
  ndn_data_t data;
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
  
  data.name = interest1.name;
  //ndn_data_set_content(&data, (uint8_t*)&tv, sizeof(struct timeval));
  ndn_data_set_content(&data, data_string, strlen(data_string));
  ndn_metainfo_init(&data.metainfo);
  ndn_metainfo_set_content_type(&data.metainfo, NDN_CONTENT_TYPE_BLOB);
  encoder_init(&encoder, buf, 4096);
  ndn_data_tlv_encode_digest_sign(&encoder, &data);
  ndn_forwarder_on_incoming_data(ndn_forwarder_get_instance(),
                                 &face->intf,
                                 &name_prefix,
                                 encoder.output_value,
                                 encoder.offset);

  return NDN_SUCCESS;
}

int main(int argc, char *argv[]){
  int ret;

  if((ret = parseArgs(argc, argv)) != 0){
    return ret;
  }

  ndn_forwarder_init();
  ndn_security_init();
  face = ndn_udp_unicast_face_construct(1, INADDR_ANY, port1, server_ip, port2);
  ndn_direct_face_construct(2);

  char prefix_string[] = "/ndn/SD/erynn/time/now";
  ndn_name_from_string(&name_prefix, prefix_string, strlen(prefix_string));
  ndn_direct_face_register_prefix(&name_prefix, on_interest);

  /*
  printf("registered prefix: ");
    for (int i=0; i < name_prefix.components_size; i++) {
    printf("/%.*s", name_prefix.components[i].size, name_prefix.components[i].value);
  }
  printf("\n");
  printf("components_size of registered prefix: %d\n", name_prefix.components_size);
  */

  running = true;
  while(running){
    ndn_udp_unicast_face_recv(face);
    usleep(10);
  }

  ndn_face_destroy(&face->intf);

  return 0;
}