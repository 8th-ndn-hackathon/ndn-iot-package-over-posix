/*
 * Laqin
 */
#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/encoder.h"
#include "ndn-lite/encode/interest.h"
#include "ndn-lite/face/direct-face.h"
#include "ndn-lite/encode/signed-interest.h"

#include "ndn-lite/forwarder/forwarder.h"
#include "adaptation/udp-unicast/ndn-udp-unicast-face.h"

in_port_t port1, port2;
in_addr_t server_ip;
ndn_name_t name_prefix;
uint8_t buf[4096];
bool running;

char interest_type[7];

int parseArgs(int argc, char *argv[]){
  char *sz_port1, *sz_port2, *sz_addr, *itype ;
  uint32_t ul_port;
  struct hostent * host_addr;
  struct in_addr ** paddrs;

  if(argc < 5){
    fprintf(stderr, "ERROR: wrong arguments.\n");
    printf("Usage: <local-port> <remote-ip> <remote-port> <name-prefix>\n");
    return 1;
  }
  sz_port1 = argv[1];
  sz_addr = argv[2];
  sz_port2 = argv[3];
  // interest_type = argv[5];
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

  if(ndn_name_from_string(&name_prefix, argv[4], strlen(argv[4])) != NDN_SUCCESS){
    fprintf(stderr, "ERROR: wrong name.\n");
    return 4;
  }

  if (strlen(argv[5]) < 7) {

    strcpy(interest_type, argv[5]);
    
  }
  return 0;
}

//timeout do nothing
int
on_interest_timeout_callback(const uint8_t* interest, uint32_t interest_size)
{
  (void)interest;
  (void)interest_size;
  printf("Time out\n");

//   blink_led(interest_size);
  return 0;
}

// data back to print the time
int
on_data_callback(const uint8_t* data, uint32_t data_size)
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

/**@brief Function for application main entry.
 */
int main(int argc, char *argv[]) {
    ndn_udp_unicast_face_t *udpface;
    ndn_interest_t interest;
    ndn_encoder_t encoder;

    int ret;

    if((ret = parseArgs(argc, argv)) != 0){
    return ret;
    }

    // Initialize the ndn lite forwarder
    ndn_forwarder_init();
    ndn_security_init();

    // Create a direct face, which we will use to send the interest for our certificate after sign on.
    ndn_direct_face_construct(2);

    udpface = ndn_udp_unicast_face_construct(1, INADDR_ANY, port1, server_ip, port2);

    if ((ret = ndn_forwarder_fib_insert(&name_prefix, &udpface->intf, 0)) != 0) {
        printf("Problem inserting fib entry, error code %d\n", ret);
    }

    /**
     * interest_type == "no": interest without siganature
     * interest_type == "yes": interest with siganature
    */

    ndn_interest_from_name(&interest, &name_prefix);
    encoder_init(&encoder, buf, 4096);

    //construct interest without signature
    if (strcmp(interest_type,"no") == 0) {
      ndn_interest_tlv_encode(&encoder, &interest);
      //send interest
      ndn_direct_face_express_interest(&name_prefix, encoder.output_value, encoder.offset, on_data_callback, NULL);

    }
    //construct interest with digest signature
    else if (strcmp(interest_type,"digest") == 0) {

      printf("digest sign\n");

      ndn_signed_interest_digest_sign(&interest);
      ndn_interest_tlv_encode(&encoder, &interest);
      //send interest
     ndn_direct_face_express_interest(&name_prefix, encoder.output_value, encoder.offset, on_data_callback, on_interest_timeout_callback);
    }

    while(true){
      ndn_udp_unicast_face_recv(udpface);
      usleep(10);
   }

    ndn_face_destroy(&udpface->intf);

}

