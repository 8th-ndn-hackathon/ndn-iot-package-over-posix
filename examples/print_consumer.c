//
//  consumer.c
//  shanxigy
//
//  Created by shanxigy on 3/9/19.
//  Copyright © 2019 shanxigy. All rights reserved.
//

#include <stdio.h>
#include <unistd.h>
#include "ndn-lite/security/ndn-lite-crypto-key.h"
#include "ndn-lite/app-support/service-discovery.h"
#include "ndn-lite/encode/signed-interest.h"
#include "ndn-lite/security/ndn-lite-hmac.h"
#include "ndn-lite/security/ndn-lite-ecc.h"
#include "ndn-lite/ndn-services.h"
#include "ndn-lite/encode/key-storage.h"
#include "adaptation/udp-unicast/ndn-udp-unicast-face.h"
#include "ndn-lite/face/direct-face.h"

ndn_ecc_pub_t* pub_key = NULL;
ndn_ecc_prv_t* prv_key = NULL;

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

ndn_udp_unicast_face_t *face;

int on_advertisement(const uint8_t* rawdata, uint32_t data_size){
    ndn_interest_t decoded_interest;
    int ret_val = ndn_interest_from_block(&decoded_interest, rawdata, data_size);
    if (ret_val != 0) {
        printf("ERROR: ndn_interest_from_block (%d)\n", ret_val);
        return ret_val;
    }
    
    ndn_sd_on_advertisement_process(&decoded_interest);
    
    return NDN_SUCCESS;
}

int on_query_response(const uint8_t* rawdata, uint32_t data_size){
    ndn_data_t data;
    
    int ret_val = ndn_data_tlv_decode_ecdsa_verify(&data, rawdata, data_size, pub_key);
    if (ret_val != 0) {
        printf("ERROR: ndn_data_tlv_decode_ecdsa_verify (%d)\n", ret_val);
        return ret_val;
    }
    
    ndn_sd_on_query_response_process(&data);
    
    return NDN_SUCCESS;
}

int main()
{
    int ret_val;

    // tests start
    ndn_security_init();
    
    ndn_encoder_t encoder;
    
    // shared pub and prv keys
    ndn_key_storage_init();
    ndn_key_storage_get_empty_ecc_key(&pub_key, &prv_key);
    ret_val = ndn_ecc_prv_init(prv_key, prv, sizeof(prv),
                               NDN_ECDSA_CURVE_SECP256R1, 123);
    if (ret_val != 0) {
        printf("ERROR: ndn_ecc_prv_init (%d)\n", ret_val);
        return ret_val;
    }
    ret_val = ndn_ecc_pub_init(pub_key, pub, sizeof(pub),
                               NDN_ECDSA_CURVE_SECP256R1, 456);
    if (ret_val != 0) {
        printf("ERROR: ndn_ecc_pub_init (%d)\n", ret_val);
        return ret_val;
    }
    
    // set home prefix
    ndn_name_t home_prefix;
    char* home_prefix_str = "/ndn";
    ret_val = ndn_name_from_string(&home_prefix, home_prefix_str, strlen(home_prefix_str));
    if (ret_val != 0) {
        printf("ERROR: ndn_name_from_string (%d)\n", ret_val);
        return ret_val;
    }
    
    // set consumer components
    char comp_consumer[] = "/ndn/consumer";
    ndn_name_t component_consumer;
    ret_val = ndn_name_from_string(&component_consumer, comp_consumer, strlen(comp_consumer));
    if (ret_val != 0) {
        printf("ERROR: name_component_from_string (%d)\n", ret_val);
        return ret_val;
    }
    
    face = ndn_udp_unicast_face_construct(1, INADDR_ANY, 6000, htonl(INADDR_LOOPBACK), 5000);
    ndn_direct_face_construct(2);

    // intialization
    ret_val = ndn_direct_face_register_prefix(&component_consumer, on_advertisement);
  

    //adding FIB entry
    ndn_name_t name;
    ndn_name_from_string(&name, "/ndn", 4);
    ndn_forwarder_fib_insert(&name, &face->intf, 0);
    
    //find the print service
    char service_need[] = "/ndn/SD/Yu/print";
    //int service_size = sizeof(service_need);
    ndn_sd_identity_t* entry;
    
    ndn_interest_t interest;
    uint8_t buffer[1024];
    int service_number;
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        encoder_init(&encoder, buffer, sizeof(buffer));
        service_number = -1;
        for (int i = 0; i < NDN_APPSUPPORT_NEIGHBORS_SIZE; ++i) {
            if (sd_context.neighbors[i].identity.size == NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
                    continue;
                }
            entry = &sd_context.neighbors[i];
            printf("Service Provider Found: ");
            for (uint8_t i = 0; i < entry->identity.size; i++)
                printf("%c", (char)entry->identity.value[i]);
            printf("\n");
            
            for (int i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; ++i) {
                if (entry->services[i].id_size == -1) continue;
                if (strcmp(service_need, entry->services[i].id_value) == 0)
                    service_number = i;
            }
        }
        if (service_number != -1) break;
        usleep(1000);
    }
    puts("Consumer: Print service found!");
    
    
    
    //send a query every second, until service state is AVAILABLE
    
    ndn_interest_t query;
    while (entry->services[service_number].status != NDN_APPSUPPORT_SERVICE_AVAILABLE) {
        puts("Consumer: service state not available");
        ndn_sd_prepare_query(&query, &entry->identity, &entry->services[service_number],
                         NULL, 0);
        encoder_init(&encoder, buffer, 1024);
        ret_val = ndn_signed_interest_ecdsa_sign(&query, &consumer_identity, prv_key);
        ret_val = ndn_interest_tlv_encode(&encoder, &query);
        ndn_direct_face_express_interest(&query.name, encoder.output_value, encoder.offset, on_query_response, NULL);
        puts("Query");
        usleep(1000);
    }
    puts("Available now!");
    
    
    //send an evoke Interest
    ndn_name_t name_prefix;
    uint8_t buf[4096];
    char name_string[] = "/ndn/SD/Yu/print/(3+5)*2-6";
    if(ndn_name_from_string(&name_prefix, name_string, strlen(name_string)) != NDN_SUCCESS){
        fprintf(stderr, "ERROR: wrong name.\n");
        return -1;
    }
    ndn_interest_from_name(&interest, &name_prefix);
    encoder_init(&encoder, buf, 4096);
    ret_val = ndn_signed_interest_ecdsa_sign(&interest, &consumer_identity, prv_key);
    if (ret_val != 0) {
        printf("ERROR: ndn_signed_interest_ecdsa_sign (%d)\n", ret_val);
        return ret_val;
    }
    ret_val = ndn_interest_tlv_encode(&encoder, &interest);
    if (ret_val != 0) {
        printf("ERROR: ndn_interest_tlv_encode (%d)\n", ret_val);
        return ret_val;
    }
    
    printf("Value of interest, encoded:\n");
    for (uint32_t i = 0; i < encoder.offset; i++) {
        if (i > 0) printf(":");
        printf("%02X", encoder.output_value[i]);
    }
    printf("\n");
    
    ndn_direct_face_express_interest(&name_prefix, encoder.output_value, encoder.offset, NULL, NULL);

    while(1){
        ndn_udp_unicast_face_recv(face);
        usleep(10);
    }
    
    ndn_face_destroy(&face->intf);
}
