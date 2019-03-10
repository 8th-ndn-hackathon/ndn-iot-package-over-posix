//
//  consumer.c
//  shanxigy
//
//  Created by shanxigy on 3/9/19.
//  Copyright © 2019 shanxigy. All rights reserved.
//


#include "ndn-lite/security/ndn-lite-crypto-key.h"
#include "ndn-lite/app-support/service-discovery.h"
#include "ndn-lite/encode/signed-interest.h"
#include "ndn-lite/security/ndn-lite-hmac.h"
#include "ndn-lite/security/ndn-lite-ecc.h"
#include "ndn-lite/ndn-services.h"

ndn_ecc_pub_t* pub_key = NULL;
ndn_ecc_prv_t* prv_key = NULL;

const uint8_t pub[] = {
    0x36, 0xF7, 0xEF, 0x7C, 0x05, 0x10, 0x68, 0xC4, 0x6C, 0x67,
    0x63, 0x2A, 0xF5, 0x82, 0x1D, 0x14, 0xBA, 0xCC, 0x50, 0x12,
    0x73, 0x73, 0xED, 0xDE, 0x7D, 0x23, 0x5D, 0x20, 0xA8, 0x5E,
    0xD1, 0x83, 0x3C, 0x0F, 0xB7, 0xD2, 0x6E, 0xB2, 0x0F, 0x8B,
    0x09, 0x1D, 0xD0, 0xF3, 0xB9, 0xAA, 0x56, 0x11, 0x1D, 0x15,
    0x0C, 0xAC, 0xE4, 0xFA, 0x9F, 0x6C, 0x61, 0xB4, 0xFF, 0x41,
    0xE8, 0xBA, 0x21, 0x89
};

int on_advertisement(const uint8_t* rawdata, uint32_t data_size){
    ndn_interest_t* decoded_interest;
    int ret_val = ndn_interest_from_block(decoded_interest, rawdata, data_size);
    if (ret_val != 0) {
        print_error("Consumer", "on_advertisement", "ndn_data_tlv_decode_ecdsa_verify", ret_val);
    }
    
    ndn_sd_on_advertisement_process(decoded_interest);
    
    return NDN_SUCCESS;
}

int on_query_response(const uint8_t* rawdata, uint32_t data_size){
    ndn_interest_t* decoded_interest;
    
    int ret_val = ndn_data_tlv_decode_ecdsa_verify(decoded_interest, data, data_size, pub_key);
    if (ret_val != 0) {
        print_error("provider", "on_query_response", "ndn_data_tlv_decode_ecdsa_verify", ret_val);
    }
    
    ndn_sd_on_query_response_process(decoded_interest);
    
    return NDN_SUCCESS;
}


int main()
{
    // tests start
    ndn_security_init();
    
    ndn_encoder_t encoder;
    
    // shared pub and prv keys
    ndn_key_storage_init();
    ndn_key_storage_get_empty_ecc_key(&pub_key, &prv_key);
    ret_val = ndn_ecc_prv_init(prv_key, prv, sizeof(prv),
                               NDN_ECDSA_CURVE_SECP256R1, 123);
    if (ret_val != 0) {
        print_error("_Consumer", "init keys", "ndn_ecc_prv_init", ret_val);
        return -1;
    }
    ret_val = ndn_ecc_pub_init(pub_key, pub, sizeof(pub),
                               NDN_ECDSA_CURVE_SECP256R1, 456);
    if (ret_val != 0) {
        print_error("_Consumer", "init keys", "ndn_ecc_pub_init", ret_val);
        return -1;
    }
    
    // set home prefix
    ndn_name_t home_prefix;
    char* home_prefix_str = "/ndn";
    int ret_val = ndn_name_from_string(&home_prefix, home_prefix_str, sizeof(home_prefix_str));
    if (ret_val != 0) {
        print_error(_current_test_name, "_Consumer", "ndn_name_from_string", ret_val);
        _all_function_calls_succeeded = false;
    }
    
    
    // set consumer components
    char comp_consumer[] = "/ndn/consumer";
    name_component_t component_consumer;
    ret_val = name_component_from_string(&component_consumer, comp_consumer, sizeof(comp_consumer));
    if (ret_val != 0) {
        print_error(_current_test_name, "_Consumer", "name_component_from_string", ret_val);
        _all_function_calls_succeeded = false;
    }
    
    
    // intialization
    ret_val = ndn_direct_face_register_prefix(comp_consumer, on_advertisement);
  

    //adding FIB entry
    ndn_name_t name;
    ndn_name_from_string(&name, "/ndn", 4);
    ndn_forwarder_fib_insert(name, &face->intf, 0);
    
    //find the print service
    char service_need[] = "/ndn/SD/Yu/print";
    int service_size = sizeof(service_need);
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
    ndn_udp_unicast_face_t *face;
    face = ndn_udp_multicast_face_construct(1, INADDR_ANY, 12345, inet_aton("225.0.0.37"));
    ndn_direct_face_construct(2);
    
    ndn_interest_t query;
    while (entry->services[service_number].status != NDN_APPSUPPORT_SERVICE_AVAILABLE) {
        puts("Consumer: service state not available");
        ndn_sd_prepare_query(&query, &entry->identity, &entry->services[service_number],
                         NULL, 0);
        encoder_init(&encoder, buf, 4096);
        ret_val = ndn_signed_interest_ecdsa_sign(&query, &consumer_identity, &prv_key);
        ret_val = ndn_interest_tlv_encode(&encoder, &query);
        ndn_direct_face_express_interest(&name_prefix, encoder.output_value, encoder.offset, on_query_response, NULL);
        puts("Query");
        usleep(1000);
    }
    puts("Available now!");
    
    
    //send an evoke Interest
    ndn_name_t name_prefix;
    ndn_interest_t interest;
    uint8_t buf[4096];
    char name_string[] = "/ndn/SD/Yu/print/(3+5)*2-6";
    if(ndn_name_from_string(&name_prefix, name_string, strlen(name_string)) != NDN_SUCCESS){
        fprintf(stderr, "ERROR: wrong name.\n");
        return -1;
    }
    ndn_interest_from_name(&interest, &name_prefix);
    encoder_init(&encoder, buf, 4096);
    ret_val = ndn_signed_interest_ecdsa_sign(&interest, &consumer_identity, &prv_key);
    if (ret_val != 0) {
        print_error(_current_test_name, "_Consumer", "ndn_signed_interest_ecdsa_sign", ret_val);
        _all_function_calls_succeeded = false;
    }
    ret_val = ndn_interest_tlv_encode(&encoder, &interest);
    if (ret_val != 0) {
        print_error(_current_test_name, "_Consumer", "ndn_interest_tlv_encode", ret_val);
        _all_function_calls_succeeded = false;
    }
    
    printf("Value of interest, encoded:\n");
    for (uint32_t i = 0; i < encoder.offset; i++) {
        if (i > 0) printf(":");
        printf("%02X", encoder.output_value[i]);
    }
    printf("\n");
    
    ndn_direct_face_express_interest(&name_prefix, encoder.output_value, encoder.offset, NULL, NULL);

    while(1){
        ndn_udp_multicast_face_recv(face);
        usleep(10);
    }
    
    ndn_face_destroy(&face->intf);
}
