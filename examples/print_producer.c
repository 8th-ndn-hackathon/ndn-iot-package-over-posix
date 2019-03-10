//
//  producer.c
//  shanxigy
//
//  Created by shanxigy on 3/9/19.
//  Copyright © 2019 shanxigy. All rights reserved.
//

#include <unistd.h>

#include "ndn-lite/security/ndn-lite-crypto-key.h"
#include "ndn-lite/app-support/service-discovery.h"
#include "ndn-lite/encode/signed-interest.h"
#include "ndn-lite/security/ndn-lite-hmac.h"
#include "ndn-lite/security/ndn-lite-ecc.h"
#include "ndn-lite/ndn-services.h"

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


int on_interest(const uint8_t* interest, uint32_t interest_size){
    ndn_interest_t* decoded_interest;
    ret_val = ndn_interest_from_block(decoded_interest, interest, interest_size);
    if (ret_val != 0) {
        print_error(_current_test_name, "_run_service_discovery_test", "ndn_interest_from_block", ret_val);
    }
    name_component_t command = decoded_interest->name.components[3];
    puts(command.value);
    return NDN_SUCCESS;
}

int main()
{
    // tests start
    ndn_security_init();
    
    // intiate private and public key
    ndn_encoder_t encoder;
    
    // set home prefix
    ndn_name_t home_prefix;
    char* home_prefix_str = "/ndn";
    ret_val = ndn_name_from_string(&home_prefix, home_prefix_str, sizeof(home_prefix_str));
    if (ret_val != 0) {
        print_error(_current_test_name, "_run_service_discovery_test", "ndn_name_from_string", ret_val);
        _all_function_calls_succeeded = false;
    }
    
    // set producer components
    char comp_producer[] = "/ndn/producer";
    name_component_t component_producer;
    ret_val = name_component_from_string(&component_producer, comp_producer, sizeof(comp_producer));
    if (ret_val != 0) {
        print_error(_current_test_name, "_run_service_discovery_test", "ndn_name_component_from_string", ret_val);
        _all_function_calls_succeeded = false;
    }
    
    
    ndn_interest_t interest;
    uint8_t buffer[1024];
    
    
    // intialization
    ndn_sd_init(&home_prefix, &component_producer);
    char NDN_SD_PRINT[] = "/SD-ADV/Yu/print";
    ndn_service_t* print_service = ndn_sd_register_get_self_service(NDN_SD_PRINT,
                                                                      sizeof(NDN_SD_PRINT));
    
    // set service status
    ndn_sd_set_service_status(print_service, NDN_APPSUPPORT_SERVICE_AVAILABLE);
    
    
    // shared prv and pub keys
    ndn_ecc_pub_t* pub_key = NULL;
    ndn_ecc_prv_t* prv_key = NULL;
    ndn_key_storage_init();
    ndn_key_storage_get_empty_ecc_key(&pub_key, &prv_key);
    ret_val = ndn_ecc_prv_init(prv_key, prv, sizeof(prv),
                               NDN_ECDSA_CURVE_SECP256R1, 123);
    if (ret_val != 0) {
        print_error("controller", "init keys", "ndn_ecc_prv_init", ret_val);
        return -1;
    }
    ret_val = ndn_ecc_pub_init(pub_key, pub, sizeof(pub),
                               NDN_ECDSA_CURVE_SECP256R1, 456);
    if (ret_val != 0) {
        print_error("controller", "init keys", "ndn_ecc_pub_init", ret_val);
        return -1;
    }

    
    // generate advertisement Interest
    encoder_init(&encoder, buffer, sizeof(buffer));
    ndn_sd_prepare_advertisement(&interest);
    printf("Advertisement Preparation Success\n");
    ret_val = ndn_interest_tlv_encode(&encoder, &interest);
    if (ret_val != 0) {
        print_error(_current_test_name, "_run_service_discovery_test",  "ndn_interest_tlv_encode", ret_val);
        _all_function_calls_succeeded = false;
    }
    
    face = ndn_udp_multicast_face_construct(1, INADDR_ANY, 12345, inet_aton("225.0.0.37"));
    ndn_direct_face_construct(2);
    
    //adding FIB entry
    ndn_name_t name;
    ndn_name_from_string(&name, "/ndn", 4);
    ndn_forwarder_fib_insert(name, &face->intf, 0);
    
    
    //register prefix
    char query_prefix[] = "/ndn/SD/Yu/QUERY";
    ndn_direct_face_register_prefix(&query_prefix, ndn_sd_on_query_process);
    char evoke_prefix[] = "/ndn/SD/Yu/print";
    ndn_direct_face_register_prefix(&evoke_prefix, on_interest);
    
    
    //periodically sending advertisement interest
    while (1) {
        ndn_direct_face_express_interest(&name_prefix, encoder.output_value, encoder.offset, NULL, NULL);
        for (int i = 0; i < 1000; ++i) {
            ndn_udp_multicast_face_recv(face);
            usleep(10);
        }
    }
    
    ndn_face_destroy(&face->intf);
    
}
