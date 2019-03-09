#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/encoder.h"
#include "ndn-lite/encode/interest.h"
#include "ndn-lite/face/direct-face.h"

#include "ndn-lite/forwarder/forwarder.h"

// defines for ndn standalone library
ndn_direct_face_t *m_face;
uint16_t m_face_id_direct = 2;

//timeout do nothing
int
on_interest_timeout_callback(const uint8_t* interest, uint32_t interest_size)
{
  (void)interest;
  (void)interest_size;
//   blink_led(interest_size);
  return 0;
}
// data back do nothing
int
on_data_callback(const uint8_t* data, uint32_t data_size)
{
  (void)data;
  (void)data_size;
  return 0;
}

/**@brief Function for application main entry.
 */
int main(void) {

    // // Initialize the log.
    // log_init();

    // // Initialize timers.
    // timers_init();

    // Initialize the ndn lite forwarder
    ndn_forwarder_init();

    int ret;


    // Create a direct face, which we will use to send the interest for our certificate after sign on.
    m_face = ndn_direct_face_construct(m_face_id_direct);

    //register route for sending interest
    char prefix_string[] = "/ndn";
    ndn_name_t prefix;
    ndn_name_from_string(&prefix, prefix_string, sizeof(prefix_string));

    if ((ret = ndn_forwarder_fib_insert(&prefix, &m_face->intf, 0)) != 0) {
        printf("Problem inserting fib entry, error code %d\n", ret);
    }

  // Enter main loop.
    while(true) {
        //construct interest without signature
        ndn_interest_t interest;
        ndn_interest_init(&interest);
        char name_string[] = "/time/get";
        ndn_name_from_string(&interest.name, name_string, sizeof(name_string));
        uint8_t interest_block[256] = {0};
        ndn_encoder_t encoder;
        encoder_init(&encoder, interest_block, 256);
        ndn_interest_tlv_encode(&encoder, &interest);
        //send interest
        ndn_direct_face_express_interest(&interest.name,
                            interest_block, encoder.offset,
                            on_data_callback, on_interest_timeout_callback);
        ndn_face_send(&m_face->intf, &interest.name, interest_block, encoder.offset);
        nrf_delay_ms(100); // for debouncing 
        }
  }
}

