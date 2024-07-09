#include "base64.hpp"
#include <SHA512.h>
// The base64 and sha512 libraries are imported, which are needed 
// to communicate encrypted and encoded messages
#pragma execution_character_set("utf-8")
#include <string.h>
const int b64_size = 88;
const int hash_size = 64;

// Global variables are created for each stage of the protocol

// Chall variables
byte crt2_chall[b64_size];
byte crt2_chall_decoded[b64_size];
 
// Random chall variables
byte rn_chall[b64_size];
byte rn_chall_decoded[b64_size];

// Response crt variables
byte resp_crt_hash[hash_size];

// Response1 variables
byte final_resp1[hash_size];
unsigned char b64_resp1[b64_size];

// Response2 variables
byte resp_client[b64_size];
unsigned char resp_client_decoded[b64_size];

// Expected variables
unsigned char final_expected[hash_size];
unsigned char b64_resp2[b64_size];
unsigned char resp2[b64_size];


void setup() {
  Serial.begin(9600);
}
void loop() {
  if (Serial.available() > 0) {
    String data = Serial.readStringUntil('\n');
    // The sequence in the program that is responsible for the mutual CHAP protocol
    if (data == "R1_incomming")
    {
      // The first step is to receive the data to generate resp1 which will be verified by the client
      Serial.flush();
      // Getting challenge from crt2
      int crt2_chall_size = Serial.readBytes(crt2_chall, b64_size);
      unsigned int chall_size_decoded = decode_base64(crt2_chall, crt2_chall_decoded);

      // Getting the random challenge
      int rn_chall_size = Serial.readBytes(rn_chall, b64_size);

      // Generating the resp_crt2 for challenge form crt2
      SHA512 resp_crt;
      resp_crt.update(crt2_chall_decoded, chall_size_decoded);
      resp_crt.finalize(resp_crt_hash, hash_size);

      // Generating resp1 = hmac(resp_crt2, rand_chall, 'sha512') and sending to client
      SHA512 resp1;
      resp1.resetHMAC(resp_crt_hash, sizeof(resp_crt_hash));
      resp1.update(rn_chall, sizeof(rn_chall));
      resp1.finalizeHMAC(resp_crt_hash, sizeof(resp_crt_hash), final_resp1, sizeof(final_resp1));
      unsigned int b64_resp1_lenght = encode_base64(final_resp1, hash_size, b64_resp1);
      Serial.write(b64_resp1, b64_size);
      int x;
      for (x = 0; x < 10; ++x ) {
        data = Serial.readStringUntil('\n');
        if (data == "R2_incomming")
        {
          // The second stage is receiving resp2 from the client and generating expected resp and then comparing 
          // them to complete the protocol and send the authentication message to the client
          
          // Getting resp2 from client
          int l = 0;
          while (l == 0) {
            Serial.flush();

            int r2_size = Serial.readBytes(resp_client, b64_size);
            unsigned int resp_decoded_size = decode_base64(resp_client, resp_client_decoded);


            // Generating expected = hmac(resp_crt2, resp1, 'sha512')
            SHA512 expected;
            expected.resetHMAC(resp_crt_hash, sizeof(resp_crt_hash));
            expected.update(b64_resp1, sizeof(b64_resp1));
            int expected_size = expected.hashSize();
            byte final_expected[expected_size];
            expected.finalizeHMAC(resp_crt_hash, sizeof(resp_crt_hash), final_expected, sizeof(final_expected));
            unsigned char b64_resp2[expected_size];
            unsigned int b64_resp2_lenght = encode_base64(final_expected, expected_size, b64_resp2);


            int n;
            n = memcmp(b64_resp2, resp_client, sizeof(b64_resp2));

            while (n == 0) {
              Serial.write("OK");
              l = 2;
              break;
            }

          }
          break;
        }
      }
    }
    // The sequence in the program that is responsible for receiving challenges and generating responses
    else if (data == "not_bound")
    {
      byte buffer[b64_size];
      byte decode[b64_size];
      int s = Serial.readBytes(buffer, b64_size);
      unsigned int x = decode_base64(buffer, decode);
      SHA512 chall_hash;
      chall_hash.update(decode, x);
      int h_size = chall_hash.hashSize();
      byte b_hash[h_size];
      chall_hash.finalize(b_hash, h_size);
      unsigned char resp[h_size];
      unsigned int b64_lenght = encode_base64(b_hash, h_size, resp);
      Serial.write(resp, b64_lenght);
      Serial.flush();
    }
  }
}