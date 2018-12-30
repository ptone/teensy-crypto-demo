#include <Arduino.h>
#include <uECC.h>
#include <Crypto.h>
#include <ChaChaPoly.h>
#include <string.h>

#include <cstring>

#include <CBOR.h>
#include <CBOR_parsing.h>
#include <CBOR_streams.h>
#if defined(ESP8266) || defined(ESP32)
#include <pgmspace.h>
#else
#include <avr/pgmspace.h>
#endif

#define MAX_PLAINTEXT_LEN 265
#define CHA_CHA_POLY_KEY_SIZE 32
#define CHA_CHA_POLY_IV_SIZE 12
#define CHA_CHA_POLY_AUTH_SIZE 16
#define CHA_CHA_POLY_TAG_SIZE 16
#define CHA_CHA_POLY_MESSAGE_SIZE 6

extern "C" {

static int RNG(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of 
  // random noise). This can take a long time to generate random data if the result of analogRead(0) 
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }
      
      if (count == 0) {
         val = (val << 1) | (init & 0x01);
      } else {
         val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}

}  // extern "C"



ChaChaPoly chachapoly;
namespace cbor = ::qindesign::cbor;

// Choose an array size of 256 and a starting address of zero
constexpr size_t kBytesSize = 256;
constexpr int kStartAddress = 0;
uint8_t bytes[kBytesSize]{0};
cbor::BytesStream bs{bytes, sizeof(bytes)};
cbor::BytesPrint bp{bytes, sizeof(bytes)};

struct TelemetryData {
  bool flag = false;
  float temperature = 0.0;
};

void encrypt(const byte key[CHA_CHA_POLY_KEY_SIZE], const byte iv[CHA_CHA_POLY_IV_SIZE], const byte auth[CHA_CHA_POLY_AUTH_SIZE], const byte plainText[CHA_CHA_POLY_MESSAGE_SIZE], byte cipherText[CHA_CHA_POLY_MESSAGE_SIZE], byte tag[CHA_CHA_POLY_TAG_SIZE])
{
    chachapoly.clear();
    chachapoly.setKey(key, CHA_CHA_POLY_KEY_SIZE);
    chachapoly.setIV(iv, CHA_CHA_POLY_IV_SIZE);
    chachapoly.addAuthData(auth, CHA_CHA_POLY_AUTH_SIZE);
    chachapoly.encrypt(cipherText, plainText, CHA_CHA_POLY_MESSAGE_SIZE);
    chachapoly.computeTag(tag, CHA_CHA_POLY_TAG_SIZE);
}

bool decrypt(const byte key[CHA_CHA_POLY_KEY_SIZE], const byte iv[CHA_CHA_POLY_IV_SIZE], const byte auth[CHA_CHA_POLY_AUTH_SIZE], const byte cipherText[CHA_CHA_POLY_MESSAGE_SIZE], byte plainText[CHA_CHA_POLY_MESSAGE_SIZE], const byte tag[CHA_CHA_POLY_TAG_SIZE])
{
    chachapoly.clear();
    chachapoly.setKey(key, CHA_CHA_POLY_KEY_SIZE);
    chachapoly.setIV(iv, CHA_CHA_POLY_IV_SIZE);
    chachapoly.addAuthData(auth, CHA_CHA_POLY_AUTH_SIZE);
    chachapoly.decrypt(plainText, cipherText, CHA_CHA_POLY_MESSAGE_SIZE);
    return chachapoly.checkTag(tag, CHA_CHA_POLY_TAG_SIZE);
}

// Forward declarations
// bool loadMyData(MyData *myData);
void storeData(const TelemetryData &data);

void setup() {
  Serial.begin(115200);
  delay(1000);
  uECC_set_rng(&RNG);
  Serial.print("Testing ecc\n");
  // uECC_set_rng(&RNG);
  // ChaChaPoly chachapoly;
  const struct uECC_Curve_t * curve = uECC_secp256r1();

  char privv[] = "00:82:78:13:55:41:53:46:cd:d9:d9:be:4c:58:00:a9:c6:d8:95:f7:4e:62:79:a0:33:ea:ff:23:b3:de:ca:6b:94";
  char* token = NULL; 
  uint8_t devicePrivate[32];
  uint8_t devicePublic[64];
  uint8_t deviceSecret[32];
 
  // parse private string into byte array
  token = strtok(privv, ":");
  int ctr = 0;
  while (token != NULL) {
    // Serial.printf("%s\n", token); 
    devicePrivate[ctr] = strtoul(token, NULL, 16);
    token = strtok(NULL, ":");
    ctr++;
  }

  for (int i=0; i < 32; i++) {
    Serial.print(" ");
    Serial.print(devicePrivate[i], HEX);
  }
  Serial.println();

  Serial.println(sizeof(devicePrivate));
  uECC_compute_public_key(devicePrivate, devicePublic, curve);

  for (int i=0; i < 64; i++) {
    Serial.print(" ");
    Serial.print(devicePublic[i], HEX);
  }
  Serial.println();

  uint8_t serverPrivate[32];
  uint8_t serverPublic[64];
  uint8_t serverSecret[32];

  uECC_make_key(serverPublic, serverPrivate, curve);
 for (int i=0; i < 32; i++) {
    Serial.print(" ");
    Serial.print(serverPrivate[i], HEX);
  }
  Serial.println(); 
  int r = uECC_shared_secret(serverPublic, devicePrivate, deviceSecret, curve);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }

  r = uECC_shared_secret(devicePublic, serverPrivate, serverSecret, curve);
  if (!r) {
    Serial.print("shared_secret() failed (2)\n");
    return;
  }
  for (int i=0; i < 32; i++) {
    Serial.print(" ");
    Serial.print(deviceSecret[i], HEX);
  } 
  Serial.println(); 

  for (int i=0; i < 32; i++) {
    Serial.print(" ");
    Serial.print(serverSecret[i], HEX);
  } 
  Serial.println(); 
  if (memcmp(deviceSecret, serverSecret, 32) != 0) {
    Serial.print("Shared secrets are not identical!\n");
  } else {
    Serial.print("Shared secrets are identical\n");
  }

  uint8_t testnonce[12];
  RNG(testnonce, 12);
  for (int i=0; i < 12; i++) {
    Serial.print(" ");
    Serial.print(testnonce[i], HEX);
  }  
  Serial.println();

  // String plain = "secret";
  // plain.getBytes(plainText, CHA_CHA_POLY_MESSAGE_SIZE);
  // Serial.print("got bytes \n");
  TelemetryData testdata = {
    false,
    2.4
  };
  Serial.println("ok");
  storeData(testdata);
  cbor::Reader cb{bs};
  cbor::Writer cw{bp};
  // for (int i=0; i < sizeof(bytes); i++) {
  //   Serial.print(" ");
  //   Serial.print(bytes[i], HEX);
  // }  

  bs.reset();
  if (!cb.isWellFormed()) {
    Serial.println("Not well-formed CBOR data.");
  }
  Serial.println();
  cbor::DataType dt;
  bs.reset();
  size_t bufferUsed = cw.getWriteSize();
  Serial.println(bufferUsed);
}

void loop() {
  // put your main code here, to run repeatedly:
}

void storeData(const TelemetryData &data) {
  cbor::Writer cbor{bp};

  // The following reset() call is only necessary if we don't know
  // the position of the printer, and if we wanted to reset it
  // to the beginning
  bp.reset();

  cbor.writeTag(cbor::kSelfDescribeTag);
  cbor.beginArray(2);
  cbor.writeBoolean(data.flag);
  cbor.writeFloat(data.temperature);
  size_t bufferUsed = cbor.getWriteSize();
  Serial.print("bytes used: ");
  Serial.println(bufferUsed);
}