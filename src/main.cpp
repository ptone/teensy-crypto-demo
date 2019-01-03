#include <Arduino.h>
#include <uECC.h>
#include <Crypto.h>
#include <ChaChaPoly.h>

#include <RNG.h>
#include <TransistorNoiseSource.h>

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

static int TestRNG(uint8_t *dest, unsigned size) {
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
size_t storeData(const TelemetryData &data);
size_t storeMsg(const byte nonce[12], const byte aad[4], const byte cipher[], const int cipherLen, const byte tag[16]);

// this prints the byte with leading zero
void p(char X) {
   if (X < 16) {Serial.print("0");}
   Serial.print(X, HEX);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  uECC_set_rng(&TestRNG);
  Serial.print("Testing ecc\n");
  const struct uECC_Curve_t * curve = uECC_secp256r1();

  char privv[] = "c9:3b:25:f0:de:87:61:54:74:fc:ab:7b:04:74:71:b7:2d:23:15:32:22:cb:21:78:16:2e:3d:f0:b1:cb:02:0d";
  // reversed
  // char privv[] = "0D:02:CB:B1:F0:3D:2E:16:78:21:CB:22:32:15:23:2D:B7:71:74:04:7B:AB:FC:74:54:61:87:DE:F0:25:3B:C9";

  char serverPublicStr[] = "b1:d2:08:07:70:64:03:c9:3d:5d:56:61:f7:d4:88:ca:20:de:fb:13:c0:74:db:d3:fe:31:b9:10:90:32:b4:4c:2a:89:93:d5:92:4d:dd:98:fc:2a:f4:18:8c:1b:54:de:b0:93:f7:ff:9e:b3:0b:41:2c:cb:db:a0:a7:94:08:3d";
  // reversed
  // char serverPublicStr[] = "3D:08:94:A7:A0:DB:CB:2C:41:0B:B3:9E:FF:F7:93:B0:DE:54:1B:8C:18:F4:2A:FC:98:DD:4D:92:D5:93:89:2A:4C:B4:32:90:10:B9:31:FE:D3:DB:74:C0:13:FB:DE:20:CA:88:D4:F7:61:56:5D:3D:C9:03:64:70:07:08:D2:B1";
  char* token = NULL; 
  uint8_t devicePrivate[32];
  uint8_t devicePublic[64];
  uint8_t deviceSecret[32];
  uint8_t serverPublic[64];
 
  // parse private string into byte array
  token = strtok(privv, ":");
  int ctr = 0;
  while (token != NULL) {
    // Serial.printf("%s\n", token); 
    devicePrivate[ctr] = strtoul(token, NULL, 16);
    token = strtok(NULL, ":");
    ctr++;
  }

  token = strtok(serverPublicStr, ":");
  ctr = 0;
  while (token != NULL) {
    // Serial.printf("%s\n", token); 
    serverPublic[ctr] = strtoul(token, NULL, 16);
    token = strtok(NULL, ":");
    ctr++;
  }


  uECC_compute_public_key(devicePrivate, devicePublic, curve);
  // uint8_t serverPrivate[32];
  // uint8_t serverSecret[32];
  // uECC_make_key(serverPublic, serverPrivate, curve);

  int r = uECC_shared_secret(serverPublic, devicePrivate, deviceSecret, curve);
  if (!r) {
    Serial.print("shared_secret() failed (1)\n");
    return;
  }

  // r = uECC_shared_secret(devicePublic, serverPrivate, serverSecret, curve);
  // if (!r) {
  //   Serial.print("shared_secret() failed (2)\n");
  //   return;
  // }
  Serial.println("shared secrets: "); 
  for (int i=0; i < 32; i++) {
    // Serial.print(" ");
    // Serial.print(deviceSecret[i], HEX);
    p(deviceSecret[i]);
  } 
  Serial.println(); 

  Serial.println("Device Private"); 
  for (int i=0; i < 32; i++) {
  //   Serial.print(" ");
    // Serial.print(devicePrivate[i], HEX);
    p(devicePrivate[i]);
  } 
  Serial.println(); 
  Serial.println(); 

  Serial.println("Device Public Computed"); 
  for (int i=0; i < 64; i++) {
  //   Serial.print(" ");
    // Serial.print(devicePrivate[i], HEX);
    p(devicePublic[i]);
  } 
  Serial.println(); 
  Serial.println(); 

  Serial.println("server public"); 
  for (int i=0; i < 64; i++) {
  //   Serial.print(" ");
    // Serial.print(serverPublic[i], HEX);
    p(serverPublic[i]);
  } 
  int pubok = uECC_valid_public_key(serverPublic, curve);
  Serial.println(); 
  Serial.println("valid public"); 
  Serial.println(pubok); 
  Serial.println(); 
  Serial.println(); 

  // if (memcmp(deviceSecret, serverSecret, 32) != 0) {
  //   Serial.print("Shared secrets are not identical!\n");
  // } else {
  //   Serial.print("Shared secrets are identical\n");
  // }

  // byte debugkey[CHA_CHA_POLY_KEY_SIZE] = {
  //       0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  //       0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  //       0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
  //       0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

  //debug      
  // uint8_t msgnonce[12] = {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};

  uint8_t msgnonce[12];
  TestRNG(msgnonce, 12);

  Serial.println("nonce:");
  for (int i=0; i < 12; i++) {
    Serial.print(" ");
    // Serial.print(msgnonce[i], HEX);
    p(msgnonce[i]);
  }  
  Serial.println();

  // String plain = "secret";
  // plain.getBytes(plainText, CHA_CHA_POLY_MESSAGE_SIZE);
  // Serial.print("got bytes \n");
  TelemetryData testdata = {
    false,
    2.4
  };

  size_t payloadSize = storeData(testdata);
  Serial.print("returned getWriteSize ");
  Serial.println(payloadSize);

  uint8_t ciphertext[payloadSize];
  uint8_t tag[16];
  uint8_t deviceid[4] = {0x01, 0x01, 0x01, 0x01};
  // encrypt(deviceSecret, msgnonce, aad, plainText, cipherText, tag);
  chachapoly.clear();
  chachapoly.setKey(deviceSecret, CHA_CHA_POLY_KEY_SIZE);
  // chachapoly.setKey(debugkey, CHA_CHA_POLY_KEY_SIZE);
  chachapoly.setIV(msgnonce, CHA_CHA_POLY_IV_SIZE);
  chachapoly.addAuthData(deviceid, 4);
  chachapoly.encrypt(ciphertext, bytes, payloadSize);
  chachapoly.computeTag(tag, CHA_CHA_POLY_TAG_SIZE);
  Serial.println("cipher:");
  for (int i=0; i < payloadSize; i++) {
    // Serial.print(ciphertext[i], HEX);
    p(ciphertext[i]);
    Serial.print(" ");
  }  
  Serial.println();
  Serial.println("tag:");
  for (int i=0; i < 16; i++) {
  // Serial.print(tag[i], HEX);
  p(tag[i]);
  Serial.print(" ");
}  
  Serial.println();
  Serial.println("original payload");

    for (int i=0; i < 20; i++) {
    // Serial.print(bytes[i], HEX);
    p(bytes[i]);
    Serial.print(" ");
  }  
  uint8_t msg[20];
  chachapoly.clear();
  chachapoly.setKey(deviceSecret, CHA_CHA_POLY_KEY_SIZE);
  // chachapoly.setKey(debugkey, CHA_CHA_POLY_KEY_SIZE);
  chachapoly.setIV(msgnonce, CHA_CHA_POLY_IV_SIZE);
  chachapoly.addAuthData(deviceid, 4);
  chachapoly.decrypt(msg, ciphertext, payloadSize);
  bool result = chachapoly.checkTag(tag, CHA_CHA_POLY_TAG_SIZE);
  Serial.println();
  Serial.println("decrypted payload");

    for (int i=0; i < 20; i++) {
    Serial.print(msg[i], HEX);
    Serial.print(" ");
  }  
  Serial.println();
  Serial.println("result:");
  Serial.println(result);

  Serial.println();
  Serial.println("full msg:");
  size_t msgSize = storeMsg(msgnonce, deviceid, ciphertext, payloadSize, tag);
  for (int i=0; i < msgSize; i++) {
    // Serial.print(bytes[i], HEX);
    p(bytes[i]);
    Serial.print(" ");
  }  
  Serial.println();
}

void loop() {
  // put your main code here, to run repeatedly:
  for (int i=0; i < 100; i++) {
    // Serial.print(bytes[i], HEX);
    p(bytes[i]);
    Serial.print(" ");
  }  
  Serial.println();
  delay(10000);
}

size_t storeMsg(const byte nonce[12], const byte aad[4], const byte cipher[], const int cipherLen, const byte tag[16]) {
  cbor::Writer cbor{bp};
  memset(bytes, 0, sizeof(bytes));

  bp.reset();
  cbor.beginMap(4);

  // type
  cbor.beginText(1);
  cbor.writeByte('t');
  cbor.writeInt(1);

  // nonce
  cbor.beginText(1);
  cbor.writeByte('n');
  cbor.beginBytes(12);
  cbor.writeBytes(nonce, 12);

  // aad
  cbor.beginText(1);
  cbor.writeByte('a');
  cbor.beginBytes(4);
  cbor.writeBytes(aad, 4);
  
  // cipher
  cbor.beginText(1);
  cbor.writeByte('c');
  cbor.beginIndefiniteBytes();
  cbor.beginBytes(cipherLen);
  cbor.writeBytes(cipher, cipherLen);
  cbor.beginBytes(16);
  cbor.writeBytes(tag, 16);
  cbor.endIndefinite();


  return cbor.getWriteSize(); 

};

size_t storeData(const TelemetryData &data) {
  cbor::Writer cbor{bp};

  // The following reset() call is only necessary if we don't know
  // the position of the printer, and if we wanted to reset it
  // to the beginning
  bp.reset();

  // cbor.writeTag(cbor::kSelfDescribeTag);
  // cbor.beginArray(2);
  // cbor.writeBoolean(data.flag);
  // cbor.writeFloat(data.temperature);
  cbor.beginMap(2);

  cbor.beginText(1);
  cbor.writeByte('s');
  cbor.writeBoolean(data.flag);

  cbor.beginText(1);
  cbor.writeByte('t');
  cbor.writeFloat(data.temperature);
  size_t bufferUsed = cbor.getWriteSize();
  Serial.print("bytes used: ");
  Serial.println(bufferUsed);
  return bufferUsed;
}