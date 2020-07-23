#include <stdint.h>
#include "functions.h"

#define TAG_STATE_OFFSET 0x20002000

uint16_t crc16(uint8_t* data, uint16_t length) {

	uint32_t wCrc = 0x6363;
	uint16_t pbtCrc = 0;
	do {
		uint8_t bt;
		bt = *data++;
		bt = (bt ^ (uint8_t)(wCrc & 0x00FF));
		bt = (bt ^ (bt << 4));
		wCrc = (wCrc >> 8) ^ ((uint32_t) bt << 8) ^ ((uint32_t) bt << 3) ^ ((uint32_t) bt >> 4);
	} while (--length);

	pbtCrc = ((uint8_t)(wCrc & 0xFF) << 8);
	pbtCrc |= (uint8_t)((wCrc >> 8) & 0xFF);

	return pbtCrc;
}

uint16_t crc16_ccitt(uint8_t* data, uint8_t length) {
	uint16_t crc = 0xFFFF;

	int i = 0;
	for (i = 0; i < length ; i++) {
		uint16_t x = ((crc >> 8) ^ data[i]) & 0xFF;
		x ^= x >> 4;
		crc = ((crc << 8) ^ (x << 12) ^ (x << 5) ^ x) & 0xFFFF;
	}
	return crc;
}

void tmemcpy(uint8_t* dst, uint8_t* src, int len) {

	for(int i = 0 ; i < len ; i++) {
		dst[i] = src[i];
	}
}

void tmemset(uint8_t* dst, uint8_t val, int len) {

	for(int i = 0 ; i < len ; i++) {
		dst[i] = val;
	}
}

uint32_t tmemcmp(uint8_t* a, uint8_t* b, int len) {

	uint32_t diff = 0;

	for(int i = 0 ; i < len ; i++) {

		if(a[i] != b[i]) {
			diff++;
			break;
		}
	}
	return diff;
}

void cryptoInit(uint32_t* cryptoState, uint8_t* key) {

	cryptoState[0] = 0x00000000;
	cryptoState[1] = 0x00000000;

	int i = 0, j = 0;

	for(i = 5 ; i >= 0 ; i--) {

		for(j = 7 ; j > 0 ; j -= 2) {
			cryptoState[1] = cryptoState[1] << 1 | (key[i]>>((j-1) ^ 7)&1);
			cryptoState[0] = cryptoState[0] << 1 | (key[i]>>((j) ^ 7)&1);
		}
	}
}

int cryptoParity(uint32_t x) {
	x ^= x >> 4;
	x ^= x >> 8;
	x ^= x >> 16;
	return (0x6996 >> (x & 0xf)) & 1;
}

uint8_t cryptoFilter(uint32_t x) {

	uint32_t f =
	(0xf22c0UL >> (x & 0xf)) & 16;
	x >>=4;
	f |= 0x6c9c0UL >> (x & 0xf) & 8;
	x >>=4;
	f |= 0x3c8b0UL >> (x & 0xf) & 4;
	x >>=4;
	f |= 0x1e458UL >> (x & 0xf) & 2;
	x >>=4;
	f |= 0x0d938UL >> (x & 0xf) & 1;

	return (0xEC57E80AUL>>f)&1;
}

uint8_t cryptoGetBit(uint32_t* cryptoState, uint8_t in, uint8_t isEncrypted) {

	uint8_t ret = cryptoFilter(cryptoState[1]);
	uint32_t feed = ret & !!isEncrypted;
	feed ^= !!in;
	feed ^= 0x29CE5C & cryptoState[1];
	feed ^= 0x870804 & cryptoState[0];
	cryptoState[0] = cryptoState[0] << 1 | cryptoParity(feed);

	// switch values
	cryptoState[1] ^= cryptoState[0];
	cryptoState[0] ^= cryptoState[1];
	cryptoState[1] ^= cryptoState[0];

	return ret;
}

uint8_t cryptoGetByte(uint32_t* cryptoState, uint8_t in, uint8_t isEncrypted) {

	uint8_t ret = 0;
	int i = 0;
	for(i = 0 ; i < 8 ; i++) {
		ret |= (cryptoGetBit(cryptoState,(in>>i)&1,isEncrypted)<<i);
	}

	return ret;
}

uint32_t cryptoGetWord(uint32_t* cryptoState, uint32_t in, uint8_t isEncrypted) {

	uint32_t ret = 0;
	int i = 0;
	for(i = 0 ; i < 32 ; i++) {

		uint32_t bit = (cryptoGetBit(cryptoState,(in>>i)&1,isEncrypted)<<(i));
		ret |= bit;
	}

	return ret;
}

uint8_t checkParity(uint8_t val) {

  int k = 0;
  uint8_t bitVal = 0;
  for(k = 0 ; k < 8 ; k++) {
    bitVal += (val>>k) & 1;
  }

  if(bitVal&1) {
    return 0;
  } else {
    return 1;
  }
}

// end of crypto, start of reveng calls

uint32_t potentialMemorySetup(uint32_t r0) {

	uint32_t (*setupFunction)(uint32_t) = (uint32_t (*)(uint32_t))0xBD47;

	uint32_t val = setupFunction(r0);

	// override atqa and uid
	uint32_t* uidPtr = 0x40020034;
	uint32_t* atqaPtr = 0x4002003c;
	uint32_t* sakPtr = 0x40020040;

	struct TagState* tagState = TAG_STATE_OFFSET;

	memcpy(&uidPtr[0],&tagState->tagHeader[0],8);

	atqaPtr[0] = 0x44000000;
	
	sakPtr[0] = 0x00040988;

	unsigned char* nfcCmdPtr = 0x40020200;
	uint32_t* startPtr = 0x40020030;

	tagState->setupState = State_Selected;
	tagState->cryptoAuthState = 0;

	// if(nfcCmdPtr[0] == 0x95) {

	// 	struct TagState* tagState = TAG_STATE_OFFSET;
	// 	tmemcpy(tagState->commandData,nfcCmdPtr,32);

	// 	unsigned char* cmd = &tagState->commandData;
	// 	uint8_t* lengthPos = 0x40020048;
	// 	uint8_t cmdLength = lengthPos[0]/8;	

	// 	handleSelect2(cmd,cmdLength,tagState);
	// 	startPtr[0] = 0x00000088;
	// }

	// void (*setupResponseHeader)(uint32_t,uint32_t) = (void (*)(uint32_t,uint32_t))0x10889;
	// setupResponseHeader(0x0f,0x97);		
	// unsigned char* i2cBlock = 0x20000D24;;
	// i2cBlock[2] = 0x10;
	// tmemcpy(&i2cBlock[3],0x40020200,16);
	// void (*sendCraftedNfcResponse)(void) = (void (*)(void))0x119BF;
	// sendCraftedNfcResponse();	

	return val;
}

void secondInterruptPatch() {

	// void (*i2cRespSend)(void) = (void (*)(void))0x10A99;
	// i2cRespSend();		

	// void (*nfcInterrupt)(void) = (void (*)(void))0x9e73;
	// nfcInterrupt();		

}

void interruptPatch() {

	// void (*i2cRespSend)(void) = (void (*)(void))0x10A99;
	// i2cRespSend();		


	// struct TagState* tagState = TAG_STATE_OFFSET;

	// tagState->setupState = State_Selected;
	// tagState->cryptoAuthState = 0;

	void (*nfcInterrupt)(void) = (void (*)(void))0x9e73;
	nfcInterrupt();		

}

// keep eye on function_handling_c_and_14_values completely_weird_function 

// 0x40020008 - length data
// 0x40020010 - send data
// 0x40020004 - 0x4000 or controls party
// 0x40020100 - response data
// 0x40020200 - cmd data

// make sure to check between enabling and disabled 0x4000 parity
void sendNfcParityResponse(uint8_t* data, uint8_t len) {

	volatile uint32_t* mem32 = 0x00;
	volatile uint8_t* mem = 0x00;

	uint8_t* nfcBuff = 0x40020100;

	mem32[0x40020030/4] = 0xffffffff;
	mem32[0x400200a4/4] = 0xffffffff;

	mem32[0x40020008/4] = ((len*9));
	mem32[0x4002000c/4] = 0x01000000;

	// PARITY CONTROLLER BIT
	mem32[0x40020004/4] |= 0x4000;

	uint16_t byte = 0;
	uint16_t bit = 0;

	tmemset(nfcBuff,0,32);
	for(int i = 0 ; i < len ; i++) {

		for(int j = 0 ; j < 8 ; j++) {

			if( (data[i]&(1<<j)) != 0 ) {
				nfcBuff[byte] |= (1<<bit);
			}

			bit++;

			if(bit>7) {
				byte++;
				bit = 0;
			}
		}

		uint8_t parityBit = checkParity(data[i]);

		// parityBit ^= 1;

		nfcBuff[byte] |= (parityBit<<bit);
		bit++;

		if(bit>7) {
			byte++;
			bit = 0;
		}
	}

	// for(int i = 0 ; i < len ; i++) {
	// 	nfcBuff[i] = data[i];
	// }

	mem32[0x40020010/4] = 0x80003;

}

void sendAck(struct TagState* tagState) {

	volatile uint32_t* mem32 = 0x00;
	volatile uint8_t* mem = 0x00;

	uint8_t* nfcBuff = 0x40021100;
	
	uint8_t ack = 0x0a;
	uint8_t cryptoByte = 0x00;
	for(int i = 0 ; i < 4 ; i++) {
		cryptoByte |= ((cryptoGetBit(tagState->cryptoState,0,0) ^ ((ack>>i)&1)))<<i;
	}

	// ack ^= cryptoByte;
	// ack &= 0x0f;

	mem32[0x40020030/4] = 0xffffffff;
	mem32[0x400200a4/4] = 0xffffffff;

	mem32[0x40020004/4] &= ~0x4000;

	mem32[0x40020008/4] = 0x00004000 | (cryptoByte<<16);

	// nfcBuff[0] = ack;
	// mem32[0x40020008/4] = 0x00000008;

	mem32[0x40020010/4] = 0x80001;
}

void sendNfcBitResponse(uint8_t* data, uint16_t len) {

	volatile uint32_t* mem32 = 0x00;
	volatile uint8_t* mem = 0x00;

	uint8_t* nfcBuff = 0x40020100;

	mem32[0x40020030/4] = 0xffffffff;
	mem32[0x400200a4/4] = 0xffffffff;

	mem32[0x40020008/4] = ((len*9));
	mem32[0x4002000c/4] = 0x01000000;

	// PARITY CONTROLLER BIT
	mem32[0x40020004/4] |= 0x4000;

	for(int i = 0 ; i < (len+4) ; i++) {
		nfcBuff[i] = data[i];
	}

	mem32[0x40020010/4] = 0x80003;

}

void sendBlock(struct TagState* tagState, uint8_t block) {

	// read block
	for(int i = 0 ; i < 16 ; i++) {
		tagState->respData[i] = tagState->tagHeader[(block*16) + i];
	}
	uint16_t crc = crc16(tagState->respData,16);
	tagState->respData[16] = crc>>8;
	tagState->respData[17] = crc&0xff;

	// encrypt
	if(tagState->cryptoAuthState == CryptoState_AuthNone) {

		sendNfcResponse(tagState->respData,18);
	} else {

		tmemset(tagState->parityRespData,0,32);

		uint16_t byte = 0;
		uint16_t bit = 0;

		// authenticated
		for(int i = 0 ; i < 18 ; i++) {
			
			uint8_t unEncVal = tagState->respData[i];
			tagState->respData[i] = tagState->respData[i] ^ cryptoGetByte(tagState->cryptoState,0,0);

			for(int j = 0 ; j < 8 ; j++) {

				if( (tagState->respData[i]&(1<<j)) != 0 ) {
					tagState->parityRespData[byte] |= (1<<bit);
				}

				bit++;

				if(bit>7) {
					byte++;
					bit = 0;
				}
			}


			// uint8_t parityBit = checkParity(tagState->respData[i]);
			// parityBit ^= 1;

			// crypto parity bit, FINGERS CROSSED
			uint8_t parityBit = (cryptoFilter(tagState->cryptoState[1]) ^ checkParity(unEncVal)) & 1;

			tagState->parityRespData[byte] |= (parityBit<<bit);
			bit++;

			if(bit>7) {
				byte++;
				bit = 0;
			}

		}

		sendNfcBitResponse(tagState->parityRespData, 18);
	}

}

// don't touch this
void sendNfcResponse(uint8_t* data, uint8_t len) {

	volatile uint32_t* mem32 = 0x00;
	volatile uint8_t* mem = 0x00;

	// see what this does

	// no changes based on this
	// mem32[0x40020030/4] = 0x00000001;
	uint8_t* nfcBuff = 0x40020100;

	// check 0x4002000c's purpose
	// 01 does nothing
	// 02 makes weird data pop out
	// 04 different weird data
	// 08 weird data, looks bitshifted
	// 10 more bitshift
	// 20 bs
	// 40
	// mem32[0x4002000c/4] = 0x02; 
	// mem32[0x4002000c/4] = 0x20; 

	// try 0x40020054 at some point
	// mem[0x40020300] = 0x00; 

	// tmemcpy(nfcBuff,data,len);

	// 0x1000 bit does something weird!!!
	// mem32[0x40020008/4] = ((len*8)) | 0x1000;

	// for ack use 0x40020008 = 0x00??4000

	// for reading from only
	// mem32[0x40020004/4] = 0xffffffff; 

	mem32[0x40020030/4] = 0xffffffff;
	mem32[0x400200a4/4] = 0xffffffff;

	mem32[0x40020008/4] = ((len*8));
	// mem32[0x4002000c/4] = 0x01000000;

	mem32[0x40020004/4] &= ~0x4000;

	// PARITY CONTROLLER
	// mem32[0x40020004/4] |= 0x4000;

	// mem32[0x40020010/4] = 0x8000;
	// mem32[0x40020008/4] = ((len*8)) | 0x08249000;
	// mem[0x4002000c] = 0x00; 

	for(int i = 0 ; i < len ; i++) {
	// for(int i = 0 ; i < 0x20 ; i++) {
		nfcBuff[i] = data[i];
	}

	// mem32[0x4002001c/4] = 0x03;

	// mem32[0x40020008/4] = len*8;

	// 14 next --- doesn't do anything
	// mem[0x40020014] = 0xff;

	// ends with 1, no crc, ends with 9, has crc
	// 0x00 - no response
	// 0x02 - no change
	// 0x04 - crc
	// 0x08 - different crc
	// 0x10 - sends 2a2a2a2a (when sending aaaaa)
	// 0x20 - no difference
	// 0x40 - no difference
	// 0x80 - nothing
	// 0x100 - 6a first time then nothing
	// 0x200 - nothing
	// 0x400 - nothing
	// 0x800 - nothing
	// mem[0x40020010] = 0x01;
	// mem[0x40020010] = 0x01;
	// 0x40000001 - huge prepend - B7 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF BF BE BE BE BE BE BE BE BE BE BE BE BE BE BE 06
	// 0x20000001 - huge prepend - B7 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF BF BE BE BE BE BE BE BE BE BE BE BE BE BE BE 06
	// mem32[0x40020010/4] = 0x00000001;
	mem32[0x40020010/4] = 0x80003;

	// mem32[0x40020010/4] = 0x80063;

	// unsigned char* nfcCmdPtr = 0x40020200;
	// if(nfcCmdPtr[0] != 0x60 && nfcCmdPtr[0] != 0x93) {
	// 	void (*i2cRespSend)(void) = (void (*)(void))0x10A99;
	// 	i2cRespSend();		
	// }

}

uint32_t identifyParityErrors(uint32_t r0, uint32_t r1) {

	unsigned char* nfcCmdPtr = 0x40020200;

	if(nfcCmdPtr[0] != 0xd8) {

		uint32_t  (*moveOn)(uint32_t,uint32_t) = (uint32_t (*)(uint32_t,uint32_t))0x1AA5F;
		return moveOn(r0,r1);		

	} else {

		void (*i2cRespSend)(void) = (void (*)(void))0x10A99;
		i2cRespSend();		

	}
	return 0;

}

void handleSelect1(unsigned char* cmd, int cmdLength, struct TagState* tagState) {

	// handle nvb stuff
	if(cmd[1] == 0x20) {
		// uid stuff
		tmemcpy(tagState->respData,tagState->tagHeader,5);

		tagState->respData[4] = tagState->respData[0] ^ tagState->respData[1] ^ tagState->respData[2] ^ tagState->respData[3];
		sendNfcResponse(tagState->respData,5);

	} else {

		tagState->respData[0] = 0x0d;

		uint16_t sakVal = crc16(tagState->respData,1);
		tagState->respData[1] = sakVal>>8;
		tagState->respData[2] = sakVal&0xff;

		if(tmemcmp(&cmd[2],tagState->tagHeader,5) == 0) {

			sendNfcResponse(tagState->respData,3);
		}
	}
}

void handleSelect2(unsigned char* cmd, int cmdLength, struct TagState* tagState) {

	// handle nvb stuff
	if(cmd[1] == 0x20) {
		// uid stuff
		tmemcpy(tagState->respData,&tagState->tagHeader[3],4);

		tagState->respData[4] = tagState->respData[0] ^ tagState->respData[1] ^ tagState->respData[2] ^ tagState->respData[3];
		sendNfcResponse(tagState->respData,5);

	// } else if(cmd[1] == 0x70) {
	} else {

		tagState->respData[0] = 0x09;

		uint16_t sakVal = crc16(tagState->respData,1);
		tagState->respData[1] = sakVal>>8;
		tagState->respData[2] = sakVal&0xff;

		// if(tmemcmp(&cmd[2],&tagState->tagHeader[3],4) == 0) {

			tagState->setupState = State_Selected;
			sendNfcResponse(tagState->respData,3);
		// }
	}
}

void handleNfcRequest() {

	unsigned char* nfcCmdPtr = 0x40020200;

	struct TagState* tagState = TAG_STATE_OFFSET;
	tmemcpy(tagState->commandData,nfcCmdPtr,32);

	unsigned char* cmd = &tagState->commandData;
	uint8_t* lengthPos = 0x40020048;
	uint8_t cmdLength = lengthPos[0]/8;	

	// sendNfcResponse(cmd,cmdLength);

	if(tagState->cryptoAuthState != CryptoState_AuthNone && cmdLength < 4) {
		tagState->setupState = State_Ready;
		tagState->cryptoAuthState = CryptoState_AuthNone;
	}

	if(tagState->cryptoAuthState == CryptoState_KeyA && cmdLength >= 4) {

		for(int i = 0 ; i < cmdLength ; i++) {
			cmd[i] = cmd[i] ^ cryptoGetByte(tagState->cryptoState,0,0);
		}

	}

	if(tagState->setupState != State_AwaitingAuth && tagState->setupState != State_AwaitingWriteBlock) {

		// handle reads etc
		switch(cmd[0]) {

			case 0x13: // not massively happy but let's see
			case CMD_REQA: // not massively happy but let's see
			case CMD_WUPA: { // sometimes gets out of sync with true wupa

				tagState->respData[0] = 0x44;
				tagState->respData[1] = 0x00;
				sendNfcResponse(tagState->respData,2);
				tagState->cryptoAuthState = 0;

				break;
			}
			case CMD_SEL_1: {
				handleSelect1(cmd,cmdLength,tagState);
				tagState->cryptoAuthState = 0;
				break;
			}
			case CMD_SEL_2: {
				handleSelect2(cmd,cmdLength,tagState);
				// void (*setupResponseHeader)(uint32_t,uint32_t) = (void (*)(uint32_t,uint32_t))0x10889;
				// setupResponseHeader(0x0f,0x97);		
				// unsigned char* i2cBlock = 0x20000D24;;
				// i2cBlock[2] = 0x10;
				// tmemcpy(&i2cBlock[3],0x40020200,16);
				// void (*sendCraftedNfcResponse)(void) = (void (*)(void))0x119BF;
				// sendCraftedNfcResponse();	
				tagState->cryptoAuthState = 0;

				break;
			}
			case CMD_AUTH_KEY_B:
			case CMD_AUTH_KEY_A: {

				uint8_t nonce[4];
				nonce[0] = 0x01;
				nonce[1] = 0x02;
				nonce[2] = 0x03;
				nonce[3] = 0x04;

				uint8_t key[6];
				key[0] = 0xff;
				key[1] = 0xff;
				key[2] = 0xff;
				key[3] = 0xff;
				key[4] = 0xff;
				key[5] = 0xff;

				// hardcoded nonce
				tagState->respData[0] = nonce[0];
				tagState->respData[1] = nonce[1];
				tagState->respData[2] = nonce[2];
				tagState->respData[3] = nonce[3];

				uint8_t block = cmd[1]>>2;
				cryptoInit(tagState->cryptoState, key);

				int i = 0;
				for(i = 0 ; i < 4 ; i++) {
					cryptoGetByte(tagState->cryptoState,tagState->respData[i] ^ tagState->tagHeader[i+3],0);
				}

				tagState->setupState = State_AwaitingAuth;

				sendNfcResponse(tagState->respData,4);

				tagState->cryptoAuthState = 0;
				// if(tagState->cryptoAuthState != CryptoState_AuthNone) {
				// 	void (*setupResponseHeader)(uint32_t,uint32_t) = (void (*)(uint32_t,uint32_t))0x10889;
				// 	setupResponseHeader(0x0f,0x9b);		
				// 	unsigned char* i2cBlock = 0x20000D24;;
				// 	i2cBlock[2] = 0x10;
				// 	i2cBlock[3] = cmdLength;
				// 	// tmemcpy(&i2cBlock[4],0x40020200,16);
				// 	tmemcpy(&i2cBlock[4],0x40020200,16);
				// 	void (*sendCraftedNfcResponse)(void) = (void (*)(void))0x119BF;
				// 	sendCraftedNfcResponse();	
				// }

				break;
			}
			case CMD_READBLOCK: {

				sendBlock(tagState,cmd[1]);

				break;
			}
			case CMD_WRITEBLOCK:
				tagState->blockToWrite = cmd[1];
				tagState->setupState = State_AwaitingWriteBlock;

				sendAck(tagState);
				break;
			case CMD_HALT: {
				tagState->cryptoAuthState = 0;
				// tagState->respData[0] = 0x77;
				// tagState->respData[1] = 0x77;
				// tagState->respData[2] = 0x77;
				// tagState->respData[3] = 0x77;
				// tagState->respData[4] = 0x77;
				// sendNfcResponse(tagState->respData,5);
				void (*updateHalt)(uint32_t) = (void (*)(uint32_t))0x5E09;
				updateHalt(0);		
				break;
			}
			// case 0x70: {// read memory function

			// 	// uint32_t address = 0;
			// 	// tmemcpy(&address,&cmd[1],4);
			// 	// uint8_t* mem = 0x00000000;
			// 	// tmemcpy(&tagState->respData[0],&mem[address],0x10);
			// 	for(int i = 0 ; i < 0x20 ; i++) {
			// 		tagState->respData[i] = cmd[1];
			// 	}
			// 	sendNfcParityResponse(tagState->respData,16);
			// 	break;
			// }
			default: {

				// tagState->respData[0] = 0x77;
				// tagState->respData[1] = 0x77;
				// tagState->respData[2] = 0x77;
				// tagState->respData[3] = 0x77;
				// tagState->respData[4] = 0x77;
				// sendNfcResponse(tagState->respData,5);
				
				// this magical ack fixes EVERYTHING
				// sendAck(tagState);

				uint8_t* oldPtr = 0x40020200;
				if(oldPtr[0] == 0x50 && oldPtr[1] == 0x00) {
					void (*updateHalt)(uint32_t) = (void (*)(uint32_t))0x5E09;
					updateHalt(0);		
				} else {
					void (*setupResponseHeader)(uint32_t,uint32_t) = (void (*)(uint32_t,uint32_t))0x10889;
					setupResponseHeader(0x0f,0x9a);		
					unsigned char* i2cBlock = 0x20000D24;;
					i2cBlock[2] = 0x10;
					i2cBlock[3] = cmdLength;
					// tmemcpy(&i2cBlock[4],0x40020200,16);
					tmemcpy(&i2cBlock[4],0x40020200,16);
					void (*sendCraftedNfcResponse)(void) = (void (*)(void))0x119BF;
					sendCraftedNfcResponse();		
				}

				tagState->cryptoAuthState = 0;

				// void (*i2cRespSend)(void) = (void (*)(void))0x10A99;
				// i2cRespSend();		

			}
		}


	} else if(tagState->setupState == State_AwaitingWriteBlock) {


		tagState->setupState = State_Selected;
		tmemcpy(&tagState->tagHeader[tagState->blockToWrite*16],&cmd[0],16);

		sendAck(tagState);

		// writes data back
		void (*setupResponseHeader)(uint32_t,uint32_t) = (void (*)(uint32_t,uint32_t))0x10889;
		setupResponseHeader(0x0f,0x99);		
		unsigned char* i2cBlock = 0x20000D24;;
		i2cBlock[2] = 0x11;
		i2cBlock[3] = tagState->blockToWrite;
		tmemcpy(&i2cBlock[4],&cmd[0],16);
		void (*sendCraftedNfcResponse)(void) = (void (*)(void))0x119BF;
		sendCraftedNfcResponse();		

		// do write blocking here if needed

	} else if(tagState->setupState == State_AwaitingAuth) {

		int i = 0;

		for(i = 0 ; i < 4 ; i++) {
    		cryptoGetByte(tagState->cryptoState,cmd[i],1);
		}

		// change this just to loop the 0,0 value
		for(i = 0 ; i < 4 ; i++) {
			cryptoGetByte(tagState->cryptoState,0,0);
		}

		// stupid efficiency increase
		tagState->respData[0] = 0x3c ^ cryptoGetByte(tagState->cryptoState,0,0);
		tagState->respData[1] = 0x2b ^ cryptoGetByte(tagState->cryptoState,0,0);
		tagState->respData[2] = 0xcd ^ cryptoGetByte(tagState->cryptoState,0,0);
		tagState->respData[3] = 0xad ^ cryptoGetByte(tagState->cryptoState,0,0);

		sendNfcResponse(tagState->respData,4);

		tagState->setupState = State_Selected;
		tagState->cryptoAuthState = CryptoState_KeyA;	

	}

}

void overrideMainNfcInterrupt() {


	// struct TagState* tagState = TAG_STATE_OFFSET;

	// tagState->setupState = State_Selected;
	// tagState->cryptoAuthState = 0;

	void (*nfcInterrupt)(void) = (void (*)(void))0x8eb1;
	nfcInterrupt();			

}

void getArbitraryMemory() {

	struct TagState* tagState = TAG_STATE_OFFSET;
	unsigned char* i2cCommandStart   = 0x200009fb-3;
	unsigned char* i2cCommandParams  = 0x200009fb;
	unsigned char* respCommand = 0x20000D24;

	if(i2cCommandStart[0] == 0x2f && i2cCommandStart[1] == 0x24 && i2cCommandStart[2] >= 3) {

		switch(i2cCommandStart[3]) {

			case 0x01: { // writeBlock

				uint8_t blockToWrite = i2cCommandParams[1];
				tmemcpy(&tagState->tagHeader[blockToWrite*16],&i2cCommandParams[2],0x10);

				break;
			}
		}

		respCommand[2] = 0x01;
		respCommand[3] = 0x00;

	} else {


		uint32_t ptrStart = 0;
		// tmemcpy(&ptrStart,&i2cCommandParams[0],4);

		unsigned char* memPos = 0x00000000;

		// respCommand[2] = 0x24;

		// uint32_t* counterPointer = TAG_STATE_OFFSET-0x10;
		// unsigned char* regPtr = counterPointer[0];

		// tmemcpy(&respCommand[3],&regPtr,4);

		// for(int i = 0 ; i < 0x20 ; i++) {
		// 	respCommand[3+4+i] = regPtr[i];
		// }

		// counterPointer[0]+=0x20;

		// if(counterPointer[0] >= 0x20003000) {
		// 	counterPointer[0] = 0x20000000;
		// }

		respCommand[2] = 0x20;

		unsigned char* commandMem = 0x40020200;
		// unsigned char* commandMem = &tagState->commandData;
		tmemcpy(&respCommand[4],&commandMem[0],0x20);

		uint8_t* lengthPos = 0x40020048;
		respCommand[3] = lengthPos[0];
	}

}

void overrideVersionNumber(unsigned char* data) {

	data[0] = 0xaa;
	data[1] = 0xbb;
	data[2] = 0xcc;
	data[3] = 0xdd;
	data[4] = 0xee;

}


void overrideStartup() {

	void (*initializeHardware)(void) = (void (*)(void))0x2225;
	initializeHardware();

	struct TagState* tagState = TAG_STATE_OFFSET;
	tmemset(tagState,0,sizeof(struct TagState));

	uint32_t* counterPointer = TAG_STATE_OFFSET-0x10;

	// counterPointer[0] = 0x40021000;
	counterPointer[0] = 0x20000000;

}