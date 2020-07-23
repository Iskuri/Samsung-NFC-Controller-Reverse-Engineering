#include <stdint.h>

#define CMD_REQA 	0x26
#define CMD_WUPA 	0x52
#define CMD_HALT 	0x50

#define CMD_AUTH_KEY_A 	0x60
#define CMD_AUTH_KEY_B 	0x61

#define CMD_SEL_1 	0x93
#define CMD_SEL_2 	0x95

#define CMD_READBLOCK 0x30
#define CMD_WRITEBLOCK 0xA0

enum SetupState {
	// handles initial requests
	State_Idle_Interrupt,
	State_Ready_Interrupt,
	State_Selected_Interrupt,

	// main state machine
    State_Idle,
    State_Ready,
    State_Selected,
    State_AwaitingAuth,
    State_AwaitingWriteBlock,
    State_Halted
};

enum CryptoAuthState {
	CryptoState_AuthNone,
	CryptoState_KeyA,
	CryptoState_KeyB,
};

struct TagState {
	enum SetupState setupState;
	enum CryptoAuthState cryptoAuthState;
	uint32_t cryptoState[2];
	uint8_t lastSelected;
	uint16_t blockToWrite;
	uint8_t commandData[32];
	// uint8_t unencryptedCommandData[32];
	uint8_t respData[32];
	uint8_t parityRespData[32];
	uint8_t tagHeader[1024];
	uint32_t crcCheckInc;
	uint8_t permissionsSector[16];
};