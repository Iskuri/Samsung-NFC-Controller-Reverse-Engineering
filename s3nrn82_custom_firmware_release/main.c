#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#define CUSTOM_FUNCTIONS_REAL_OFFSET 0x24AE0
#define CUSTOM_FUNCTIONS_OFFSET CUSTOM_FUNCTIONS_REAL_OFFSET-0x2000

// generate jumps to custom functions
uint32_t generateBLFunction(uint32_t currAddress, uint32_t destinationAddress) {


	// +4 to put it to current address
	uint32_t offset = destinationAddress-currAddress-4;

	// two's complement

	if(destinationAddress < currAddress) {
		uint32_t mask = 0b11111111111111111111111;
		// offset += 8;
		offset = ((destinationAddress-currAddress-4) & mask) + ((destinationAddress-currAddress-4) & ~mask);
	}

	// four bytes
	// top nybble of each second byte is f so that it can be relative
	uint8_t blFunction[4];
	memset(blFunction,0,4);

	// 0b11111111111111111111111

	// first instruction value - upper bits
	blFunction[1] = 0xf0; 
	uint32_t val = (offset & 0b11111111111000000000000)>>12;
	blFunction[0] = val&0xff;
	blFunction[1] |= val>>8;
	
	// second instruction value - lower bits
	blFunction[3] = 0xf0;
	blFunction[3] |= 0x08;
	blFunction[2] = (offset & 0b111111111111)>>1;
	blFunction[3] |= (offset>>9);

	uint32_t retVal;
	memcpy(&retVal,blFunction,4);
	// printf("Relocated: %08x\n",retVal);
	return retVal;
}

struct SymbolPointer {
	char symbolName[64];
	uint32_t symbolPointer;
};

struct SymbolPointer symbolPointers[64];
uint32_t symbolPointerCount = 0;

void generateSymbolPointers() {

	char str[65536];
	int f = open("function_pointers.txt",O_RDONLY);
	int pointersSize = read(f,str,65536);
	char lines[64][1024];

	char* pch;
	pch = strtok (str,"\n");
	int lineInc = 0;
	while (pch != NULL) {
		printf ("%s\n",pch);
		strcpy(lines[lineInc],pch);
		lineInc++;

		pch = strtok (NULL, "\n");
	}

	for(int i = 0 ; i < lineInc ; i++) {
		pch = strtok(lines[i]," \n");

		int parseInc = 0;
		uint32_t position = 0;
		while (pch != NULL) {

			switch(parseInc) {
				case 0:
					position = (int)strtol(pch, NULL, 16);
					symbolPointers[symbolPointerCount].symbolPointer = position-1;
					break;
				case 1:
					strcpy(symbolPointers[symbolPointerCount].symbolName,pch);
					printf("Set up pointer: %s %08x - %08x\n",symbolPointers[symbolPointerCount].symbolName,symbolPointers[symbolPointerCount].symbolPointer,symbolPointers[symbolPointerCount].symbolPointer + CUSTOM_FUNCTIONS_REAL_OFFSET);
					symbolPointerCount++;
					break;
			}
			parseInc++;
			pch = strtok (NULL, " \n");
		}
	}

	close(f);
}

uint32_t getSymbolPointer(char* str) {

	for(int i = 0 ; i < symbolPointerCount ; i++) {

		if(strcmp(str,symbolPointers[i].symbolName) == 0) {
			return symbolPointers[i].symbolPointer + CUSTOM_FUNCTIONS_REAL_OFFSET;
		}
	}

	printf("Can't find symbol: %s\n",str);
	exit(1);
	return 0;
}

uint8_t fwData[0x27000-0x2000];

void performRelocations() {

	printf("Performing relocations\n");
	char str[65536];
	char lines[64][1024];

	int f = open("relocations.txt",O_RDONLY);
	int relocationSize = read(f,str,65536);

	char* pch;
	pch = strtok (str,"\n");
	int lineInc = 0;
	while (pch != NULL) {
		printf ("%s\n",pch);
		strcpy(lines[lineInc],pch);
		lineInc++;

		pch = strtok (NULL, "\n");
	}

	for(int i = 0 ; i < lineInc ; i++) {
		pch = strtok(lines[i]," \n");

		int parseInc = 0;
		uint32_t position = 0;
		uint32_t target = 0;
		while (pch != NULL) {

			switch(parseInc) {
				case 0:
					position = (int)strtol(pch, NULL, 16);
					break;
				case 1:
					target = (int)strtol(pch, NULL, 16);
					break;
				case 2: {

					// updating
					uint32_t bl = generateBLFunction(position+CUSTOM_FUNCTIONS_OFFSET+0x3000,target+CUSTOM_FUNCTIONS_OFFSET+0x3000);


					printf("%s pos: %08x target %08x BL: %08x\n",pch,position,target,bl);

					if(target == 0) {
						printf("Couldn't find symbol!\n");
						exit(1);
					}

					memcpy(&fwData[position+CUSTOM_FUNCTIONS_OFFSET],&bl,4);
					break;
				}
			}
			parseInc++;
			pch = strtok (NULL, " \n");
		}
	}

	close(f);
}

int main() {

	// performRelocations();
	// return 0;

	printf("Starting firmware build\n");

	// printf("Doing test branch\n");
	// generateBLFunction(0x4,0x00);
	// generateBLFunction(0,0x37a6);
	// exit(0);

	// get original firmware
	int size = 0;
	int f = open("s3nrn82.bin",O_RDONLY);
	int readSize = read(f,&fwData[0x0000],0x27000-0x2000);
	printf("Original firmware size: %08x\n",readSize);
	close(f);

	// patched in functions
	int ff = open("functions.bin",O_RDONLY);
	readSize = read(ff,&fwData[CUSTOM_FUNCTIONS_OFFSET],0x4000);
	printf("Additional firmware size: %d %08x (%d)\n",ff,readSize,readSize);
	close(ff);

	// relocate function calls
	performRelocations();

	// generate symbol pointers
	generateSymbolPointers();

	// patched version
	fwData[0x0004] = 0x99;

	uint32_t testPointer = getSymbolPointer("overrideVersionNumber");
	printf("Test pointer: %08x\n",testPointer);

	uint32_t versionNumberCall = generateBLFunction(0x10A1E,getSymbolPointer("overrideVersionNumber"));
	printf("Version number call: %08x\n",versionNumberCall);
	memcpy(&fwData[0x10A1E -0x2000],&versionNumberCall,4);

	// arbitrary memory cmd
	uint32_t arbitraryMemoryCall = generateBLFunction(0x10AC4,getSymbolPointer("getArbitraryMemory"));
	memcpy(&fwData[0x10AC4 -0x2000],&arbitraryMemoryCall,4);

	uint32_t overrideStartup = generateBLFunction(0x20C2,getSymbolPointer("overrideStartup"));
	memcpy(&fwData[0x20C2 -0x2000],&overrideStartup,4);

	// interrupt override
	uint32_t interruptPointer = getSymbolPointer("interruptPatch")+1;
	memcpy(&fwData[0x2475C -0x2000],&interruptPointer,4);

	// main nfc call interrupt override
	uint32_t mainNfcInterruptPointer = getSymbolPointer("overrideMainNfcInterrupt")+1;
	memcpy(&fwData[0x24760 -0x2000],&mainNfcInterruptPointer,4);

	// override atqa setup functions
	uint32_t potentialMemorySetup = generateBLFunction(0x5C40,getSymbolPointer("potentialMemorySetup"));
	memcpy(&fwData[0x5C40 -0x2000],&potentialMemorySetup,4);

	fwData[0x9334-0x2000] = 0x99;
	fwData[0x9336-0x2000] = 0x00;
	fwData[0x9337-0x2000] = 0x46;

	fwData[0x1779C-0x2000] = 0xe1;
	fwData[0x1AA66-0x2000] = 0xe1;

	// start address
	uint32_t popAddress = 0x177dc -0x2000;

	// fwData[popAddress] =   0xf8;
	// fwData[popAddress+1] = 0xbd;	

	// fwData[popAddress] =   0x00;
	// fwData[popAddress+1] = 0x00;		
	// fwData[popAddress+2] =   0x00;
	// fwData[popAddress+3] = 0x00;		

	// override function

	// 1aa98 - stops sending completely

	// uint32_t section = 0x177dc-0x2000;
	// fwData[section] = 0xf8;
	// fwData[section+1] = 0xbd;
	// fwData[section+2] = 0x70;
	// fwData[section+3] = 0xbf;

	// works - 0x1aa98
	// 177e2 seems to handle i2c writeback maybe, could also be donig sends - come back to

	// proper setup for function
	uint32_t mentalVal = 0x1aa98;
	uint32_t nfcResponsePos = generateBLFunction(mentalVal,getSymbolPointer("handleNfcRequest"));
	memcpy(&fwData[mentalVal -0x2000],&nfcResponsePos,4);

	// try overriding the interrupt - didn't work
	// uint32_t mentalVal = getSymbolPointer("handleNfcRequest");
	// memcpy(&fwData[0x24760 -0x2000],&mentalVal,4);

	// override 93 check
	// fwData[0x9334 - 0x2000] = 0x95;

	// fwData[0x3a62 - 0x2000] = 0x07;
	// fwData[0x3a63 - 0x2000] = 0xe0;


	// override upper call with i2cresp
	// 017780 - next call to override
	// uint32_t i2cOverride = generateBLFunction(0x017780,0x10A98);
	// uint32_t i2cOverride = generateBLFunction(0x0177d6,getSymbolPointer("sendNfcResponse"));
	// memcpy(&fwData[0x017780 -0x2000],&i2cOverride,4);
	
	// override e1 check
	fwData[0x1aa66 - 0x2000] = 0x00;
	fwData[0x1aa67 - 0x2000] = 0x00;
	fwData[0x1aa68 - 0x2000] = 0x00;
	fwData[0x1aa69 - 0x2000] = 0x00;
	fwData[0x1aa6a - 0x2000] = 0x00;
	fwData[0x1aa6b - 0x2000] = 0x00;
	fwData[0x1aa6c - 0x2000] = 0x00;
	fwData[0x1aa6d - 0x2000] = 0x00;

	fwData[0x1779c - 0x2000] = 0x00;
	fwData[0x1779d - 0x2000] = 0x00;
	fwData[0x1779e - 0x2000] = 0x00;
	fwData[0x1779f - 0x2000] = 0x00;

	// override crc check
	fwData[0x17780 - 0x2000] = 0x00;
	fwData[0x17781 - 0x2000] = 0x00;
	fwData[0x17782 - 0x2000] = 0x00;
	fwData[0x17783 - 0x2000] = 0x00;
	fwData[0x17784 - 0x2000] = 0x00;
	fwData[0x17785 - 0x2000] = 0x00;

	fwData[0x17786 - 0x2000] = 0x07;
	fwData[0x17787 - 0x2000] = 0xe0;

	// potentially override parity check
	fwData[0x177C6 - 0x2000] = 0x04;
	fwData[0x177C7 - 0x2000] = 0xe0;

	fwData[0x177a0 - 0x2000] = 0x00;
	fwData[0x177a1 - 0x2000] = 0x00;
	fwData[0x177a2 - 0x2000] = 0x00;
	fwData[0x177a3 - 0x2000] = 0x00;
	fwData[0x177a4 - 0x2000] = 0x00;
	fwData[0x177a5 - 0x2000] = 0x00;

	fwData[0x177a6 - 0x2000] = 0x07;
	fwData[0x177a7 - 0x2000] = 0xe0;
	
	// fwData[0x1769a - 0x2000] = 0x00;
	// fwData[0x1769b - 0x2000] = 0x00;
	// fwData[0x1769c - 0x2000] = 0x00;
	// fwData[0x1769d - 0x2000] = 0x00;
	// fwData[0x1769e - 0x2000] = 0x00;
	// fwData[0x1769f - 0x2000] = 0x00;

	// fwData[0x176a0 - 0x2000] = 0x00;
	// fwData[0x176a1 - 0x2000] = 0x00;


	// fwData[0x176ae - 0x2000] = 0x00;
	// fwData[0x176af - 0x2000] = 0x00;
	// fwData[0x176b0 - 0x2000] = 0x00;
	// fwData[0x176b1 - 0x2000] = 0x00;

	fwData[0x176c8 - 0x2000] = 0x00;
	fwData[0x176c9 - 0x2000] = 0x00;

	// jump directly to my state machine
	fwData[0x176ae - 0x2000] = 0x68;
	fwData[0x176af - 0x2000] = 0xe0;

	// fix d8s
	fwData[0x1aa7c - 0x2000] = 0x00;
	fwData[0x1aa7d - 0x2000] = 0x00;
	fwData[0x1aa7e - 0x2000] = 0x00;
	fwData[0x1aa7f - 0x2000] = 0x00;

	fwData[0x1aa88 - 0x2000] = 0x00;
	fwData[0x1aa89 - 0x2000] = 0x00;
	fwData[0x1aa8a - 0x2000] = 0x00;
	fwData[0x1aa8b - 0x2000] = 0x00;

	//trying to work out write problems
	fwData[0x14242 - 0x2000] = 0x08;
	// 14242 - causes read problems, look into it

	fwData[0x14AC0 - 0x2000] = 0x09;

	// fwData[0x14C68 - 0x2000] = 0x00;
	// fwData[0x14C69 - 0x2000] = 0x00;
	// fwData[0x14C6a - 0x2000] = 0x00;
	// fwData[0x14C6b - 0x2000] = 0x00;

	// further checking for auth
	// uint32_t identifyParityErrors = generateBLFunction(0x177D6,getSymbolPointer("identifyParityErrors"));
	// memcpy(&fwData[0x177D6 -0x2000],&identifyParityErrors,4);

	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int wf = open("custom_firmware.bin",O_CREAT | O_TRUNC | O_WRONLY,mode);
	int wrSize = write(wf,fwData,0x27000-0x2000);

	printf("Write size: %d %d\n",wrSize,0x27000-0x2000);

	close(wf);

	return 0;
}