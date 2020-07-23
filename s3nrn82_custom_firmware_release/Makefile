all:
	arm-none-eabi-gcc -O2 -mthumb -c functions.c
	arm-none-eabi-objdump -d functions.o
	#readelf -r functions.o | grep THM
	#arm-none-eabi-objdump -d functions.o | egrep -i '[0-9a-f]{8} <' | while read line; do echo $(echo $line | cut -d' ' -f1)' '$(echo $line | cut -d'<' -f2| cut -d'>' -f1); done
	arm-none-eabi-objcopy --only-section=.text --image-base=0x2000 --section-alignment=0x2000 -O binary functions.o functions.bin
	readelf -r functions.o | grep THM |sed 's/  */ /g' | cut -d' ' -f5,1,4 | tee relocations.txt
	readelf -s functions.o | grep FUNC | sed 's/  */ /g'  | cut -d' ' -f 3,9 | tee function_pointers.txt
	gcc -o generate_firmware main.c
	./generate_firmware
	aarch64-linux-gnu-gcc-8 -static -o run run_firmware.c

updaters:
# 	gcc updater.c -o update
# 	gcc run_firmware.c -o run	
	aarch64-linux-gnu-gcc-8 -static -o run run_firmware.c