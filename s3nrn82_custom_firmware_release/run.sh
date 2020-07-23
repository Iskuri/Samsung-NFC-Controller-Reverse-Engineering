#!/bin/bash

make &&\
adb push ../s3nrn82_custom_firmware_release /sdcard/ &&\
adb shell 'su -c mv /sdcard/s3nrn82_custom_firmware_release /data/local/' &&\
adb shell 'su -c chmod +x /data/local/s3nrn82_custom_firmware_release/run'
