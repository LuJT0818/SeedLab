#!/bin/bash

openssl enc -aes-128-ecb -e -in Labsetup/Files/pic_original.bmp -out p1.bmp \
	-K 00112233445566778999aabbccddeeff \

openssl enc -aes-128-cbc -e -in Labsetup/Files/pic_original.bmp -out p2.bmp \
	-K 00112233445566778999aabbccddeeff \
	-iv 0102030405060708090a0b0c0d0e0f10

head -c 54 Labsetup/Files/pic_original.bmp > header
tail -c +55 p1.bmp > body
cat header body > task3_ecb.bmp

tail -c +55 p2.bmp > body
cat header body > task3_cbc.bmp
