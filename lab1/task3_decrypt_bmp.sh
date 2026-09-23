#!/bin/bash

openssl enc -aes-128-ecb -d -in p1.bmp -out task3_ebc_plain.bmp \
	-K 00112233445566778999aabbccddeeff 
openssl enc -aes-128-cbc -d -in p2.bmp -out task3_cbc_plain.bmp \
	-K 00112233445566778999aabbccddeeff \
	-iv 0102030405060708090a0b0c0d0e0f10
