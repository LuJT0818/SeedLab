#!/bin/bash
openssl enc -aes-128-ofb -e \
       	-in task4_f1.txt \
	-out task4_cipher_1.txt \
	-K 00112233445566778999aabbccddeeff \
	-iv 0102030405060708090a0b0c0d0e0f10

openssl enc -aes-128-ofb -e \
        -in task4_f2.txt \
        -out task4_cipher_2.txt \
        -K 00112233445566778999aabbccddeeff \
        -iv 0102030405060708090a0b0c0d0e0f10

openssl enc -aes-128-ofb -e \
        -in task4_f3.txt \
        -out task4_cipher_3.txt \
        -K 00112233445566778999aabbccddeeff \
        -iv 0102030405060708090a0b0c0d0e0f10

openssl enc -aes-128-ofb -d -nopad \
        -in task4_cipher_1.txt \
        -out task4_plain_1.txt \
        -K 00112233445566778999aabbccddeeff \
        -iv 0102030405060708090a0b0c0d0e0f10

openssl enc -aes-128-ofb -d -nopad \
        -in task4_cipher_2.txt \
        -out task4_plain_2.txt \
        -K 00112233445566778999aabbccddeeff \
        -iv 0102030405060708090a0b0c0d0e0f10

openssl enc -aes-128-ofb -d -nopad \
        -in task4_cipher_3.txt \
        -out task4_plain_3.txt \
        -K 00112233445566778999aabbccddeeff \
        -iv 0102030405060708090a0b0c0d0e0f10

wc -c task4_plain_1.txt
wc -c task4_plain_2.txt
wc -c task4_plain_3.txt
