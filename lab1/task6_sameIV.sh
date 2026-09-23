#!/bin/bash

openssl enc -aes-128-cbc -e \
	-in task6_text.txt \
	-out task6_cipher_1.txt \
	-K 00112233445566778999aabbccddeeff \
	-iv 0102030405060708090a0b0c0d0e0f10

openssl enc -aes-128-cbc -e \
        -in task6_text.txt \
        -out task6_cipher_2.txt \
        -K 00112233445566778999aabbccddeeff \
        -iv 0102030405060708090a0b0c0d0e0f10

openssl enc -aes-128-cbc -e \
        -in task6_text.txt \
        -out task6_cipher_3.txt \
        -K 00112233445566778999aabbccddeeff \
        -iv 0102030405060708090a0b0c0d0e0f10
echo "1"
hexdump -C task6_cipher_1.txt
xxd task6_cipher_1.txt

echo "2"
hexdump -C task6_cipher_2.txt
xxd task6_cipher_2.txt

echo "3"
hexdump -C task6_cipher_3.txt
xxd task6_cipher_3.txt
