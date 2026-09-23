#!/bin/bash

openssl enc -aes-128-cbc -e \
        -in task5_text.txt \
        -out task5_cipher.txt \
        -K 00112233445566778999aabbccddeeff \
        -iv 0102030405060708090a0b0c0d0e0f10

bless task5_cipher.txt

openssl enc -aes-128-cbc -d \
        -in task5_cipher.txt \
        -out task5_plain.txt \
        -K 00112233445566778999aabbccddeeff \
        -iv 0102030405060708090a0b0c0d0e0f10

vim task5_plain.txt
