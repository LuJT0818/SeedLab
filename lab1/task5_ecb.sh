#!/bin/bash

openssl enc -aes-128-ecb -e \
        -in task5_text.txt \
        -out task5_cipher.txt \
        -K 00112233445566778999aabbccddeeff

bless task5_cipher.txt

openssl enc -aes-128-ecb -d \
        -in task5_cipher.txt \
        -out task5_plain.txt \
        -K 00112233445566778999aabbccddeeff

vim task5_plain.txt
