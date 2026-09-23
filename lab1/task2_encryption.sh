#!/bin/bash
openssl enc -aes-128-cbc -e \
  -in task2_plain.txt \
  -out task2_cipher.bin \
  -K 00112233445566778999aabbccddeeff \
  -iv 0102030405060708090a0b0c0d0e0f10
