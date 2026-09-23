#!/bin/bash

tr [:upper:] [:lower:] < ./Labsetup/Files/ciphertext.txt > lowercase.txt
tr -cd '[a-z][\n][:space:]' < lowercase.txt > ciphertext.txt