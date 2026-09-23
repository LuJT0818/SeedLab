#!/bin/bash

echo -n "01234" > task4_f1.txt
echo -n "0123456789" > task4_f2.txt
echo -n "0123456789abcde"> task4_f3.txt

wc -c task4_f1.txt
wc -c task4_f2.txt
wc -c task4_f3.txt
