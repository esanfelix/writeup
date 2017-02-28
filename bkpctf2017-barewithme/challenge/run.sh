#!/bin/sh

appline=$(head -c 1000 /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"BkP{This is the flag.}"
qemu-system-arm -M versatilepb -cpu cortex-a15 -m 128M -nographic -kernel boot.bin -monitor /dev/null -append "$appline" -s 2>/dev/null
