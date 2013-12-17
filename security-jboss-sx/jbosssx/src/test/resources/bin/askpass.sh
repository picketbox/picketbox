#!/bin/sh

if [ "$1" = "Enter passphrase for askpass test" ]; then
    echo vault22
else
    echo $1
fi
