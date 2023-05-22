#!/bin/bash
echo ADMIN ACCOUNT RESET
echo

read -p 'Admin account (admin): ' username
if [ "${username}" = "" ]; then
    username="admin"
fi

while true; do
    read -sp "Password for ${username}: " password
    echo
    read -sp "Repeat password: " repeat
    echo
    [ "$password" = "$repeat" ] && break
    echo ERROR: Password mismatch!
    echo
done

venv/bin/python netadmin_api_server.py --reset ${username} ${password}

