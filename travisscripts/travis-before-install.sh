#!/bin/sh

echo start-travis-before-install
sudo sed -i 's/localhost.localdomain//' /etc/hosts
sudo cat /etc/hosts
sudo apt-get update
echo end-travis-before-install