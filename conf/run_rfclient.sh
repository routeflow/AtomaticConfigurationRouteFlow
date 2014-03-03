#!/bin/sh
sleep 5
/etc/init.d/quagga start
/opt/rfclient/rfclient > /var/log/rfclient.log &

