#!/bin/bash

function notify-send() {
    local display=":$(ls /tmp/.X11-unix/* | sed 's#/tmp/.X11-unix/X##' | head -n 1)"
    local user=$(who | grep "($display)" | awk '{print $1}' | head -n 1)
    local uid=$(id -u "$user")
    sudo -u "$user" DISPLAY+"$display" DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus notify-send "$@"
}
