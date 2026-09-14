#!/bin/bash
apk=$1

name=$(aapt dump badging "$apk" |
    grep "application-label-zh-CN" |
    awk -F ":" '{print $2}' |
    awk -F "'" '{print $2}')

if [ -z "$name" ]; then
    name=$(aapt dump badging "$apk" |
        grep "application-label-zh" |
        awk -F ":" '{print $2}' |
        awk -F "'" '{print $2}')
fi

if [ -z "$name" ]; then
    name=$(aapt dump badging "$apk" |
        grep "application-label" |
        awk -F ":" '{print $2}' |
        awk -F "'" '{print $2}')
fi

printf '%s\n' "$name"
