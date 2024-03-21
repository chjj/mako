#!/bin/sh

for de in `ls . | grep '^t-'`
do
    echo $de
    ./$de
    if test $? != '0'
    then
        echo $de failed
        exit 1
    fi
done

echo all successful

exit 0
