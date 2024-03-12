#!/bin/bash

START=0

run_server(){
    local END=$(date '+%s')
    local diff=$(($END - $START))
    if [ $diff -gt 3 ]; then
        echo "restarting server..."
        pkill micropython 2> /dev/null
        micropython main.py &
        START=$END
    fi
}

restart(){
    local f=$1
    if ! echo $f | egrep "(\.kate\-swp)|(\.pyc)" > /dev/null 2>&1 ; then
      echo $f
      run_server
    fi
}

file_removed() {
    echo "$2 removed"
    restart $2
}

file_modified() {
    echo "$2 modified"
    restart $2
}

file_created() {
    echo "$2 created"
    restart $2
}

run_server

inotifywait -q -m -r -e modify,delete,create $1 | while read DIRECTORY EVENT FILE; do
    echo $EVENT
    case $EVENT in
        MODIFY*)
            file_modified "$DIRECTORY" "$FILE"
            ;;
        CREATE*)
            file_created "$DIRECTORY" "$FILE"
            ;;
        DELETE*)
            file_removed "$DIRECTORY" "$FILE"
            ;;
    esac
done
