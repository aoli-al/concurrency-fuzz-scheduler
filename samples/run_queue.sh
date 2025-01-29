#!/bin/sh

BASEDIR=$(dirname "$0")
cd $BASEDIR

if [ ! -d "queue_target" ]; then
    echo "Queue is not compiled. Please run build_queue.sh"
    exit 1
fi

exec java -cp queue_target Queue "$@"