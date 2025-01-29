#!/bin/sh

BASEDIR=$(dirname "$0")
cd $BASEDIR

mkdir -p queue_target
javac -d queue_target Queue.java

echo "Queue compiled successfully. Run it via run_queue.sh"