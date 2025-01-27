#!/usr/bin/sh

sudo -E PATH=$PATH zsh -c "java --enable-native-access=ALL-UNNAMED -jar target/concurrency-fuzz-scheduler-0.1-SNAPSHOT-jar-with-dependencies.jar $*" -- "$@"
