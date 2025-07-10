#!/usr/bin/env sh

sudo -E PATH=$PATH zsh -c "java -Djava.library.path=/nix/store/qw38p671303rs4j1dkdlf70y6zzp1j1b-libbpf-1.5.1/lib --enable-native-access=ALL-UNNAMED -jar target/concurrency-fuzz-scheduler-0.1-SNAPSHOT-jar-with-dependencies.jar $*" -- "$@"
