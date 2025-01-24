Concurrency Fuzz Scheduler
===========

A scheduler that creates random scheduling edge cases and is written in Java using [hello-ebpf](https://github.com/parttimenerd/hello-ebpf).

## Usage

```
./scheduler.sh [script to execute] --cores 3 (limit to core 0..N-1) --sleep 0.1s,100s --run 10s,100s --seed 100 --error-command ./error.sh (else error code != 0 will be used) --iteration-time 100s (restart every 100s) --exclusive-cores (keep the cores exclusive) --slice 1ms --system-slice 1ms --dont-scale-slice
```

Runs the specified process or script under controlled scheduling on cores 0–2. It alternates between randomized sleep (0.1–100s) and run phases for 100 iterations, with a max duration of 10s per iteration. A seed ensures reproducibility, and an error-checking script (./error.sh) validates conditions after each cycle, terminating early if issues are detected and printing the schedule for debugging. (edited)

this has enough config params so that we can simulate scenarios, but limits it to the most important

the random number generation would be done using a simple generator in the kernel (seeding for basic reproducability)

```sh
./scheduler.sh
```

Or when considering only firefox and slicing the scale:
```
./scheduler.sh --bpm=200 --scale-slice --filter firefox
```

## Install

Install a 6.12 (or later) kernel, on Ubuntu use [mainline](https://github.com/bkw777/mainline) if you're on Ubuntu 24.10 or older.

You should also have installed:

- `libbpf-dev`
- clang
- Java 23

Now you just have to build the sound-of-scheduling via:

```sh
mvn package
```

You can speed it up with `mvnd`.

License
=======
GPLv2