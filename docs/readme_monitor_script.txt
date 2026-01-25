OpenPerfML – monitor_script usage (cheatsheet)
=============================================

Applies to:
- Linux + perf_event_open backend
- Intel Alder Lake (hybrid P-core / E-core) only (current validated target)

Why Alder Lake-only right now:
- P/E detection uses: /sys/devices/system/cpu/cpu*/topology/core_type
- Some counter selection differs on P vs E cores

----------------------------------------------------------------------
Build variants
----------------------------------------------------------------------

All commands assume you are at the repository root.

Default build (no extra macros):
  ./scripts/monitor_script.sh build

Build with placement/debug prints (MONITOR_SPLIT_DEBUG):
  ./scripts/monitor_script.sh build --split

Build quiet (QUIET_MONITOR):
  ./scripts/monitor_script.sh build --quiet

Build split + quiet:
  ./scripts/monitor_script.sh build --split --quiet

Output:
- ./libmonitor.so  (LD_PRELOAD shared library)

----------------------------------------------------------------------
Example workload
----------------------------------------------------------------------

Compile the included example workload:
  gcc -O2 -o examples/highmiss_loop examples/highmiss_loop.c
  chmod +x examples/highmiss_loop

----------------------------------------------------------------------
Run / Observe (no dataset logging)
----------------------------------------------------------------------

Observe-only:
  ./scripts/monitor_script.sh run --mode observe --workload examples/highmiss_loop --args "5 5 20000"

Tip: you can also run manually:
  LD_PRELOAD=./libmonitor.so CORESET="0-15" ./examples/highmiss_loop 5 5 20000

----------------------------------------------------------------------
Training / Dataset logging (Alder Lake only)
----------------------------------------------------------------------

Training-only (no dataset file):
  ./scripts/monitor_script.sh run --mode train --force P --workload examples/highmiss_loop --args "5 5 20000"

Training + dataset logging (CSV):
  ./scripts/monitor_script.sh run \
    --mode train \
    --force E \
    --dataset train.csv \
    --run-id r2 \
    --workload-name highmiss_loop \
    --warmup 0 \
    --workload examples/highmiss_loop \
    --args "5 5 20000"

Notes:
- --force {P|E} pins threads to P-cores or E-cores (Alder Lake hybrid only).
- --warmup N skips the first N sampling windows before writing rows to the CSV.
- --interval-ms controls sampling interval (default: 100ms).
- --coreset controls which CPUs are allowed (must match your system topology).

----------------------------------------------------------------------
Advanced (manual environment variables)
----------------------------------------------------------------------

This is equivalent to what the script configures internally:

  TRAINING_MODE=1 \
  MONITOR_FORCE=P \
  WARMUP_WINDOWS=5 \
  RUN_ID=runP \
  WORKLOAD_NAME=highmiss_loop \
  DATASET_CSV=train_P.csv \
  LD_PRELOAD=./libmonitor.so \
  CORESET="0-15" \
  taskset -c 0-15 ./examples/highmiss_loop 5 5 20000

----------------------------------------------------------------------
Removed / deprecated parts
----------------------------------------------------------------------

The following were part of older experiments and are no longer included:
- Python scripts: fit_models.py, parse_scheduler_log.py, parse_sched_eval.py
- scheduler build/run instructions (scheduler.c is not part of this repo anymore)