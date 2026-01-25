#!/usr/bin/env bash
set -euo pipefail

# Usage examples:
#   ./monitor_script.sh build --split --quiet
#   ./monitor_script.sh build --split
#   ./monitor_script.sh run --mode train --force P --workload thread_stress --args "5 5 20000"
#   ./monitor_script.sh run --mode observe --workload thread_stress --args "5 5 20000"
#   ./monitor_script.sh run --mode train_observe --force E --dataset out.csv --workload thread_stress --args "30 10 20000"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SO_PATH="$ROOT_DIR/libmonitor.so"
PB_OBJ="$ROOT_DIR/perf_backend.o"

CORESET_DEFAULT="0-15"
INTERVAL_MS_DEFAULT="100"

die() { echo "ERROR: $*" >&2; exit 1; }

build() {
  local split=0 quiet=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --split) split=1; shift;;
      --quiet) quiet=1; shift;;
      *) die "unknown build option: $1";;
    esac
  done

  local cflags="-O2 -fPIC"
  if [[ $split -eq 1 ]]; then cflags="$cflags -DMONITOR_SPLIT_DEBUG"; fi
  if [[ $quiet -eq 1 ]]; then cflags="$cflags -DQUIET_MONITOR"; fi

  echo "[build] compiling perf_backend.c -> perf_backend.o"
  gcc -O2 -c -fPIC "$ROOT_DIR/perf_backend.c" -o "$PB_OBJ"

  echo "[build] compiling libmonitor.c -> libmonitor.so"
  gcc $cflags -shared -o "$SO_PATH" "$ROOT_DIR/libmonitor.c" "$PB_OBJ" -ldl -lpthread

  echo "[build] done: $SO_PATH"
  echo "[build] strings check:"
  strings "$SO_PATH" | grep -E "TRAINING_MODE|MONITOR_FORCE|TRAINING" || true
}

run() {
  local mode="" force="" workload="" args="" coreset="$CORESET_DEFAULT"
  local dataset="" run_id="run" workload_name="workload" warmup="0"
  local interval_ms="$INTERVAL_MS_DEFAULT"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode) mode="$2"; shift 2;;
      --force) force="$2"; shift 2;;
      --workload) workload="$2"; shift 2;;
      --args) args="$2"; shift 2;;
      --coreset) coreset="$2"; shift 2;;
      --dataset) dataset="$2"; shift 2;;
      --run-id) run_id="$2"; shift 2;;
      --workload-name) workload_name="$2"; shift 2;;
      --warmup) warmup="$2"; shift 2;;
      --interval-ms) interval_ms="$2"; shift 2;;
      *) die "unknown run option: $1";;
    esac
  done

  [[ -f "$SO_PATH" ]] || die "missing $SO_PATH (run build first)"
  [[ -n "$mode" ]] || die "--mode required (train|observe|train_observe)"
  [[ -n "$workload" ]] || die "--workload required"
  [[ -x "$ROOT_DIR/$workload" ]] || die "workload not found/executable: $ROOT_DIR/$workload"

  
  export MONITOR_RESAMPLE_INTERVAL_MILLISECONDS="$interval_ms" 2>/dev/null || true
  export LD_PRELOAD="$SO_PATH"
  export CORESET="$coreset"

  case "$mode" in
    observe)
      echo "[run] observe-only (no training vars)"
      unset TRAINING_MODE MONITOR_FORCE DATASET_CSV RUN_ID WORKLOAD_NAME WARMUP_WINDOWS || true
      ;;
    train)
      [[ -n "$force" ]] || die "train mode requires --force P|E"
      echo "[run] training-only force=$force"
      export TRAINING_MODE=1
      export MONITOR_FORCE="$force"
      export WARMUP_WINDOWS="$warmup"
      export RUN_ID="$run_id"
      export WORKLOAD_NAME="$workload_name"
      if [[ -n "$dataset" ]]; then
        export DATASET_CSV="$dataset"
      else
        unset DATASET_CSV || true
      fi
      ;;
    train_observe)
      [[ -n "$force" ]] || die "train_observe mode requires --force P|E"
      echo "[run] training + observation force=$force (still prints/sends)"
      export TRAINING_MODE=1
      export MONITOR_FORCE="$force"
      export WARMUP_WINDOWS="$warmup"
      export RUN_ID="$run_id"
      export WORKLOAD_NAME="$workload_name"
      if [[ -n "$dataset" ]]; then
        export DATASET_CSV="$dataset"
      else
        unset DATASET_CSV || true
      fi
      ;;
    *)
      die "unknown mode: $mode (use train|observe|train_observe)"
      ;;
  esac

  echo "[run] command:"
  echo "      LD_PRELOAD=$LD_PRELOAD $ROOT_DIR/$workload $args"
  exec "$ROOT_DIR/$workload" $args
}

cmd="${1:-}"
shift || true
case "$cmd" in
  build) build "$@";;
  run) run "$@";;
  *) die "usage: $0 {build|run} ...";;
esac