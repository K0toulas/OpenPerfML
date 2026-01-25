---------------Build default (no extra macros):-------------

./monitor_script.sh build

---------------Build with placement/debug prints------------

./monitor_script.sh build --split


--------------Build quiet---------------------------------

./monitor_script.sh build --quiet


------------Build both ---------------------------------

./monitor_script.sh build --split --quiet



----------------Training only-------------------------
./monitor_script.sh run \
  --mode train \
  --force E \
  --workload thread_stress \
  --args "30 10 20000"


---------------Training + dataset logging ------------
./monitor_script.sh run \
  --mode train \
  --force E \
  --dataset train.csv \
  --run-id r2 \
  --workload-name thread_stress \
  --warmup 0 \
  --workload thread_stress \
  --args "30 10 20000"


---------------training:-------------


TRAINING_MODE=1 \
MONITOR_FORCE=P \
WARMUP_WINDOWS=5 \
RUN_ID=runP \
WORKLOAD_NAME=phased_st \
DATASET_CSV=train_P.csv \
LD_PRELOAD=./libmonitor.so \
CORESET="0-15" \
taskset -c 0-7 ./phased_workload 60 300 0

TRAINING_MODE=1 \
MONITOR_FORCE=P \
WARMUP_WINDOWS=5 \
RUN_ID=runP_mt_compute \
WORKLOAD_NAME=mt_compute \
DATASET_CSV=train_mt_compute_P.csv \
LD_PRELOAD=./libmonitor.so \
CORESET="0-15" \
taskset -c 0-7 ./mt_compute -t 20 -s 60


TRAINING_MODE=1 \
MONITOR_FORCE=E \
WARMUP_WINDOWS=5 \
RUN_ID=runP_mt_compute \
WORKLOAD_NAME=mt_compute \
DATASET_CSV=train_mt_compute_E.csv \
LD_PRELOAD=./libmonitor.so \
CORESET="0-15" \
taskset -c 0-7 ./mt_compute -t 20 -s 60



TRAINING_MODE=1 \
MONITOR_FORCE=E \
WARMUP_WINDOWS=5 \
RUN_ID=runE \
WORKLOAD_NAME=phased_st \
DATASET_CSV=train_E.csv \
LD_PRELOAD=./libmonitor.so \
CORESET="0-15" \
taskset -c 8-15 ./phased_workload 60 300 0


---running--------

LD_PRELOAD=./libmonitor.so CORESET="0-15" ./highmiss_loop


---- after training ----
python3 fit_models.py

-----compile scheduler----
gcc -O2 -g -o scheduler scheduler.c cJSON.c -lpthread -lm



----- run scheduler and make log file -------
 ./scheduler 0-15 2>&1 | tee scheduler.log

----- se what cores the scheduler chose-----
python3 parse_scheduler_log.py scheduler.log

----see detailed values------
python3 parse_sched_eval.py scheduler.log


