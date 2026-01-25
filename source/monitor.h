#ifndef MONITOR_H
#define MONITOR_H

#define NUM_EVENTS 7
#define MAX_THREADS 64
#define MAX_CPUS 256

typedef struct {
    unsigned long long rchar;
    unsigned long long wchar;
    unsigned long long syscr;
    unsigned long long syscw;
    unsigned long long read_bytes;
    unsigned long long write_bytes;
} ProcessIOStats;

typedef struct {
    double IPC;
    double Cache_Miss_Ratio;
    double Uop_per_Cycle;
    double MemStallCycle_per_Mem_Inst;
    double MemStallCycle_per_Inst;
    double Fault_Rate_per_mem_instr;
    double RChar_per_Cycle;
    double WChar_per_Cycle;
    double RBytes_per_Cycle;
    double WBytes_per_Cycle;
} PerformanceRatios;

typedef struct {
    int thread_count;
    int hw_thread_count;
    int pthread_count;
    int pcore_count;
    int ecore_count;
    int total_cores;
    long long total_values[NUM_EVENTS];
    ProcessIOStats io_delta;
    PerformanceRatios ratios;
    double exec_time_ms;
    double dt_ms;
    double compute_prob_cjson;
    double io_prob_cjson;
    double memory_prob_cjson;
    double compute_prob_cjson_2step;
    double io_prob_cjson_2step;
    double memory_prob_cjson_2step;
    double compute_prob_onnx;
    double io_prob_onnx;
    double memory_prob_onnx;
    double compute_prob_onnx_2step;
    double io_prob_onnx_2step;
    double memory_prob_onnx_2step;

} MonitorData;

#endif