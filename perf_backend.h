#ifndef PERF_BACKEND_H
#define PERF_BACKEND_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MEV_INST_RETIRED = 0,           // Instructions retired
    MEV_CORE_CYCLES,                // Core cycles 
    MEV_REF_CYCLES,                 // Reference cycles (unaffected by frequency)
    MEV_MEM_LOADS,                  // Memory load instructions retired
    MEV_MEM_STORES,                 // Memory store instructions retired
    MEV_L3_LOAD_HIT,                // L3 cache load hits
    MEV_L3_LOAD_MISS,               // L3 cache load misses
    MEV_MEM_STALL_CYCLES,           // Cycles stalled on memory
    MEV_PAGE_FAULTS,                // Page faults
    MEV_UOPS_RETIRED,               // Micro ops retired ( only E-core)
    MEV_NUM_EVENTS
} perf_event_id_t;

typedef struct {
    int cpu;                        // CPU pinned
    int pcore;                      // 1 = P-core 0 = E-core
    int pmu_type;                   // cpu_core or cpu_atom PMU type
    int fds[MEV_NUM_EVENTS];        // perf file descriptors, -1 if not used
} perf_monitor_t;

int perf_monitor_open(int cpu, perf_monitor_t *mon);
int perf_monitor_start(perf_monitor_t *mon);
int perf_monitor_stop_and_read(perf_monitor_t *mon, uint64_t values[MEV_NUM_EVENTS]);
void perf_monitor_close(perf_monitor_t *mon);

#ifdef __cplusplus
}
#endif

#endif // PERF_BACKEND_H