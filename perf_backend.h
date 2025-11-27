#ifndef PERF_BACKEND_H
#define PERF_BACKEND_H

#include <stdint.h>
// c / c++ compatible
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MEV_INST_RETIRED = 0,          // P-core: INST_RETIRED.ANY_P, E-core: UOPS_RETIRED.ALL
    MEV_CACHE_MISSES,              // LLC misses
    MEV_CORE_CYCLES,               // UNHALTED_CORE_CYCLES
    MEV_MEM_INST_RETIRED,          // P-core: MEM_INST_RETIRED.ANY, E-core: MEM_UOPS_RETIRED.ALL_LOADS
    MEV_PAGE_FAULTS,               // Page falts
    MEV_CYCLE_ACTIVITY_MEM,        // P-core only: CYCLE_ACTIVITY.CYCLES_MEM_ANY
    MEV_UOPS_RETIRED,              // E-core only: UOPS_RETIRED.ALL
    MEV_NUM_EVENTS
} perf_event_id_t;

typedef struct {
    int cpu;                        // logical CPU set (pinned)
    int pcore;                      // 1 = P-core, 0 = E-core
    int pmu_type;                   // cpu_core or cpu_atom pmu type
    int fds[MEV_NUM_EVENTS];        // perf fds -1 if not used
} perf_monitor_t;


int perf_monitor_open(int cpu, perf_monitor_t *mon);

int perf_monitor_start(perf_monitor_t *mon);

/**
 * value[i] corresponds to perf_event_id_t i.
 * if an event is not available on this core value[i] is set to 0.
 */
int perf_monitor_stop_and_read(perf_monitor_t *mon, uint64_t values[MEV_NUM_EVENTS]);

void perf_monitor_close(perf_monitor_t *mon);

#ifdef __cplusplus
}
#endif

#endif // PERF_BACKEND_H