#define _GNU_SOURCE
#include "perf_backend.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>

static const char *event_names[MEV_NUM_EVENTS] = {
    "INST_RETIRED.ANY",
    "CPU_CLK_UNHALTED.THREAD",
    "CPU_CLK_UNHALTED.REF_TSC",
    "MEM_INST_RETIRED.ALL_LOADS",
    "MEM_INST_RETIRED.ALL_STORES",
    "MEM_LOAD_RETIRED.L3_HIT",
    "MEM_LOAD_RETIRED.L3_MISS",
    "CYCLE_ACTIVITY.CYCLES_MEM_ANY / MEM_BOUND_STALLS.LOAD",
    "PAGE_FAULTS",
    "UOPS_RETIRED.ALL"
};

// perf_event_open syscall wrapper
static long perf_event_open_sys(struct perf_event_attr *hw_event,
                                pid_t pid, int cpu, int group_fd,
                                unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// Classify CPU as P-core or E-core
static int is_pcore(int cpu) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/topology/core_cpus_list", cpu);
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    char buf[256];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 1; }
    fclose(f);
    int first = atoi(buf);
    return (first < 8);  
}

// cpu_core for P-cores, cpu_atom for E-cores
static int get_pmu_type(int pcore) {
    const char *pmu_name = pcore ? "cpu_core" : "cpu_atom";
    char path[256];
    snprintf(path, sizeof(path), "/sys/devices/%s/type", pmu_name);
    FILE *f = fopen(path, "r");
    if (!f) {
        return pcore ? 4 : 10; 
    }
    int type;
    if (fscanf(f, "%d", &type) != 1) {
        fclose(f);
        return pcore ? 4 : 10;
    }
    fclose(f);
    return type;
}

// Setup perf_event_attr for each logical event
static void setup_event_attr(int pcore, int pmu_type,
                             perf_event_id_t ev, struct perf_event_attr *attr)
{
    memset(attr, 0, sizeof(*attr));
    attr->size = sizeof(*attr);
    attr->disabled = 1;
    attr->exclude_kernel = 0;   // Include kernel
    attr->exclude_hv = 1;
    attr->read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
                        PERF_FORMAT_TOTAL_TIME_RUNNING;

    // page faults
    if (ev == MEV_PAGE_FAULTS) {
        attr->type = PERF_TYPE_SOFTWARE;
        attr->config = PERF_COUNT_SW_PAGE_FAULTS;
        return;
    }

    attr->type = pmu_type;

    if (pcore) {
        // ========== P-CORE (cpu_core) ENCODINGS ==========
        switch (ev) {
        case MEV_INST_RETIRED:
            // INST_RETIRED.ANY[CORE]: event=0xC0, umask=0x00
            attr->config = 0xC0 | (0x00ULL << 8);
            break;

        case MEV_CORE_CYCLES:
            // CPU_CLK_UNHALTED.THREAD[CORE]: event=0x3C, umask=0x00
            attr->config = 0x3C | (0x00ULL << 8);
            break;

        case MEV_REF_CYCLES:
            // CPU_CLK_UNHALTED.REF_TSC[CORE]: event=0x3C, umask=0x03
            // (unaffected by frequency scaling)
            attr->config = 0x3C | (0x03ULL << 8);
            break;

        case MEV_MEM_LOADS:
            // MEM_INST_RETIRED.ALL_LOADS[CORE]: event=0xD0, umask=0x81
            attr->config = 0xD0 | (0x81ULL << 8);
            break;

        case MEV_MEM_STORES:
            // MEM_INST_RETIRED.ALL_STORES[CORE]: event=0xD0, umask=0x82
            attr->config = 0xD0 | (0x82ULL << 8);
            break;

        case MEV_L3_LOAD_HIT:
            // MEM_LOAD_RETIRED.L3_HIT[CORE]: event=0xD1, umask=0x04
            attr->config = 0xD1 | (0x04ULL << 8);
            break;

        case MEV_L3_LOAD_MISS:
            // MEM_LOAD_RETIRED.L3_MISS[CORE]: event=0xD1, umask=0x20
            attr->config = 0xD1 | (0x20ULL << 8);
            break;

        case MEV_MEM_STALL_CYCLES:
            // CYCLE_ACTIVITY.CYCLES_MEM_ANY[CORE]:
            // event=0xA3, umask=0x10, cmask=0x10
            attr->config = 0xA3 | (0x10ULL << 8) | (0x10ULL << 24);
            break;

        case MEV_UOPS_RETIRED:
            // P-core unsupported
            attr->type = 0;
            break;

        default:
            attr->type = 0;
            break;
        }
    } else {
        // ========== E-CORE (cpu_atom) ENCODINGS ==========
        switch (ev) {
        case MEV_INST_RETIRED:
            // INST_RETIRED.ANY[ATOM]: event=0xC0, umask=0x00
            attr->config = 0xC0 | (0x00ULL << 8);
            break;

        case MEV_CORE_CYCLES:
            // CPU_CLK_UNHALTED.THREAD[ATOM]: event=0x3C, umask=0x00
            attr->config = 0x3C | (0x00ULL << 8);
            break;

        case MEV_REF_CYCLES:
            // CPU_CLK_UNHALTED.REF_TSC[ATOM]: event=0x3C, umask=0x03
            attr->config = 0x3C | (0x03ULL << 8);
            break;

        case MEV_MEM_LOADS:
            // MEM_INST_RETIRED.ALL_LOADS[ATOM]: event=0xD0, umask=0x81
            // if unsupported on Atom set attr->type = 0)
            attr->config = 0xD0 | (0x81ULL << 8);
            break;

        case MEV_MEM_STORES:
            // MEM_INST_RETIRED.ALL_STORES[ATOM]: event=0xD0, umask=0x82
            // if unsupported on Atom set attr->type = 0)
            attr->config = 0xD0 | (0x82ULL << 8);
            break;

        case MEV_L3_LOAD_HIT:
        case MEV_L3_LOAD_MISS:
            
            attr->type = 0;
            break;

        case MEV_MEM_STALL_CYCLES:
            // MEM_BOUND_STALLS.LOAD[ATOM]
            // event=0x34, umask=0x07
            attr->config = 0x34 | (0x07ULL << 8);
            break;

        case MEV_UOPS_RETIRED:
            // UOPS_RETIRED.ALL[ATOM]: event=0xC2, umask=0x00
            attr->config = 0xC2 | (0x00ULL << 8);
            break;

        default:
            attr->type = 0;
            break;
        }
    }
}

// ========== API IMPLEMENTATION ==========

int perf_monitor_open(int cpu, perf_monitor_t *mon)
{
    if (!mon) return -1;

    mon->cpu = cpu;
    mon->pcore = is_pcore(cpu);
    mon->pmu_type = get_pmu_type(mon->pcore);

    for (int i = 0; i < MEV_NUM_EVENTS; i++)
        mon->fds[i] = -1;

    // Pin current thread to this CPU
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        perror("perf_monitor_open: sched_setaffinity");
    }

    struct perf_event_attr attr;

    for (int i = 0; i < MEV_NUM_EVENTS; i++) {
        setup_event_attr(mon->pcore, mon->pmu_type, (perf_event_id_t)i, &attr);

        if (attr.type == 0) {
            // If event unsupported on this core type
            mon->fds[i] = -1;
            continue;
        }

        int fd = perf_event_open_sys(&attr, 0, cpu, -1, 0);
        if (fd < 0) {
            fprintf(stderr,
                    "perf_monitor_open: failed to open %s on cpu %d (%s): %s\n",
                    event_names[i], cpu, mon->pcore ? "P-core" : "E-core", strerror(errno));
            mon->fds[i] = -1;
        } else {
            mon->fds[i] = fd;
        }
    }

    return 0;
}

int perf_monitor_start(perf_monitor_t *mon)
{
    if (!mon) return -1;
    for (int i = 0; i < MEV_NUM_EVENTS; i++) {
        if (mon->fds[i] >= 0) {
            if (ioctl(mon->fds[i], PERF_EVENT_IOC_RESET, 0) < 0)
                return -1;
            if (ioctl(mon->fds[i], PERF_EVENT_IOC_ENABLE, 0) < 0)
                return -1;
        }
    }
    return 0;
}

int perf_monitor_stop_and_read(perf_monitor_t *mon, uint64_t values[MEV_NUM_EVENTS])
{
    if (!mon || !values) return -1;

    for (int i = 0; i < MEV_NUM_EVENTS; i++) {
        values[i] = 0;
    }

    for (int i = 0; i < MEV_NUM_EVENTS; i++) {
        if (mon->fds[i] >= 0) {
            ioctl(mon->fds[i], PERF_EVENT_IOC_DISABLE, 0);

            struct {
                uint64_t value;
                uint64_t time_enabled;
                uint64_t time_running;
            } data;

            ssize_t n = read(mon->fds[i], &data, sizeof(data));
            if (n == sizeof(data)) {
                values[i] = data.value;
            }
        }
    }

    return 0;
}

void perf_monitor_close(perf_monitor_t *mon)
{
    if (!mon) return;
    for (int i = 0; i < MEV_NUM_EVENTS; i++) {
        if (mon->fds[i] >= 0) {
            close(mon->fds[i]);
            mon->fds[i] = -1;
        }
    }
}