#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/sched.h>
#include "perf_backend.h"
#include "monitor.h"

/* --- Constants & Macros --- */
#define CORESET "0-15"
#define SOCKET_PATH "/tmp/scheduler_socket"
#define MONITOR_RESAMPLE_INTERVAL_MILLISECONDS 100 

#define MONITOR_PRINTF(fmt, ...) \
    printf("\033[32m[MONITOR]\033[0m: " fmt, ##__VA_ARGS__);

#define MONITOR_PERROR(fmt, ...) \
    fprintf(stderr, "\033[31m[MONITOR ERROR]\033[0m: " fmt, ##__VA_ARGS__);

/* --- Enums --- */
typedef enum {
    TELEMETRY_PROCESS = 0,   // (sum all threads)
    TELEMETRY_SPLIT_PE = 1,  // compute separate P-only and E-only totals/ratios
    TELEMETRY_MAIN_ONLY = 2  // only main thread
} TelemetryMode;

typedef enum { 
    FORCE_NONE = 0, 
    FORCE_P = 1, 
    FORCE_E = 2 
} ForceMode;

enum {
    MON_INST_RETIRED = 0,
    MON_CACHE_MISSES,
    MON_CORE_CYCLES,
    MON_MEM_RETIRED,
    MON_PAGE_FAULTS,
    MON_MEM_STALL_CYCLES,
    MON_UOPS_RETIRED,
    MON_NUM_EVENTS
};

/* --- Data Structures --- */
typedef struct {
    pid_t tid;
    int active;

    int last_cpu;               // last observed CPU
    int last_pcore;             // last observed core type (1=P, 0=E)
    uint32_t cpu_bitmask;

    perf_monitor_t mon;
    int mon_initialized;

    uint64_t prev[MEV_NUM_EVENTS];
    uint64_t curr[MEV_NUM_EVENTS];

    // for actual storage IO
    int io_initialized;
    ProcessIOStats prev_io;
    ProcessIOStats curr_io;
} ThreadData;

/* --- Global State --- */
static TelemetryMode g_mode = TELEMETRY_PROCESS;
static pid_t g_main_tid = 0;

static __thread int tl_disable_wrap = 0;
static ThreadData thread_data[MAX_THREADS];
static int thread_count = 0;
static pid_t target_pid = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int results_output = 0;

static ProcessIOStats initial_io, final_io;
static struct timespec start_time;
static cpu_set_t global_cpuset;

static double g_prev_exec_time_ms = -1.0;
static int g_training_mode = 0;
static ForceMode g_force_mode = FORCE_NONE;

static cpu_set_t g_pset;
static cpu_set_t g_eset;
static cpu_set_t g_forced_set;
static int g_forced_set_ready = 0;

static unsigned long g_window_idx = 0;
static int g_warmup_windows = 0;

static FILE *g_dataset_fp = NULL;
static char g_run_id[128] = {0};
static char g_workload_name[128] = {0};
static char g_dataset_path[256] = {0};

/* --- Function Pointers  --- */
static int (*real_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = NULL;
static int (*real_clone)(int (*)(void *), void *, int, void *, ...) = NULL;
static void (*real_pthread_exit)(void *) = NULL;
static int (*real_pthread_join)(pthread_t, void **) = NULL;

/* --- Forward Declarations for compilation  errors--- */
static int find_thread_index(pid_t tid);
static int alloc_thread_slot(pid_t tid);
static int open_or_reopen_thread_perf(ThreadData *td, int cpu_now, int pcore_now);
static void output_results(void);
static void *thread_wrapper(void *arg);
static ForceMode parse_force_mode(const char *s);
static void build_p_e_sets_from_global_cpuset(void);
static int is_cpuset_empty(const cpu_set_t *set);
static void training_apply_affinity(pid_t tid, const cpu_set_t *set, const char *tag);



// detect if a CPU is P-core or E-core via sysfs
static int detect_pcore_sysfs(int cpu) {
    char path[128];
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/topology/core_type", cpu);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        // if sysfs not available
        return (cpu < 8) ? 1 : 0;
    }

    int core_type = 0;
    if (fscanf(fp, "%d", &core_type) != 1) {
        fclose(fp);
        return (cpu < 8) ? 1 : 0;
    }
    fclose(fp);

    // Common convention: performance=0, efficiency=1
    if (core_type == 1) return 1;
    if (core_type == 2) return 0;

    // Unknown type -> fallback
    return (cpu < 8) ? 1 : 0;
}

// Initialize global_cpuset from CORESET
static void init_global_cpuset() {
    CPU_ZERO(&global_cpuset);
    if (!CORESET || strlen(CORESET) == 0) {
        MONITOR_PERROR("CORESET is not defined or empty\n");
        exit(1);
    }
    char *copy = strdup(CORESET);
    char *token = strtok(copy, ",");
    int core_count = 0;
    while (token) {
        if (strchr(token, '-')) {
            int start, end;
            if (sscanf(token, "%d-%d", &start, &end) == 2) {
                if (start < 0 || end >= 16 || start > end) { // Limit to 16 CPUs
                    MONITOR_PERROR("Invalid CORESET range: %s\n", token);
                    free(copy);
                    exit(1);
                }
                for (int i = start; i <= end; i++) {
                    CPU_SET(i, &global_cpuset);
                    core_count++;
                }
            }
        } else {
            int cpu = atoi(token);
            if (cpu < 0 || cpu >= 16) { // Limit to 16 CPUs
                MONITOR_PERROR("Invalid CORESET CPU: %s\n", token);
                free(copy);
                exit(1);
            }
            CPU_SET(cpu, &global_cpuset);
            core_count++;
        }
        token = strtok(NULL, ",");
    }
    free(copy);
    if (core_count == 0) {
        MONITOR_PERROR("No valid cores in CORESET %s\n", CORESET);
        exit(1);
    }
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Initialized global_cpuset for CORESET=%s, core_count=%d\n", CORESET, core_count);
    #endif
}

// Set affinity for a PID or TID
static void set_affinity(pid_t pid, const char *coreset) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    if (!coreset || strlen(coreset) == 0) {
        MONITOR_PERROR("CORESET is not defined or empty\n");
        exit(1);
    }
    char *copy = strdup(coreset);
    char *token = strtok(copy, ",");
    while (token) {
        if (strchr(token, '-')) {
            int start, end;
            if (sscanf(token, "%d-%d", &start, &end) == 2) {
                if (start < 0 || end >= 16 || start > end) { // Limit to 32 CPUs
                    MONITOR_PERROR("Invalid CORESET range: %s\n", token);
                    free(copy);
                    exit(1);
                }
                for (int i = start; i <= end; i++) {
                    CPU_SET(i, &cpuset);
                }
            }
        } else {
            int cpu = atoi(token);
            if (cpu < 0 || cpu >= 16) { // Limit to 32 CPUs
                MONITOR_PERROR("Invalid CORESET CPU: %s\n", token);
                free(copy);
                exit(1);
            }
            CPU_SET(cpu, &cpuset);
        }
        token = strtok(NULL, ",");
    }
    free(copy);

    if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset) == -1) {
        MONITOR_PERROR("Failed to set affinity for PID/TID %d: %s\n", pid, strerror(errno));
        return;
    }
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Pinned PID/TID %d to coreset %s\n", pid, coreset);
    #endif
}

static int get_thread_io_stats(pid_t pid, pid_t tid, ProcessIOStats *stats) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/io", pid, tid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    memset(stats, 0, sizeof(*stats));
    char line[128];

    while (fgets(line, sizeof(line), fp)) {
        sscanf(line, "rchar: %llu", &stats->rchar);
        sscanf(line, "wchar: %llu", &stats->wchar);
        sscanf(line, "syscr: %llu", &stats->syscr);
        sscanf(line, "syscw: %llu", &stats->syscw);
        sscanf(line, "read_bytes: %llu", &stats->read_bytes);
        sscanf(line, "write_bytes: %llu", &stats->write_bytes);
    }
    fclose(fp);
    return 0;
}

// Get process I/O stats
static int get_process_io_stats(pid_t pid, ProcessIOStats *stats) {
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Getting process I/O stats for PID %d\n", pid);
    #endif
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/io", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    memset(stats, 0, sizeof(ProcessIOStats));
    char line[128];
    while (fgets(line, sizeof(line), fp)) {
        sscanf(line, "rchar: %llu", &stats->rchar);
        sscanf(line, "wchar: %llu", &stats->wchar);
        sscanf(line, "syscr: %llu", &stats->syscr);
        sscanf(line, "syscw: %llu", &stats->syscw);
        sscanf(line, "read_bytes: %llu", &stats->read_bytes);
        sscanf(line, "write_bytes: %llu", &stats->write_bytes);
    }
    fclose(fp);
    return 0;
}

// Get current CPU for a thread by reading /proc/<pid>/task/<tid>/stat
static int get_thread_cpu(pid_t tid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/stat", target_pid, tid);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        MONITOR_PERROR("Failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }
    char line[256];
    if (!fgets(line, sizeof(line), fp)) {
        MONITOR_PERROR("Failed to read %s: %s\n", path, strerror(errno));
        fclose(fp);
        return -1;
    }
    fclose(fp);
    // Field 39 in /proc/<pid>/task/<tid>/stat is the CPU number
    char *field = line;
    for (int i = 1; i < 39; i++) {
        field = strchr(field, ' ');
        if (!field) return -1;
        field++;
    }
    int cpu;
    if (sscanf(field, "%d", &cpu) != 1) {
        MONITOR_PERROR("Failed to parse CPU from %s\n", path);
        return -1;
    }
    if (cpu < 0 || cpu >= 16 || !CPU_ISSET(cpu, &global_cpuset)) {
        MONITOR_PERROR("Thread %d: Invalid CPU %d\n", tid, cpu);
        return -1;
    }
#ifndef QUIET_MONITOR
    MONITOR_PRINTF("Thread %d is on CPU %d\n", tid, cpu);
#endif
    return cpu;
}

// Calculate performance ratios
static void calculate_ratios(long long *total_values, ProcessIOStats *io_delta, PerformanceRatios *ratios) {
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Calculating performance ratios\n");
    #endif
    long long inst_retired = total_values[0];
    long long cache_misses = total_values[1];
    long long core_cycles = total_values[2];
    long long mem_retired = total_values[3];
    long long faults = total_values[4];
    long long mem_stall_cycles = total_values[5];
    long long uops_retired = total_values[6];

    ratios->IPC = core_cycles ? (double)inst_retired / core_cycles : 0.0;
    ratios->Cache_Miss_Ratio = mem_retired ? (double)cache_misses / mem_retired : 0.0;
    ratios->Uop_per_Cycle = core_cycles ? (double)uops_retired / core_cycles : 0.0;
    ratios->MemStallCycle_per_Mem_Inst = mem_retired ? (double)mem_stall_cycles / mem_retired : 0.0;
    ratios->MemStallCycle_per_Inst = inst_retired ? (double)mem_stall_cycles / inst_retired : 0.0;
    ratios->Fault_Rate_per_mem_instr = mem_retired ? (double)faults / mem_retired : 0.0;
    ratios->RChar_per_Cycle = core_cycles ? (double)io_delta->rchar / core_cycles : 0.0;
    ratios->WChar_per_Cycle = core_cycles ? (double)io_delta->wchar / core_cycles : 0.0;
    ratios->RBytes_per_Cycle = core_cycles ? (double)io_delta->read_bytes / core_cycles : 0.0;
    ratios->WBytes_per_Cycle = core_cycles ? (double)io_delta->write_bytes / core_cycles : 0.0;
}

// Send data to scheduler
static void send_to_scheduler(const MonitorData *data, int startup_flag) {
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Sending %s to scheduler\n", startup_flag ? "startup notification" : "data");
    #endif
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        MONITOR_PERROR("socket: %s\n", strerror(errno));
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        MONITOR_PERROR("connect: %s\n", strerror(errno));
        close(sock);
        return;
    }
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Connected to scheduler\n");
    #endif

    pid_t pid = getpid();
    ssize_t bytes_written;
    bytes_written = write(sock, &pid, sizeof(pid));
    if (bytes_written != sizeof(pid)) {
        MONITOR_PERROR("Failed to write PID: %s\n", strerror(errno));
        close(sock);
        return;
    }
    bytes_written = write(sock, &startup_flag, sizeof(int));
    if (bytes_written != sizeof(int)) {
        MONITOR_PERROR("Failed to write startup_flag: %s\n", strerror(errno));
        close(sock);
        return;
    }
    bytes_written = write(sock, data, sizeof(MonitorData));
    if (bytes_written != sizeof(MonitorData)) {
        MONITOR_PERROR("Failed to write MonitorData: %s\n", strerror(errno));
        close(sock);
        return;
    }

    close(sock);
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Sent %s to scheduler\n", startup_flag ? "startup notification" : "data");
    #endif
    if (!startup_flag) {
        #ifndef QUIET_MONITOR
        MONITOR_PRINTF("Total threads (hw_thread_count): %d\n", data->hw_thread_count);
        MONITOR_PRINTF("P-Threads (pthread_count): %d\n", data->pthread_count);
        MONITOR_PRINTF("P-Cores: %d\n", data->pcore_count);
        MONITOR_PRINTF("E-Cores: %d\n", data->ecore_count);
        #endif
    }
}

static void output_results(void) {
#ifndef QUIET_MONITOR
    MONITOR_PRINTF("Outputting results\n");
#endif
    pthread_mutex_lock(&mutex);

    g_window_idx++;

    if (g_training_mode && g_forced_set_ready) {
        // re pin every active thread each window.
        for (int i = 0; i < thread_count; i++) {
            if (!thread_data[i].active) continue;
            training_apply_affinity(thread_data[i].tid, &g_forced_set, "repin/window");
        }
    }

    long long total_values[MON_NUM_EVENTS] = {0};

    long long total_values_p[MON_NUM_EVENTS] = {0};
    long long total_values_e[MON_NUM_EVENTS] = {0};
    PerformanceRatios ratios_p = {0};
    PerformanceRatios ratios_e = {0};
    ProcessIOStats io_p_delta = {0};
    ProcessIOStats io_e_delta = {0};

    int hw_thread_count = 0;
    int pthread_count_local = 0;   // threads currently on P-cores
    int pcore_count = 0;
    int ecore_count = 0;
    int total_cores = 0;

    uint32_t seen_pcore_mask = 0;
    uint32_t seen_ecore_mask = 0;

    for (int i = 0; i < thread_count; i++) {
        if (!thread_data[i].active) continue;

        pid_t tid = thread_data[i].tid;

        int cpu = get_thread_cpu(tid);
        if (cpu < 0) {
            // close perf fds if open and mark inactive
            if (thread_data[i].mon_initialized) {
                perf_monitor_close(&thread_data[i].mon);
                thread_data[i].mon_initialized = 0;
            }
            thread_data[i].active = 0;
            thread_data[i].io_initialized = 0;
            continue;
        }

        hw_thread_count++;
        int pcore_now = detect_pcore_sysfs(cpu);
        // track unique cores used in this window
        if (pcore_now) {
            pthread_count_local++;
            if (!(seen_pcore_mask & (1U << cpu))) {
                seen_pcore_mask |= (1U << cpu);
                pcore_count++;
            }
        } else {
            if (!(seen_ecore_mask & (1U << cpu))) {
                seen_ecore_mask |= (1U << cpu);
                ecore_count++;
            }
        }
        
        // get io for storage 
        ProcessIOStats tio;
        if (get_thread_io_stats(target_pid, tid, &tio) == 0) {
            if (!thread_data[i].io_initialized) {
                thread_data[i].prev_io = tio;
                thread_data[i].io_initialized = 1;
            } else {
                ProcessIOStats d = {
                    .rchar       = tio.rchar       - thread_data[i].prev_io.rchar,
                    .wchar       = tio.wchar       - thread_data[i].prev_io.wchar,
                    .syscr       = tio.syscr       - thread_data[i].prev_io.syscr,
                    .syscw       = tio.syscw       - thread_data[i].prev_io.syscw,
                    .read_bytes  = tio.read_bytes  - thread_data[i].prev_io.read_bytes,
                    .write_bytes = tio.write_bytes - thread_data[i].prev_io.write_bytes
                };
                thread_data[i].prev_io = tio;

                ProcessIOStats *dstio = pcore_now ? &io_p_delta : &io_e_delta;
                dstio->rchar       += d.rchar;
                dstio->wchar       += d.wchar;
                dstio->syscr       += d.syscr;
                dstio->syscw       += d.syscw;
                dstio->read_bytes  += d.read_bytes;
                dstio->write_bytes += d.write_bytes;
            }
        } else {
             //skip if per thread i/o failed
            thread_data[i].io_initialized = 0;
        }
       
#ifdef MONITOR_SPLIT_DEBUG
        MONITOR_PRINTF("[Placement] tid=%d cpu=%d class=%s\n",
                       (int)tid, cpu, pcore_now ? "P" : "E");
#endif
        // reopen if not initialized or core type changed (used for migration p-core to e-core and opposite)
        if (!thread_data[i].mon_initialized || thread_data[i].last_pcore != pcore_now) {
            open_or_reopen_thread_perf(&thread_data[i], cpu, pcore_now);
            // skip this window after reopen to avoid weird deltas
            continue;
        }

        if (perf_monitor_read(&thread_data[i].mon, thread_data[i].curr) != 0) {
            continue;
        }

        uint64_t delta[MEV_NUM_EVENTS];
        for (int e = 0; e < MEV_NUM_EVENTS; e++) {
            delta[e] = thread_data[i].curr[e] - thread_data[i].prev[e];
        }
        memcpy(thread_data[i].prev, thread_data[i].curr, sizeof(thread_data[i].prev));

        uint64_t inst_retired     = delta[MEV_INST_RETIRED];
        uint64_t core_cycles      = delta[MEV_CORE_CYCLES];
        uint64_t mem_retired      = delta[MEV_MEM_LOADS] + delta[MEV_MEM_STORES];
        uint64_t mem_stall_cycles = delta[MEV_MEM_STALL_CYCLES];
        uint64_t page_faults      = delta[MEV_PAGE_FAULTS];
        uint64_t uops_retired     = delta[MEV_UOPS_RETIRED];

        // L3 load misses for P-cores, LLC load misses for E-cores:
        uint64_t cache_misses = pcore_now ? delta[MEV_L3_LOAD_MISS] : delta[MEV_CACHE_LOAD_MISS];

        total_values[MON_INST_RETIRED]     += (long long)inst_retired;
        total_values[MON_CACHE_MISSES]     += (long long)cache_misses;
        total_values[MON_CORE_CYCLES]      += (long long)core_cycles;
        total_values[MON_MEM_RETIRED]      += (long long)mem_retired;
        total_values[MON_PAGE_FAULTS]      += (long long)page_faults;
        total_values[MON_MEM_STALL_CYCLES] += (long long)mem_stall_cycles;
        total_values[MON_UOPS_RETIRED]     += (long long)uops_retired;
        
        // second mode 
        long long *dst = pcore_now ? total_values_p : total_values_e;

        dst[MON_INST_RETIRED]     += (long long)inst_retired;
        dst[MON_CACHE_MISSES]     += (long long)cache_misses;
        dst[MON_CORE_CYCLES]      += (long long)core_cycles;
        dst[MON_MEM_RETIRED]      += (long long)mem_retired;
        dst[MON_PAGE_FAULTS]      += (long long)page_faults;
        dst[MON_MEM_STALL_CYCLES] += (long long)mem_stall_cycles;
        dst[MON_UOPS_RETIRED]     += (long long)uops_retired;
    }

    total_cores = pcore_count + ecore_count;

    // Fill MonitorData and send
    MonitorData data = (MonitorData){0};
    data.thread_count    = thread_count;
    data.hw_thread_count = hw_thread_count;
    data.pthread_count   = pthread_count_local;
    data.pcore_count     = pcore_count;
    data.ecore_count     = ecore_count;
    data.total_cores     = total_cores;

    memcpy(data.total_values, total_values, sizeof(total_values));

    data.io_delta = (ProcessIOStats){
        final_io.rchar       - initial_io.rchar,
        final_io.wchar       - initial_io.wchar,
        final_io.syscr       - initial_io.syscr,
        final_io.syscw       - initial_io.syscw,
        final_io.read_bytes  - initial_io.read_bytes,
        final_io.write_bytes - initial_io.write_bytes
    };
    memcpy(&initial_io, &final_io, sizeof(ProcessIOStats));

    calculate_ratios(total_values, &data.io_delta, &data.ratios);
    calculate_ratios(total_values_p, &io_p_delta, &ratios_p);
    calculate_ratios(total_values_e, &io_e_delta, &ratios_e);

    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    data.exec_time_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e6;

    double dt_ms = 0.0;
    if (g_prev_exec_time_ms < 0.0) dt_ms = 0.0;   // first window
    else dt_ms = data.exec_time_ms - g_prev_exec_time_ms;
    g_prev_exec_time_ms = data.exec_time_ms;
    
    pthread_mutex_unlock(&mutex);
    double d_inst   = (double)total_values[MON_INST_RETIRED];
    double d_cycles = (double)total_values[MON_CORE_CYCLES];
    double CPI = d_inst > 0.0 ? (d_cycles / d_inst) : 0.0;

    // dataset logging (training mode only)
    if (g_training_mode && g_dataset_fp) {
        if ((int)g_window_idx > g_warmup_windows) {
            const char *force_str =
                (g_force_mode == FORCE_P ? "P" : (g_force_mode == FORCE_E ? "E" : "NONE"));
            double inst_per_ms   = (dt_ms > 0.0) ? (d_inst / dt_ms) : 0.0;
            double cycles_per_ms = (dt_ms > 0.0) ? (d_cycles / dt_ms) : 0.0;
            
            // new dataset for pcore vs ecore
            fprintf(g_dataset_fp,
              "%s,%s,%s,%lu,%.3f,%.3f,"
              "%d,%d,%d,%d,"
                    
              "%lld,%lld,%lld,%lld,%lld,%lld,%lld,"
              "%lld,%lld,%lld,%lld,%lld,%lld,%lld,"
              "%lld,%lld,%lld,%lld,%lld,%lld,%lld,"
                    
              "%llu,%llu,%llu,%llu,%llu,%llu,"
              "%llu,%llu,%llu,%llu,%llu,%llu,"
                    
              "%.10f,%.10f,"
                    
              "%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,"
                    
              "%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,"
              "%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f,%.8f\n",
                    
              g_run_id, g_workload_name, force_str, g_window_idx, data.exec_time_ms, dt_ms,
              data.hw_thread_count, data.pthread_count, data.pcore_count, data.ecore_count,
                    
              total_values[MON_INST_RETIRED],
              total_values[MON_CORE_CYCLES],
              total_values[MON_MEM_RETIRED],
              total_values[MON_CACHE_MISSES],
              total_values[MON_PAGE_FAULTS],
              total_values[MON_MEM_STALL_CYCLES],
              total_values[MON_UOPS_RETIRED],
                    
              total_values_p[MON_INST_RETIRED],
              total_values_p[MON_CORE_CYCLES],
              total_values_p[MON_MEM_RETIRED],
              total_values_p[MON_CACHE_MISSES],
              total_values_p[MON_PAGE_FAULTS],
              total_values_p[MON_MEM_STALL_CYCLES],
              total_values_p[MON_UOPS_RETIRED],
                    
              total_values_e[MON_INST_RETIRED],
              total_values_e[MON_CORE_CYCLES],
              total_values_e[MON_MEM_RETIRED],
              total_values_e[MON_CACHE_MISSES],
              total_values_e[MON_PAGE_FAULTS],
              total_values_e[MON_MEM_STALL_CYCLES],
              total_values_e[MON_UOPS_RETIRED],
                    
              io_p_delta.rchar, io_p_delta.wchar, io_p_delta.syscr, io_p_delta.syscw, io_p_delta.read_bytes, io_p_delta.write_bytes,
              io_e_delta.rchar, io_e_delta.wchar, io_e_delta.syscr, io_e_delta.syscw, io_e_delta.read_bytes, io_e_delta.write_bytes,
                    
              inst_per_ms, cycles_per_ms,
                    
              data.ratios.IPC,
              CPI,
              data.ratios.Cache_Miss_Ratio,
              data.ratios.Uop_per_Cycle,
              data.ratios.MemStallCycle_per_Mem_Inst,
              data.ratios.MemStallCycle_per_Inst,
              data.ratios.Fault_Rate_per_mem_instr,
              data.ratios.RChar_per_Cycle,
              data.ratios.WChar_per_Cycle,
              data.ratios.RBytes_per_Cycle,
              data.ratios.WBytes_per_Cycle,
                    
              ratios_p.IPC,
              ratios_p.Cache_Miss_Ratio,
              ratios_p.Uop_per_Cycle,
              ratios_p.MemStallCycle_per_Mem_Inst,
              ratios_p.MemStallCycle_per_Inst,
              ratios_p.Fault_Rate_per_mem_instr,
              ratios_p.RChar_per_Cycle,
              ratios_p.WChar_per_Cycle,
              ratios_p.RBytes_per_Cycle,
              ratios_p.WBytes_per_Cycle,
                    
              ratios_e.IPC,
              ratios_e.Cache_Miss_Ratio,
              ratios_e.Uop_per_Cycle,
              ratios_e.MemStallCycle_per_Mem_Inst,
              ratios_e.MemStallCycle_per_Inst,
              ratios_e.Fault_Rate_per_mem_instr,
              ratios_e.RChar_per_Cycle,
              ratios_e.WChar_per_Cycle,
              ratios_e.RBytes_per_Cycle,
              ratios_e.WBytes_per_Cycle
            ); 
            fflush(g_dataset_fp);
        }
    }
    
  #ifndef QUIET_MONITOR
    // Debug print for features
    MONITOR_PRINTF("Feature 0 (P-Threads): %f\n", (double)pthread_count_local);
    MONITOR_PRINTF("Feature 1 (P-Cores): %f\n", (double)pcore_count);
    MONITOR_PRINTF("Feature 2 (E-Cores): %f\n", (double)ecore_count);
    MONITOR_PRINTF("Feature 3 (IPC): %f\n", data.ratios.IPC);
    MONITOR_PRINTF("Feature 4 (Cache_Miss_Ratio): %f\n", data.ratios.Cache_Miss_Ratio);
    MONITOR_PRINTF("Feature 5 (Uop_per_Cycle): %f\n", data.ratios.Uop_per_Cycle);
    MONITOR_PRINTF("Feature 6 (MemStallCycle_per_Mem_Inst): %f\n", data.ratios.MemStallCycle_per_Mem_Inst);
    MONITOR_PRINTF("Feature 7 (MemStallCycle_per_Inst): %f\n", data.ratios.MemStallCycle_per_Inst);
    MONITOR_PRINTF("Feature 8 (Fault_Rate_per_mem_instr): %f\n", data.ratios.Fault_Rate_per_mem_instr);
    MONITOR_PRINTF("Feature 9 (RChar_per_Cycle): %f\n", data.ratios.RChar_per_Cycle);
    MONITOR_PRINTF("Feature 10 (WChar_per_Cycle): %f\n", data.ratios.WChar_per_Cycle);
    MONITOR_PRINTF("Feature 11 (RBytes_per_Cycle): %f\n", data.ratios.RBytes_per_Cycle);
    MONITOR_PRINTF("Feature 12 (WBytes_per_Cycle): %f\n", data.ratios.WBytes_per_Cycle);
#endif

#ifdef MONITOR_SPLIT_DEBUG
    MONITOR_PRINTF("P-only Ratios: IPC=%.6f CacheMissRatio=%.6f Uop/Cycle=%.6f MemStall/MemInst=%.6f MemStall/Inst=%.6f FaultRate/mem=%.6f\n",
                   ratios_p.IPC, ratios_p.Cache_Miss_Ratio, ratios_p.Uop_per_Cycle,
                   ratios_p.MemStallCycle_per_Mem_Inst, ratios_p.MemStallCycle_per_Inst,
                   ratios_p.Fault_Rate_per_mem_instr);

    MONITOR_PRINTF("E-only Ratios: IPC=%.6f CacheMissRatio=%.6f Uop/Cycle=%.6f MemStall/MemInst=%.6f MemStall/Inst=%.6f FaultRate/mem=%.6f\n",
                   ratios_e.IPC, ratios_e.Cache_Miss_Ratio, ratios_e.Uop_per_Cycle,
                   ratios_e.MemStallCycle_per_Mem_Inst, ratios_e.MemStallCycle_per_Inst,
                   ratios_e.Fault_Rate_per_mem_instr);
#endif
    send_to_scheduler(&data, 0);
}

static ForceMode parse_force_mode(const char *s) {
    if (!s || !*s) return FORCE_NONE;
    if (!strcmp(s, "P") || !strcmp(s, "p")) return FORCE_P;
    if (!strcmp(s, "E") || !strcmp(s, "e")) return FORCE_E;
    if (!strcmp(s, "NONE") || !strcmp(s, "none")) return FORCE_NONE;
    return FORCE_NONE;
}

static void build_p_e_sets_from_global_cpuset(void) {
    CPU_ZERO(&g_pset);
    CPU_ZERO(&g_eset);

    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &global_cpuset)) continue;
        int is_p = detect_pcore_sysfs(cpu);
        if (is_p) CPU_SET(cpu, &g_pset);
        else      CPU_SET(cpu, &g_eset);
    }
}

static int is_cpuset_empty(const cpu_set_t *set) {
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (CPU_ISSET(cpu, set)) return 0;
    }
    return 1;
}

static void training_apply_affinity(pid_t tid, const cpu_set_t *set, const char *tag) {
    if (sched_setaffinity(tid, sizeof(cpu_set_t), set) != 0) {
        MONITOR_PERROR("[TRAINING] sched_setaffinity(%s) failed tid=%d: %s\n",
                       tag, (int)tid, strerror(errno));
        exit(1);
    }
}

static void *thread_wrapper(void *arg) {
    void *(*start_routine)(void *) = ((void **)arg)[0];
    void *start_arg = ((void **)arg)[1];
    free(arg);

    pid_t tid = syscall(SYS_gettid);

    if (g_training_mode && g_forced_set_ready) {
        training_apply_affinity(0 /* self */, &g_forced_set, "thread_wrapper/self");
    }

    pthread_mutex_lock(&mutex);
    int idx = alloc_thread_slot(tid);
    pthread_mutex_unlock(&mutex);

    if (idx >= 0) {
        int cpu = sched_getcpu();
        if (cpu >= 0) {
            int pcore_now = detect_pcore_sysfs(cpu);
            pthread_mutex_lock(&mutex);
            thread_data[idx].cpu_bitmask = (cpu < 32) ? (1U << cpu) : 0;
            open_or_reopen_thread_perf(&thread_data[idx], cpu, pcore_now);
            pthread_mutex_unlock(&mutex);
        }
    } else {
        MONITOR_PERROR("Thread limit reached (%d)\n", MAX_THREADS);
    }

    void *ret = start_routine(start_arg);

    // cleanup on thread exit
    pthread_mutex_lock(&mutex);
    int idx2 = find_thread_index(tid);
    if (idx2 >= 0) {
        if (thread_data[idx2].mon_initialized) {
            perf_monitor_close(&thread_data[idx2].mon);
            thread_data[idx2].mon_initialized = 0;
        }
        thread_data[idx2].active = 0;
    }
    pthread_mutex_unlock(&mutex);

    return ret;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {

    if (!real_pthread_create) {
        real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
        if (!real_pthread_create) {
            MONITOR_PERROR("Failed to get real pthread_create: %s\n", dlerror());
            exit(1);
        }
    }

    if (tl_disable_wrap) {
#ifndef QUIET_MONITOR
        MONITOR_PRINTF("pthread_create bypass (monitor thread)\n");
#endif
        return real_pthread_create(thread, attr, start_routine, arg);
    }

#ifndef QUIET_MONITOR
    MONITOR_PRINTF("pthread_create called (wrapping)\n");
#endif

    void **wrapper_arg = malloc(sizeof(void *) * 2);
    if (!wrapper_arg) return ENOMEM;
    wrapper_arg[0] = (void*)start_routine;
    wrapper_arg[1] = arg;

    int ret = real_pthread_create(thread, attr, thread_wrapper, wrapper_arg);
    if (ret != 0) free(wrapper_arg);
    return ret;
}
// clone wrapper - maybe working
int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...) {
#ifndef QUIET_MONITOR
    MONITOR_PRINTF("clone called\n");
#endif
    if (!real_clone) {
        real_clone = dlsym(RTLD_NEXT, "clone");
        if (!real_clone) {
            MONITOR_PERROR("Failed to get real clone: %s\n", dlerror());
            exit(1);
        }
    }

    va_list ap;
    va_start(ap, arg);

    pid_t *ptid = NULL;
    void  *tls  = NULL;
    pid_t *ctid = NULL;

    if (flags & CLONE_PARENT_SETTID) {
        ptid = va_arg(ap, pid_t *);
    }
    if (flags & CLONE_SETTLS) {
        tls = va_arg(ap, void *);
    }
    if (flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID)) {
        ctid = va_arg(ap, pid_t *);
    }

    va_end(ap);

    int ret;

    // Now forward to real_clone with correct args
    if ((flags & CLONE_PARENT_SETTID) && (flags & CLONE_SETTLS) &&
        (flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID))) {
        ret = real_clone(fn, child_stack, flags, arg, ptid, tls, ctid);
    } else if ((flags & CLONE_PARENT_SETTID) && (flags & CLONE_SETTLS)) {
        ret = real_clone(fn, child_stack, flags, arg, ptid, tls);
    } else if ((flags & CLONE_PARENT_SETTID) &&
               (flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID))) {
        ret = real_clone(fn, child_stack, flags, arg, ptid, ctid);
    } else if ((flags & CLONE_SETTLS) &&
               (flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID))) {
        ret = real_clone(fn, child_stack, flags, arg, tls, ctid);
    } else if (flags & CLONE_PARENT_SETTID) {
        ret = real_clone(fn, child_stack, flags, arg, ptid);
    } else if (flags & CLONE_SETTLS) {
        ret = real_clone(fn, child_stack, flags, arg, tls);
    } else if (flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID)) {
        ret = real_clone(fn, child_stack, flags, arg, ctid);
    } else {
        ret = real_clone(fn, child_stack, flags, arg);
    }

    // Track clone created threads in the parent side when it is a thread
    if (ret > 0 && (flags & CLONE_THREAD)) {
        pid_t child_tid = (pid_t)ret;

        pthread_mutex_lock(&mutex);
        int idx = alloc_thread_slot(child_tid);
        pthread_mutex_unlock(&mutex);

        (void)idx;
    }

    return ret;
}

int pthread_join(pthread_t thread, void **retval) {
    if (!real_pthread_join) {
        real_pthread_join = dlsym(RTLD_NEXT, "pthread_join");
        if (!real_pthread_join) {
            MONITOR_PERROR("Failed to get real pthread_join: %s\n", dlerror());
            exit(1);
        }
    }
    return real_pthread_join(thread, retval);
}

static int find_thread_index(pid_t tid) {
    for (int i = 0; i < thread_count; i++) {
        if (thread_data[i].active && thread_data[i].tid == tid) return i;
    }
    return -1;
}

// Reuse inactive slots if possible else append.
static int alloc_thread_slot(pid_t tid) {
    for (int i = 0; i < thread_count; i++) {
        if (!thread_data[i].active) {
            memset(&thread_data[i], 0, sizeof(ThreadData));
            thread_data[i].tid = tid;
            thread_data[i].active = 1;
            thread_data[i].last_cpu = -1;
            return i;
        }
    }
    if (thread_count >= MAX_THREADS) return -1;

    int idx = thread_count++;
    memset(&thread_data[idx], 0, sizeof(ThreadData));
    thread_data[idx].tid = tid;
    thread_data[idx].active = 1;
    thread_data[idx].last_cpu = -1;
    return idx;
}

__attribute__((noreturn)) void pthread_exit(void *retval) {
#ifndef QUIET_MONITOR
    MONITOR_PRINTF("pthread_exit called\n");
#endif
    if (!real_pthread_exit) {
        real_pthread_exit = dlsym(RTLD_NEXT, "pthread_exit");
        if (!real_pthread_exit) {
            MONITOR_PERROR("Failed to get real pthread_exit: %s\n", dlerror());
            exit(1);
        }
    }
    pid_t tid = syscall(SYS_gettid);
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < thread_count; i++) {
        if (thread_data[i].tid == tid && thread_data[i].active) {
            thread_data[i].active = 0;
            thread_data[i].io_initialized = 0; // for storage io
            break;
        }
    }
    pthread_mutex_unlock(&mutex);
    real_pthread_exit(retval);
    __builtin_unreachable();
}

// Start the monitor loop
static void *start_monitor_loop(void *unused) {
    (void)unused;
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Starting monitor loop\n");
    #endif
    if (g_training_mode && g_forced_set_ready) {
        training_apply_affinity(0 /* self */, &g_forced_set, "monitor_thread/self");
    }
    // This function is used to send data to the scheduler periodically - 100ms
    // using a separate thread. It is also used to calculate delta values
    // for the initial and final I/O stats as well as the performance ratios.
    // The loop runs until the process is terminated or the monitor is finalized.
    while (1) {
        // Sleep for the resample interval
        usleep(MONITOR_RESAMPLE_INTERVAL_MILLISECONDS * 1000);
        get_process_io_stats(target_pid, &final_io);
        output_results();
        // Check if the process is still running
        if (kill(target_pid, 0) == -1 && errno == ESRCH) {
            #ifndef QUIET_MONITOR
            MONITOR_PRINTF("Target process %d has terminated, exiting monitor loop\n", target_pid);
            #endif
            break;
        }
    }
    return NULL;
}

__attribute__((constructor))
void init_monitor(void) {
    g_main_tid = syscall(SYS_gettid);

    const char *m = getenv("MONITOR_MODE");
    if (m) {
        if (!strcmp(m, "process")) g_mode = TELEMETRY_PROCESS;
        else if (!strcmp(m, "split")) g_mode = TELEMETRY_SPLIT_PE;
        else if (!strcmp(m, "main")) g_mode = TELEMETRY_MAIN_ONLY;
    }
#ifndef QUIET_MONITOR
    MONITOR_PRINTF("Initializing monitor\n");
#endif
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;

    // Initialize global_cpuset from CORESET
    init_global_cpuset();
    // Training config
    g_training_mode = 0;
    g_force_mode = FORCE_NONE;
    g_window_idx = 0;

    const char *tm = getenv("TRAINING_MODE");
    if (tm && atoi(tm) == 1) g_training_mode = 1;

    g_force_mode = parse_force_mode(getenv("MONITOR_FORCE"));

    const char *ww = getenv("WARMUP_WINDOWS");
    g_warmup_windows = ww ? atoi(ww) : 0;

    const char *rid = getenv("RUN_ID");
    const char *wn  = getenv("WORKLOAD_NAME");
    if (rid) snprintf(g_run_id, sizeof(g_run_id), "%s", rid);
    else     snprintf(g_run_id, sizeof(g_run_id), "run");

    if (wn)  snprintf(g_workload_name, sizeof(g_workload_name), "%s", wn);
    else     snprintf(g_workload_name, sizeof(g_workload_name), "workload");

    const char *dp = getenv("DATASET_CSV");
    if (dp) snprintf(g_dataset_path, sizeof(g_dataset_path), "%s", dp);
    else    g_dataset_path[0] = '\0';

    build_p_e_sets_from_global_cpuset();

    if (g_training_mode && g_force_mode != FORCE_NONE) {
        CPU_ZERO(&g_forced_set);
        if (g_force_mode == FORCE_P) g_forced_set = g_pset;
        else                         g_forced_set = g_eset;

        if (is_cpuset_empty(&g_forced_set)) {
            MONITOR_PERROR("[TRAINING] Forced set is empty. Check CORESET + core_type sysfs.\n");
            exit(1);
        }
        g_forced_set_ready = 1;

#ifndef QUIET_MONITOR
        MONITOR_PRINTF("[TRAINING] mode=1 force=%s warmup_windows=%d\n",
                       (g_force_mode == FORCE_P ? "P" : "E"),
                       g_warmup_windows);
#endif



        training_apply_affinity(0, &g_forced_set, "main/self");
    } else {
        g_forced_set_ready = 0;
#ifndef QUIET_MONITOR
        MONITOR_PRINTF("[TRAINING] mode=%d force=%s\n", g_training_mode,
                       (g_force_mode == FORCE_P ? "P" : (g_force_mode == FORCE_E ? "E" : "NONE")));
#endif
    }
    if (g_training_mode && g_dataset_path[0]) {
        g_dataset_fp = fopen(g_dataset_path, "a");
        if (!g_dataset_fp) {
            MONITOR_PERROR("[TRAINING] Failed to open DATASET_CSV=%s: %s\n", g_dataset_path, strerror(errno));
            exit(1);
        }

        // Write header if file is empty
        fseek(g_dataset_fp, 0, SEEK_END);
        long sz = ftell(g_dataset_fp);
        if (sz == 0) {
            // this header will be used for training ecore vs pcore
            fprintf(g_dataset_fp,
              "run_id,workload,force,window_idx,t_ms,dt_ms,"
              "hw_threads,pcore_threads,pcore_count,ecore_count,"

              "d_inst,d_cycles,d_mem,d_cache_miss,d_pf,d_mem_stall,d_uops,"
              "d_inst_p,d_cycles_p,d_mem_p,d_cache_miss_p,d_pf_p,d_mem_stall_p,d_uops_p,"
              "d_inst_e,d_cycles_e,d_mem_e,d_cache_miss_e,d_pf_e,d_mem_stall_e,d_uops_e,"

              "rchar_p,wchar_p,syscr_p,syscw_p,read_bytes_p,write_bytes_p,"
              "rchar_e,wchar_e,syscr_e,syscw_e,read_bytes_e,write_bytes_e,"

              "inst_per_ms,cycles_per_ms,"

              "IPC,CPI,Cache_Miss_Ratio,Uop_per_Cycle,MemStall_per_Mem,MemStall_per_Inst,FaultRate_per_mem,"
              "RChar_per_Cycle,WChar_per_Cycle,RBytes_per_Cycle,WBytes_per_Cycle,"

              "IPC_p,Cache_Miss_Ratio_p,Uop_per_Cycle_p,MemStall_per_Mem_p,MemStall_per_Inst_p,FaultRate_per_mem_p,"
              "RChar_per_Cycle_p,WChar_per_Cycle_p,RBytes_per_Cycle_p,WBytes_per_Cycle_p,"

              "IPC_e,Cache_Miss_Ratio_e,Uop_per_Cycle_e,MemStall_per_Mem_e,MemStall_per_Inst_e,FaultRate_per_mem_e,"
              "RChar_per_Cycle_e,WChar_per_Cycle_e,RBytes_per_Cycle_e,WBytes_per_Cycle_e\n"
            );
            fflush(g_dataset_fp);
        }
    }

    target_pid = getpid();

    // I/O + timing baseline
    get_process_io_stats(target_pid, &initial_io);
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Pick an initial CPU for the process
    int cpu = sched_getcpu();
#ifndef QUIET_MONITOR
    MONITOR_PRINTF("Main process pinned/observed on CPU %d\n", cpu);
#endif
    if (cpu < 0 || cpu >= 32 || !CPU_ISSET(cpu, &global_cpuset)) {
        MONITOR_PERROR("Main process initial CPU %d invalid or not in CORESET %s\n",
                       cpu, CORESET);
        // you can choose to exit(1) or just continue with a default cpu=0
        cpu = 0;
    }

    // Register main thread slot
    pthread_mutex_lock(&mutex);
    if (thread_count < MAX_THREADS) {
        thread_data[thread_count].tid = syscall(SYS_gettid);
        thread_data[thread_count].active = 1;
        thread_data[thread_count].cpu_bitmask = 0;
        int t_cpu = sched_getcpu();
        if (t_cpu >= 0 && t_cpu < 32 && CPU_ISSET(t_cpu, &global_cpuset)) {
            thread_data[thread_count].cpu_bitmask = (1U << t_cpu);
        } else {
            MONITOR_PERROR("Main thread %d: Invalid CPU %d (not in CORESET %s)\n",
                           thread_data[thread_count].tid, t_cpu, CORESET);
        }
        thread_count++;
    }
    pthread_mutex_unlock(&mutex);

    // After registering main thread slot open perf for it
    pthread_mutex_lock(&mutex);
    int main_idx = find_thread_index(syscall(SYS_gettid));
    pthread_mutex_unlock(&mutex);

    if (main_idx >= 0) {
        int cpu0 = sched_getcpu();
        if (cpu0 >= 0) {
            int pcore0 = detect_pcore_sysfs(cpu0);
            pthread_mutex_lock(&mutex);
            open_or_reopen_thread_perf(&thread_data[main_idx], cpu0, pcore0);
            pthread_mutex_unlock(&mutex);
        }
    }

    // Notify scheduler of startup
    MonitorData initial_data = {0};
    send_to_scheduler(&initial_data, 1);

    // Start the monitor loop in a separate thread
    pthread_t monitor_thread;

    tl_disable_wrap = 1;
    int rc = pthread_create(&monitor_thread, NULL,
            (void *(*)(void *))start_monitor_loop, NULL);
    tl_disable_wrap = 0;

    if (rc != 0) {
        MONITOR_PERROR("Failed to create monitor thread: %s\n", strerror(rc));
        exit(1);
    }
}

static int open_or_reopen_thread_perf(ThreadData *td, int cpu_now, int pcore_now) {
    // Close old fds if open
    if (td->mon_initialized) {
        perf_monitor_close(&td->mon);
        td->mon_initialized = 0;
    }

    // Open with correct encodings for the *current* core type
    if (perf_monitor_open_thread(td->tid, cpu_now, &td->mon) != 0) {
        MONITOR_PERROR("perf_monitor_open_thread failed for tid=%d cpu=%d\n", td->tid, cpu_now);
        return -1;
    }
    if (perf_monitor_start(&td->mon) != 0) {
        MONITOR_PERROR("perf_monitor_start failed for tid=%d cpu=%d\n", td->tid, cpu_now);
        perf_monitor_close(&td->mon);
        return -1;
    }

    td->mon_initialized = 1;
    td->last_cpu = cpu_now;
    td->last_pcore = pcore_now;

    // Establish baseline
    if (perf_monitor_read(&td->mon, td->curr) == 0) {
        memcpy(td->prev, td->curr, sizeof(td->prev));
    } else {
        memset(td->prev, 0, sizeof(td->prev));
    }
    return 0;
}

__attribute__((destructor))
void finish_monitor(void) {
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < thread_count; i++) {
        if (thread_data[i].mon_initialized) {
            perf_monitor_close(&thread_data[i].mon);
            thread_data[i].mon_initialized = 0;
        }
        thread_data[i].active = 0;
    }
    pthread_mutex_unlock(&mutex);
    if (g_dataset_fp) {
        fclose(g_dataset_fp);
        g_dataset_fp = NULL;
    }
}