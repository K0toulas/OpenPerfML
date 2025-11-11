#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <papi.h>
#include <papi.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "monitor.h"

const char *events[] = {
    "INST_RETIRED:ANY_P", "perf::PERF_COUNT_HW_CACHE_MISSES", "ix86arch::UNHALTED_CORE_CYCLES",
    "MEM_INST_RETIRED:ANY", "perf::FAULTS", "CYCLE_ACTIVITY:CYCLES_MEM_ANY", "adl_grt::UOPS_RETIRED"
};

#define SOCKET_PATH "/tmp/scheduler_socket"
#define MONITOR_PRINTF(fmt, ...) \
    printf("\033[32m[MONITOR]\033[0m: " fmt, ##__VA_ARGS__);
#define MONITOR_RESAMPLE_INTERVAL_MILLISECONDS 30 // Resample interval in milliseconds 
#define MONITOR_PERROR(fmt, ...) \
    fprintf(stderr, "\033[31m[MONITOR ERROR]\033[0m: " fmt, ##__VA_ARGS__);

// #define CORESET "0-31"

typedef struct {
    int EventSet;
    pid_t tid;
    int active;
    long long initial_values[NUM_EVENTS];
    long long final_values[NUM_EVENTS];
    uint32_t cpu_bitmask;
} ThreadData;

static ThreadData thread_data[MAX_THREADS];
static int thread_count = 0;
static pid_t target_pid = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int results_output = 0;
static ProcessIOStats initial_io, final_io;
static struct timespec start_time;
static cpu_set_t global_cpuset;

// Function pointers for original functions
static int (*real_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = NULL;
static int (*real_clone)(int (*)(void *), void *, int, void *, ...) = NULL;
static void (*real_pthread_exit)(void *) = NULL;
static int (*real_pthread_join)(pthread_t, void **) = NULL;

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
                if (start < 0 || end >= 32 || start > end) { // Limit to 32 CPUs
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
            if (cpu < 0 || cpu >= 32) { // Limit to 32 CPUs
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
                if (start < 0 || end >= 32 || start > end) { // Limit to 32 CPUs
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
            if (cpu < 0 || cpu >= 32) { // Limit to 32 CPUs
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

// Handle PAPI errors
static void handle_error(const char *msg, int retval, const char *event) {
    fprintf(stderr, "%s: %s (code: %d), Event: %s\n", msg, 
            retval == PAPI_ESYS ? strerror(errno) : PAPI_strerror(retval), 
            retval, event ? event : "none");
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

// New: Get current CPU for a thread by reading /proc/<pid>/task/<tid>/stat
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
    if (cpu < 0 || cpu >= 32 || !CPU_ISSET(cpu, &global_cpuset)) {
        MONITOR_PERROR("Thread %d: Invalid CPU %d\n", tid, cpu);
        return -1;
    }
#ifndef QUIET_MONITOR
    MONITOR_PRINTF("Thread %d is on CPU %d\n", tid, cpu);
#endif
    return cpu;
}

// Setup PAPI event set
static int setup_eventset(pid_t tid, ThreadData *data) {
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Setting up event set for TID %d\n", tid);
    #endif
    int EventSet = PAPI_NULL;
    if (PAPI_create_eventset(&EventSet) != PAPI_OK) return -1;
    for (int i = 0; i < NUM_EVENTS; i++) {
        if (PAPI_add_named_event(EventSet, events[i]) != PAPI_OK) {
            handle_error("Failed to add event", PAPI_EINVAL, events[i]);
        }
    }
    if (PAPI_attach(EventSet, tid) != PAPI_OK || PAPI_start(EventSet) != PAPI_OK) {
        PAPI_destroy_eventset(&EventSet);
        return -1;
    }
    PAPI_read(EventSet, data->initial_values);
    return EventSet;
}

// Cleanup thread PAPI data
static void cleanup_thread(ThreadData *data) {
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Cleaning up thread TID %d\n", data->tid);
    #endif
    if (!data->active) return;
    PAPI_read(data->EventSet, data->final_values);
    PAPI_stop(data->EventSet, NULL);
    PAPI_destroy_eventset(&data->EventSet);
    data->active = 0;
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

// Output performance results
static void output_results(void) {
#ifndef QUIET_MONITOR
    MONITOR_PRINTF("Outputting results\n");
#endif
    pthread_mutex_lock(&mutex);
    long long total_values[NUM_EVENTS] = {0};
    uint32_t iteration_cpu_bitmask = 0;

    // Update cpu_bitmask for active threads
    for (size_t i = 0; i < thread_count; i++) {
        if (thread_data[i].active) {
            PAPI_read(thread_data[i].EventSet, thread_data[i].final_values);
            int cpu = get_thread_cpu(thread_data[i].tid);
            if (cpu >= 0) {
                if (thread_data[i].cpu_bitmask && !(thread_data[i].cpu_bitmask & (1U << cpu))) {
                    #ifndef QUIET_MONITOR
                    MONITOR_PRINTF("Thread %d switched to CPU %d\n", thread_data[i].tid, cpu);
                    #endif
                }
                thread_data[i].cpu_bitmask = (1U << cpu); // Set to current CPU only
                iteration_cpu_bitmask |= thread_data[i].cpu_bitmask;
            }
        }
        for (int j = 0; j < NUM_EVENTS; j++) {
            total_values[j] += thread_data[i].final_values[j] - thread_data[i].initial_values[j];
        }
    }

    // Count threads and cores for this iteration
    cpu_set_t used_cpuset;
    CPU_ZERO(&used_cpuset);
    for (int cpu = 0; cpu < 32; cpu++) {
        if (iteration_cpu_bitmask & (1U << cpu)) {
            CPU_SET(cpu, &used_cpuset);
        }
    }

    int pcore_count = 0, ecore_count = 0, pthread_count = 0;
    int pcore_pairs[8] = {0};
    const char *coreset = CORESET;
    for (int cpu = 0; cpu < 32; cpu++) {
        if (CPU_ISSET(cpu, &used_cpuset)) {
            if (!CPU_ISSET(cpu, &global_cpuset)) {
                MONITOR_PERROR("CPU %d used but not in CORESET %s\n", cpu, coreset);
                continue;
            }
            if (cpu < 16) {
                pthread_count++;
                int pair_idx = cpu / 2;
                pcore_pairs[pair_idx] = 1;
            } else {
                ecore_count++;
            }
        }
    }
    for (int i = 0; i < 8; i++) {
        pcore_count += pcore_pairs[i];
    }
    int total_cores = pcore_count + ecore_count;
    int hw_thread_count = pthread_count + ecore_count;


    MonitorData data = {0};
    data.thread_count = thread_count;
    data.hw_thread_count = hw_thread_count;
    data.pthread_count = pthread_count;
    data.pcore_count = pcore_count;
    data.ecore_count = ecore_count;
    data.total_cores = total_cores;
    memcpy(data.total_values, total_values, sizeof(total_values));
    data.io_delta = (ProcessIOStats){
        final_io.rchar - initial_io.rchar,
        final_io.wchar - initial_io.wchar,
        final_io.syscr - initial_io.syscr,
        final_io.syscw - initial_io.syscw,
        final_io.read_bytes - initial_io.read_bytes,
        final_io.write_bytes - final_io.write_bytes
    };
    memcpy(&initial_io, &final_io, sizeof(ProcessIOStats));
    calculate_ratios(total_values, &data.io_delta, &data.ratios);
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    data.exec_time_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e6;

    send_to_scheduler(&data, 0);

    // Log features for debugging
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Feature 0 (P-Threads): %f\n", (double)pthread_count);
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

    pthread_mutex_unlock(&mutex);
}

// Thread wrapper to set affinity and monitor
static void *thread_wrapper(void *arg) {
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Thread wrapper started\n");
    #endif
    void *(*start_routine)(void *) = ((void **)arg)[0];
    void *start_arg = ((void **)arg)[1];
    pid_t tid = syscall(SYS_gettid);

    // Set affinity for the new thread
    // set_affinity(tid, CORESET);

    pthread_mutex_lock(&mutex);
    if (thread_count < MAX_THREADS) {
        thread_data[thread_count].tid = tid;
        thread_data[thread_count].tid = tid;
        thread_data[thread_count].active = 1;
        thread_data[thread_count].cpu_bitmask = 0; // Explicitly initialize
        int cpu = sched_getcpu();
        #ifndef QUIET_MONITOR
        MONITOR_PRINTF("Thread %d: sched_getcpu returned %d\n", tid, cpu); // Debug
        #endif
        if (cpu >= 0 && cpu < 32 && CPU_ISSET(cpu, &global_cpuset)) {
            thread_data[thread_count].cpu_bitmask = (1U << cpu);
            #ifndef QUIET_MONITOR
            MONITOR_PRINTF("Thread %d assigned to CPU %d\n", tid, cpu);
            #endif
        } else {
            MONITOR_PERROR("Thread %d: Invalid CPU %d (not in CORESET %s)\n", tid, cpu, CORESET);
        }
        thread_data[thread_count].EventSet = setup_eventset(tid, &thread_data[thread_count]);
        if (thread_data[thread_count].EventSet != -1) {
            thread_count++;
        }
    } else {
        MONITOR_PERROR("Thread limit reached (%d) for monitoring\n", MAX_THREADS);
    }
    pthread_mutex_unlock(&mutex);


    void *ret = start_routine(start_arg);
    free(arg);
    return ret;
}

// Interpose pthread_create
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("pthread_create called\n");
    #endif
    if (!real_pthread_create) {
        real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
        if (!real_pthread_create) {
            MONITOR_PERROR("Failed to get real pthread_create: %s\n", dlerror());
            exit(1);
        }
    }

    void **wrapper_arg = malloc(sizeof(void *) * 2);
    wrapper_arg[0] = start_routine;
    wrapper_arg[1] = arg;
    int ret = real_pthread_create(thread, attr, thread_wrapper, wrapper_arg);
    if (ret != 0) {
        free(wrapper_arg);
    }
    return ret;
}

// Interpose clone
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

    int tid = real_clone(fn, child_stack, flags, arg);
    if (tid == 0 && (flags & CLONE_THREAD)) {
        pid_t child_tid = syscall(SYS_gettid);
        // set_affinity(child_tid, CORESET);
        pthread_mutex_lock(&mutex);
        if (thread_count < MAX_THREADS) {
            thread_data[thread_count].tid = child_tid;
            thread_data[thread_count].active = 1;
            thread_data[thread_count].cpu_bitmask = 0; // Explicitly initialize
            int cpu = sched_getcpu();
            #ifndef QUIET_MONITOR
            MONITOR_PRINTF("Thread %d: sched_getcpu returned %d\n", child_tid, cpu); // Debug
            #endif
            if (cpu >= 0 && cpu < 32 && CPU_ISSET(cpu, &global_cpuset)) {
                thread_data[thread_count].cpu_bitmask = (1U << cpu);
                #ifndef QUIET_MONITOR
                MONITOR_PRINTF("Thread %d assigned to CPU %d\n", child_tid, cpu);
                #endif
            } else {
                MONITOR_PERROR("Thread %d: Invalid CPU %d (not in CORESET %s)\n", child_tid, cpu, CORESET);
            }
            thread_data[thread_count].EventSet = setup_eventset(child_tid, &thread_data[thread_count]);
            if (thread_data[thread_count].EventSet != -1) {
                thread_count++;
            }
        } else {
            MONITOR_PERROR("Thread limit reached (%d) for monitoring\n", MAX_THREADS);
        }
        pthread_mutex_unlock(&mutex);
    }
    return tid;
}

// Interpose pthread_join
int pthread_join(pthread_t thread, void **retval) {
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("pthread_join called\n");
    #endif
    if (!real_pthread_join) {
        real_pthread_join = dlsym(RTLD_NEXT, "pthread_join");
        if (!real_pthread_join) {
            MONITOR_PERROR("Failed to get real pthread_join: %s\n", dlerror());
            exit(1);
        }
        if (!real_pthread_join) {
            MONITOR_PERROR("Failed to get real pthread_join: %s\n", dlerror());
            exit(1);
        }
    }
    int ret = real_pthread_join(thread, retval);
    if (ret == 0) {
        pthread_mutex_lock(&mutex);
        for (int i = 0; i < thread_count; i++) {
            if (thread_data[i].tid == syscall(SYS_gettid) && thread_data[i].active) {
                cleanup_thread(&thread_data[i]);
                break;
            }
        }
        pthread_mutex_unlock(&mutex);
    }
    return ret;
}

// Interpose pthread_exit
// Interpose pthread_exit
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
        if (!real_pthread_exit) {
            MONITOR_PERROR("Failed to get real pthread_exit: %s\n", dlerror());
            exit(1);
        }
    }
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < thread_count; i++) {
        if (thread_data[i].tid == syscall(SYS_gettid) && thread_data[i].active) {
            cleanup_thread(&thread_data[i]);
            break;
        }
    }
    pthread_mutex_unlock(&mutex);
    real_pthread_exit(retval);
    __builtin_unreachable();
}

// Start the monitor loop
static void start_monitor_loop(void) {
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Starting monitor loop\n");
    #endif
    // This function is used to send data to the scheduler periodically
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
}

// Initialize monitor
__attribute__((constructor))
void init_monitor(void) {
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Initializing monitor\n");
    #endif
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;

    // Initialize global_cpuset
    init_global_cpuset();

    target_pid = getpid();
    PAPI_library_init(PAPI_VER_CURRENT);
    PAPI_thread_init(NULL);
    get_process_io_stats(target_pid, &initial_io);
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    pthread_mutex_lock(&mutex);
    if (thread_count < MAX_THREADS) {
        thread_data[thread_count].tid = syscall(SYS_gettid);
        thread_data[thread_count].active = 1;
        thread_data[thread_count].cpu_bitmask = 0; // Initialize
        int cpu = sched_getcpu();
        #ifndef QUIET_MONITOR
        MONITOR_PRINTF("Main thread %d: sched_getcpu returned %d\n", thread_data[thread_count].tid, cpu); // Validate
        #endif
        if (cpu >= 0 && cpu < 32 && CPU_ISSET(cpu, &global_cpuset)) {
            thread_data[thread_count].cpu_bitmask = (1U << cpu);
            #ifndef QUIET_MONITOR
            MONITOR_PRINTF("Main thread %d assigned to CPU %d\n", thread_data[thread_count].tid, cpu);
            #endif
        } else {
            MONITOR_PERROR("Main thread %d: Invalid CPU %d (not in CORESET %s)\n", thread_data[thread_count].tid, cpu, CORESET);
        }
        thread_data[thread_count].EventSet = setup_eventset(thread_data[thread_count].tid, &thread_data[thread_count]);
        if (thread_data[thread_count].EventSet != -1) {
            thread_count++;
        }
    }
    pthread_mutex_unlock(&mutex);

    MonitorData initial_data = {0};
    send_to_scheduler(&initial_data, 1);
    // Start the monitor loop in a separate thread
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Starting monitor loop in a separate thread\n");
    #endif
    pthread_t monitor_thread;
    if (pthread_create(&monitor_thread, NULL, (void *(*)(void *))start_monitor_loop, NULL) != 0) {
        MONITOR_PERROR("Failed to create monitor thread: %s\n", strerror(errno));
        exit(1);
    }
}

// Finalize monitor
__attribute__((destructor))
void finish_monitor(void) {
    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("Finalizing monitor\n");
    #endif

    pthread_mutex_lock(&mutex);

    for (int i = 0; i < thread_count; i++) {
        if (thread_data[i].EventSet != PAPI_NULL && thread_data[i].EventSet != -1) {
            // Stop counters for this EventSet
            int retval = PAPI_stop(thread_data[i].EventSet, NULL);
            if (retval != PAPI_OK) {
                MONITOR_PERROR("PAPI_stop failed for thread %d: %s\n",
                               thread_data[i].tid, PAPI_strerror(retval));
            }

            // Clean up this EventSet
            retval = PAPI_cleanup_eventset(thread_data[i].EventSet);
            if (retval != PAPI_OK) {
                MONITOR_PERROR("PAPI_cleanup_eventset failed for thread %d: %s\n",
                               thread_data[i].tid, PAPI_strerror(retval));
            }

            retval = PAPI_destroy_eventset(&thread_data[i].EventSet);
            if (retval != PAPI_OK) {
                MONITOR_PERROR("PAPI_destroy_eventset failed for thread %d: %s\n",
                               thread_data[i].tid, PAPI_strerror(retval));
            }

            thread_data[i].EventSet = PAPI_NULL;
        }
    }

    pthread_mutex_unlock(&mutex);

    // Shut down the PAPI library
    PAPI_shutdown();

    #ifndef QUIET_MONITOR
    MONITOR_PRINTF("PAPI resources cleaned up and shut down.\n");
    MONITOR_PRINTF("End\n");
    #endif
}
