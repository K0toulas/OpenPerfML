#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <math.h>
#include <stdint.h>
#include <ctype.h>
#include "monitor.h"
#include "cJSON.h"
//#include "libclassifier.h"

/* ==========================================================================
 * Constants and Macros
 * ========================================================================== */

#define SOCKET_PATH                 "/tmp/scheduler_socket"
#define CSV_FILE                    "classifier_val.csv"
#define CORE_ALLOCATION_CSV         "core_allocation.csv"

#define MAX_CORES                   16
#define MAX_QUEUE_SIZE              2048 //( max number of proccesses)
#define SCHEDULER_SLEEP_MILLISECONDS 100

// Default Core Sets
#define COMPUTE_CORESET             "0,1,2,3,4,5,6,7"
#define IO_CORESET                  "8-15"
#define MEMORY_CORESET              "0,1,2,3,4,5,6,7"

#define P_CORESET                   "0-7"
#define E_CORESET                   "8-15"
#define ALL_CORESET                 "0-15"

// Macros
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// Logging
#ifndef QUIET_SCHEDULER
#define SCHEDULER_PRINTF(fmt, ...) \
    printf("\033[33m[SCHEDULER]\033[0m: " fmt, ##__VA_ARGS__)
#else
#define SCHEDULER_PRINTF(fmt, ...) /* No-op */
#endif

#define SCHEDULER_PERROR(fmt, ...) \
    fprintf(stderr, "\033[31m[SCHEDULER ERROR]\033[0m: " fmt, ##__VA_ARGS__)

/* ==========================================================================
 * Data Structures
 * ========================================================================== */

// Linear Regression Model Structure
typedef struct {
    double intercept;
    double w_cycles_per_ms;
    double w_ipc;
    double w_cmr;      // Cache Miss Ratio
    double w_mspm;     // Mem Stall per Mem
    double w_mspi;     // Mem Stall per Inst
    int loaded;
} PredictionModel;

// Process status register 
typedef struct {
    int p_threads;
    int e_threads;
    int other_threads;
    int total_threads;
} ThreadDistributionSummary;

// Dynamic core allocations
typedef struct {
    char compute_coreset[256];
    char io_coreset[256];
    char memory_coreset[256];
} DynamicCoreMasks;

// Process queue entry
typedef struct {
    pid_t pid;
    MonitorData current_data;
    MonitorData *history;
    int history_count;
    int history_capacity;
    MonitorData last_used;
    int has_last_used;
    int startup_flag;
    char predicted_class[16];
    int last_on_p;   // P=1 default, E=0
    int has_last_on_p;
} ProcessEntry;

/* ==========================================================================
 * Global State
 * ========================================================================== */

static PredictionModel g_model_P;
static PredictionModel g_model_E;
static const double HYST = 0.15;     // 15% Hysteresis threshold

static ProcessEntry g_process_queue[MAX_QUEUE_SIZE];
static int g_queue_size = 0;

static int g_active_compute_threads = 0;
static int g_active_io_threads = 0;
static int g_active_memory_threads = 0;

static DynamicCoreMasks g_prev_masks = { {0}, {0}, {0} };

/* ==========================================================================
 * Utility Functions 
 * ========================================================================== */
// Clamp value to non negative
static double clamp_nonneg(double value) {
    return (value < 0.0) ? 0.0 : value;
}

static inline uint64_t get_nsec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static char *read_entire_file(const char *file_path) {
    FILE *file_ptr = fopen(file_path, "rb");
    if (!file_ptr) return NULL;
    
    if (fseek(file_ptr, 0, SEEK_END) != 0) { 
        fclose(file_ptr); 
        return NULL; 
    }
    
    long file_size = ftell(file_ptr);
    if (file_size < 0) { 
        fclose(file_ptr); 
        return NULL; 
    }
    rewind(file_ptr);

    char *buffer = (char*)malloc((size_t)file_size + 1);
    if (!buffer) { 
        fclose(file_ptr); 
        return NULL; 
    }

    size_t bytes_read = fread(buffer, 1, (size_t)file_size, file_ptr);
    fclose(file_ptr);
    
    if (bytes_read != (size_t)file_size) { 
        free(buffer); 
        return NULL; 
    }

    buffer[file_size] = '\0';
    return buffer;
}

static int is_process_alive(pid_t pid) {
    if (kill(pid, 0) == 0) return 1; // Process exists
    return errno != ESRCH; // Return 0 only if process definitely doesn't exist
}

static int compare_integers(const void *a, const void *b) {
    return *(int *)a - *(int *)b;
}

/* ==========================================================================
 * JSON & Model Loading Logic
 * ========================================================================== */

static int json_validate_features(const cJSON *root) {
    static const char *required_features[5] = {
        "cycles_per_ms", "IPC", "Cache_Miss_Ratio", "MemStall_per_Mem", "MemStall_per_Inst"
    };

    const cJSON *features_array = cJSON_GetObjectItemCaseSensitive((cJSON*)root, "features");
    if (!cJSON_IsArray(features_array)) return 0;

    // Check each required feature appears at least once
    for (int k = 0; k < 5; k++) {
        int found = 0;
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, features_array) {
            if (cJSON_IsString(item) && item->valuestring && strcmp(item->valuestring, required_features[k]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) return 0;
    }
    return 1;
}
// Extract double value from JSON object by key
static int json_get_double(const cJSON *obj, const char *key, double *out_value) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive((cJSON*)obj, key);
    if (!cJSON_IsNumber(item)) return -1;
    *out_value = item->valuedouble;
    return 0;
}

static int load_prediction_model(const char *json_path, PredictionModel *model_out) {
    memset(model_out, 0, sizeof(*model_out));

    char *json_content = read_entire_file(json_path);
    if (!json_content) {
        SCHEDULER_PERROR("Failed to read model file %s\n", json_path);
        return -1;
    }

    cJSON *root = cJSON_Parse(json_content);
    free(json_content);
    if (!root) {
        SCHEDULER_PERROR("Failed to parse JSON in %s\n", json_path);
        return -1;
    }
    
    if (!json_validate_features(root)) {
        SCHEDULER_PERROR("Model %s: 'features' does not match expected set\n", json_path);
        cJSON_Delete(root);
        return -1;
    }

    if (json_get_double(root, "intercept", &model_out->intercept) != 0) goto error;

    cJSON *weights = cJSON_GetObjectItemCaseSensitive(root, "weights");
    if (!cJSON_IsObject(weights)) goto error;

    if (json_get_double(weights, "cycles_per_ms", &model_out->w_cycles_per_ms) != 0) goto error;
    if (json_get_double(weights, "IPC",           &model_out->w_ipc)          != 0) goto error;
    if (json_get_double(weights, "Cache_Miss_Ratio", &model_out->w_cmr)       != 0) goto error;
    if (json_get_double(weights, "MemStall_per_Mem", &model_out->w_mspm)      != 0) goto error;
    if (json_get_double(weights, "MemStall_per_Inst",&model_out->w_mspi)      != 0) goto error;

    model_out->loaded = 1;
    cJSON_Delete(root);
    return 0;

error:
    SCHEDULER_PERROR("Model %s missing expected fields/weights\n", json_path);
    cJSON_Delete(root);
    return -1;
}

static double calculate_prediction_score(const PredictionModel *model,
                       double cycles_per_ms,
                       double ipc,
                       double cmr,
                       double mspm,
                       double mspi)
{
    double score = model->intercept
             + model->w_cycles_per_ms * cycles_per_ms
             + model->w_ipc          * ipc
             + model->w_cmr          * cmr
             + model->w_mspm         * mspm
             + model->w_mspi         * mspi;
    return clamp_nonneg(score);
}

/* ==========================================================================
 * Core Affinity and Helpers
 * ========================================================================== */

static void parse_coreset_string(const char *coreset_str, int *out_cores, int *out_count) {
    *out_count = 0;
    if (!coreset_str || !coreset_str[0]) return;
    
    char *str_copy = strdup(coreset_str);
    if (!str_copy) {
        SCHEDULER_PERROR("Failed to allocate memory for coreset parsing\n");
        return;
    }
    
    char *token = strtok(str_copy, ",");
    while (token) {
        if (strchr(token, '-')) {
            int start, end;
            if (sscanf(token, "%d-%d", &start, &end) == 2) {
                for (int i = start; i <= end && *out_count < MAX_CORES; i++) {
                    if (i >= 0 && i < MAX_CORES) out_cores[(*out_count)++] = i;
                }
            }
        } else {
            int core_id = atoi(token);
            if (core_id >= 0 && core_id < MAX_CORES && *out_count < MAX_CORES) {
                out_cores[(*out_count)++] = core_id;
            }
        }
        token = strtok(NULL, ",");
    }
    free(str_copy);
}

static void convert_cores_to_string(int *cores, int core_count, char *out_str, size_t size) {
    if (core_count == 0) {
        out_str[0] = '\0';
        return;
    }
    
    qsort(cores, core_count, sizeof(int), compare_integers);
    out_str[0] = '\0';
    
    int i = 0;
    while (i < core_count) {
        int start = cores[i];
        int end = start;
        while (i + 1 < core_count && cores[i + 1] == end + 1) {
            end++;
            i++;
        }
        
        char temp_buf[32];
        if (start == end) {
            snprintf(temp_buf, sizeof(temp_buf), "%d", start);
        } else {
            snprintf(temp_buf, sizeof(temp_buf), "%d-%d", start, end);
        }
        
        if (out_str[0]) {
            strncat(out_str, ",", size - strlen(out_str) - 1);
        }
        strncat(out_str, temp_buf, size - strlen(out_str) - 1);
        i++;
    }
}

static int read_processor_from_tid(pid_t tid, int *out_cpu) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/stat", tid, tid);

    FILE *file_ptr = fopen(path, "r");
    if (!file_ptr) return -1;

    char buffer[4096];
    if (!fgets(buffer, sizeof(buffer), file_ptr)) {
        fclose(file_ptr);
        return -1;
    }
    fclose(file_ptr);

    char *right_paren = strrchr(buffer, ')');
    if (!right_paren) return -1;

    char *cursor = right_paren + 1; 
    // We need field #39 overall ( processor)
    int field_idx = 3;
    char *saveptr = NULL;
    char *token = strtok_r(cursor, " ", &saveptr);
    
    while (token) {
        if (*token == '\0') { 
            token = strtok_r(NULL, " ", &saveptr); 
            continue; 
        }
        if (field_idx == 39) {
            *out_cpu = atoi(token);
            return 0;
        }
        field_idx++;
        token = strtok_r(NULL, " ", &saveptr);
    }
    return -1;
}

// Summarize thread distribution for a process
static ThreadDistributionSummary summarize_psr_for_process(pid_t pid) {
    ThreadDistributionSummary summary = {0};
    char task_dir_path[256];
    snprintf(task_dir_path, sizeof(task_dir_path), "/proc/%d/task", pid);

    DIR *dir = opendir(task_dir_path);
    if (!dir) return summary;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0])) continue;

        pid_t tid = (pid_t)atoi(entry->d_name);
        if (tid <= 0) continue;

        int cpu = -1;
        if (read_processor_from_tid(tid, &cpu) != 0) continue;

        summary.total_threads++;
        if (0 <= cpu && cpu <= 7) summary.p_threads++;
        else if (8 <= cpu && cpu <= 15) summary.e_threads++;
        else summary.other_threads++;
    }
    closedir(dir);
    return summary;
}

void get_current_core_info(pid_t pid, int *out_core, int *out_is_pcore) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    if (sched_getaffinity(pid, sizeof(cpu_set_t), &cpuset) == -1) {
        *out_core = -1;
        *out_is_pcore = 0;
        return;
    }
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, &cpuset)) {
            *out_core = i;
            *out_is_pcore = (i < 8) ? 1 : 0; // Assumption: 0-7 are p-cores
            return;
        }
    }
    *out_core = -1;
    *out_is_pcore = 0;
}
// Set process affinity based on coreset string
void set_process_affinity(pid_t pid, const char *coreset_str) {
    if (!coreset_str || !coreset_str[0]) {
        SCHEDULER_PERROR("Empty coreset for PID %d\n", pid);
        return;
    }
    SCHEDULER_PRINTF("Setting affinity for PID %d to coreset %s\n", pid, coreset_str);
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    
    char *str_copy = strdup(coreset_str);
    if (!str_copy) {
        SCHEDULER_PERROR("Failed to allocate memory for coreset\n");
        return;
    }
    
    char *token = strtok(str_copy, ",");
    while (token) {
        if (strchr(token, '-')) {
            int start, end;
            if (sscanf(token, "%d-%d", &start, &end) == 2) {
                for (int i = start; i <= end && i < MAX_CORES; i++) {
                    if (i >= 0) CPU_SET(i, &cpuset);
                }
            }
        } else {
            int cpu = atoi(token);
            if (cpu >= 0 && cpu < MAX_CORES) CPU_SET(cpu, &cpuset);
        }
        token = strtok(NULL, ",");
    }
    free(str_copy);
    
    if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset) == -1) {
        SCHEDULER_PERROR("Failed to set affinity for PID %d: %s\n", pid, strerror(errno));
    }
}
// Apply affinity recursively to all threads of a process - used for pthreads child threads
void apply_affinity_recursive(pid_t pid, const char *coreset_str) {
    if (!is_process_alive(pid)) {
        SCHEDULER_PRINTF("PID %d not alive, skipping affinity\n", pid);
        return;
    }
    set_process_affinity(pid, coreset_str);
    
    char task_dir_path[256];
    snprintf(task_dir_path, sizeof(task_dir_path), "/proc/%d/task", pid);
    
    DIR *dir = opendir(task_dir_path);
    if (!dir) {
        SCHEDULER_PERROR("Failed to open task directory for PID %d: %s\n", pid, strerror(errno));
        return;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        pid_t tid = atoi(entry->d_name);
        if (tid > 0 && tid != pid && is_process_alive(tid)) {
            set_process_affinity(tid, coreset_str);
        }
    }
    closedir(dir);
}

void verify_process_affinity(pid_t pid) {
    if (!is_process_alive(pid)) {
        SCHEDULER_PRINTF("PID %d not alive, skipping verification\n", pid);
        return;
    }
    char cmd_buffer[256];
    snprintf(cmd_buffer, sizeof(cmd_buffer), "ps -mo pid,tid,psr,cmd -p %d", pid);
    SCHEDULER_PRINTF("Verifying affinity for PID %d:\n", pid);
    if (system(cmd_buffer) != 0) {
        SCHEDULER_PERROR("Failed to execute ps command for PID %d\n", pid);
    }
}

void set_thread_priority(pid_t tid, int priority, const char *class_name, int core, int is_pcore) {
    struct sched_param param;
    param.sched_priority = priority;
    if (sched_setscheduler(tid, SCHED_FIFO, &param) == -1) {
        fprintf(stderr, "Failed to set priority %d for TID %d: %s\n", priority, tid, strerror(errno));
    }
}

/* ==========================================================================
 * Queue Management
 * ========================================================================== */
// Initialize a process entry to default values
static void init_process_entry(ProcessEntry *entry) {
    entry->pid = 0;
    memset(&entry->current_data, 0, sizeof(MonitorData));
    entry->history = NULL;
    entry->history_count = 0;
    entry->history_capacity = 0;
    memset(&entry->last_used, 0, sizeof(MonitorData));
    entry->has_last_used = 0;
    entry->startup_flag = 0;
    entry->last_on_p = 1;
    entry->has_last_on_p = 0;
}

static void free_process_entry(ProcessEntry *entry) {
    if (entry->history) {
        free(entry->history);
        entry->history = NULL;
    }
    entry->history_count = 0;
    entry->history_capacity = 0;
    entry->pid = 0;
    memset(&entry->current_data, 0, sizeof(MonitorData));
    memset(&entry->last_used, 0, sizeof(MonitorData));
    entry->has_last_used = 0;
    entry->startup_flag = 0;
}

static void remove_process_from_queue(int index) {
    SCHEDULER_PRINTF("Removing PID %d from queue\n", g_process_queue[index].pid);
    
    if (g_process_queue[index].history) {
        free(g_process_queue[index].history);
        g_process_queue[index].history = NULL;
    }
    
    // Shift remaining entries
    for (int i = index; i < g_queue_size - 1; i++) {
        g_process_queue[i] = g_process_queue[i + 1];
    }
    
    init_process_entry(&g_process_queue[g_queue_size - 1]);
    g_queue_size--;
}

static int update_or_add_process(pid_t pid, MonitorData data, int startup_flag) {
    if (!is_process_alive(pid)) {
        SCHEDULER_PRINTF("PID %d does not exist, not adding/updating queue\n", pid);
        return -1;
    }

    // Try to find and update existing entry
    for (int i = 0; i < g_queue_size; i++) {
        if (g_process_queue[i].pid == pid) {
            SCHEDULER_PRINTF("Updating PID %d in queue\n", pid);

            if (g_process_queue[i].history_count >= g_process_queue[i].history_capacity) {
                int new_cap = (g_process_queue[i].history_capacity == 0) ? 4 : g_process_queue[i].history_capacity * 2;
                MonitorData *new_history = realloc(g_process_queue[i].history, new_cap * sizeof(MonitorData));
                if (!new_history) {
                    SCHEDULER_PERROR("Failed to allocate history for PID %d\n", pid);
                    return -1;
                }
                g_process_queue[i].history = new_history;
                g_process_queue[i].history_capacity = new_cap;
            }

            g_process_queue[i].history[g_process_queue[i].history_count++] = data;
            g_process_queue[i].current_data = data;
            g_process_queue[i].startup_flag = startup_flag;

            return 0;
        }
    }

    // Add new entry
    if (g_queue_size >= MAX_QUEUE_SIZE) {
        SCHEDULER_PERROR("Queue full, cannot add PID %d\n", pid);
        return -1;
    }

    SCHEDULER_PRINTF("Adding PID %d to queue\n", pid);

    init_process_entry(&g_process_queue[g_queue_size]);
    g_process_queue[g_queue_size].pid = pid;

    g_process_queue[g_queue_size].history = malloc(4 * sizeof(MonitorData));
    if (!g_process_queue[g_queue_size].history) {
        SCHEDULER_PERROR("Failed to allocate history for PID %d\n", pid);
        return -1;
    }

    g_process_queue[g_queue_size].history_capacity = 4;
    g_process_queue[g_queue_size].history[0] = data;
    g_process_queue[g_queue_size].history_count = 1;
    g_process_queue[g_queue_size].current_data = data;
    g_process_queue[g_queue_size].startup_flag = startup_flag;

    g_queue_size++;
    return 0;
}

/* ==========================================================================
 * Scheduling Logic
 * ========================================================================== */
static void calculate_dynamic_coresets(DynamicCoreMasks *out_masks) {
    int total_threads = g_active_compute_threads + g_active_io_threads + g_active_memory_threads;

    if (total_threads == 0) {
        strcpy(out_masks->compute_coreset, COMPUTE_CORESET);
        strcpy(out_masks->io_coreset, IO_CORESET);
        strcpy(out_masks->memory_coreset, MEMORY_CORESET);
        SCHEDULER_PRINTF("No threads, reset: Compute=%s, IO=%s, Memory=%s\n",
                         out_masks->compute_coreset, out_masks->io_coreset, out_masks->memory_coreset);
        strcpy(g_prev_masks.compute_coreset, out_masks->compute_coreset);
        strcpy(g_prev_masks.io_coreset, out_masks->io_coreset);
        strcpy(g_prev_masks.memory_coreset, out_masks->memory_coreset);
        return;
    }

    int pcores_pool[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    int ecores_pool[8] = {8, 9, 10, 11, 12, 13, 14, 15};
    int available_pcores = 8, available_ecores = 8;
    
    int compute_cores[64] = {0}, io_cores[64] = {0}, memory_cores[64] = {0};
    int n_compute = 0, n_io = 0, n_memory = 0;

    int min_cores_per_class = 1;
    int is_compute_active = g_active_compute_threads > 0;
    int is_memory_active = g_active_memory_threads > 0;
    int is_io_active = g_active_io_threads > 0;
    
    int active_classes_count = is_compute_active + is_memory_active + is_io_active;
    int reserved_cores = min_cores_per_class * active_classes_count;
    int remaining_cores_total = MAX_CORES - reserved_cores;

    // Weighting Logic
    int weight_compute = g_active_compute_threads;
    int weight_memory = g_active_memory_threads >> 2; 
    int weight_io = g_active_io_threads;
    double total_weight = (double)(weight_compute + weight_memory + weight_io);
    if (total_weight == 0) total_weight = 1.0;

    int desired_compute = is_compute_active ? min_cores_per_class + (int)(remaining_cores_total * weight_compute / total_weight) : 0;
    int desired_io = is_io_active ? min_cores_per_class + (int)(remaining_cores_total * weight_io / total_weight) : 0;
    int desired_memory = is_memory_active ? min_cores_per_class + (int)(remaining_cores_total * weight_memory / total_weight) : 0;

    // Fix rounding errors
    int desired_total = desired_compute + desired_io + desired_memory;
    if (desired_total < MAX_CORES) {
        if (is_compute_active) desired_compute += MAX_CORES - desired_total;
        else if (is_memory_active) desired_memory += MAX_CORES - desired_total;
        else if (is_io_active) desired_io += MAX_CORES - desired_total;
    } else if (desired_total > MAX_CORES) {
        if (is_io_active) {
            desired_io -= desired_total - MAX_CORES;
            desired_io = MAX(desired_io, min_cores_per_class);
        } else if (is_memory_active) {
            desired_memory -= desired_total - MAX_CORES;
            desired_memory = MAX(desired_memory, min_cores_per_class);
        } else if (is_compute_active) {
            desired_compute -= desired_total - MAX_CORES;
            desired_compute = MAX(desired_compute, min_cores_per_class);
        }
    }

    int p_pool_idx = 0;

    /* --- P-Core Allocation --- */
    int remaining_p = available_pcores;
    double p_weight = (double)(weight_compute + weight_memory);
    if (p_weight > 0) {
        int p_compute = (int)(remaining_p * weight_compute / p_weight);
        int p_memory = remaining_p - p_compute;

        int cores_to_take = MIN(p_compute, available_pcores);
        for (int i = 0; i < cores_to_take; i++) {
            compute_cores[n_compute++] = pcores_pool[p_pool_idx++];
        }
        desired_compute = MAX(desired_compute - cores_to_take, 0);
        available_pcores -= cores_to_take;
        SCHEDULER_PRINTF("Compute assigned %d additional P-cores (proportional)\n", cores_to_take);

        cores_to_take = MIN(p_memory, available_pcores);
        for (int i = 0; i < cores_to_take; i++) {
            memory_cores[n_memory++] = pcores_pool[p_pool_idx++];
        }
        desired_memory = MAX(desired_memory - cores_to_take, 0);
        available_pcores -= cores_to_take;
        SCHEDULER_PRINTF("Memory assigned %d additional P-cores (proportional)\n", cores_to_take);
    }

    /* --- E-Core Allocation to IO --- */
    if (is_io_active && desired_io > 0) {
        int cores_to_take = MIN(desired_io, available_ecores);
        for (int i = 0; i < cores_to_take; i++) {
            io_cores[n_io++] = ecores_pool[i];
        }
        memmove(ecores_pool, ecores_pool + cores_to_take, (available_ecores - cores_to_take) * sizeof(int));
        available_ecores -= cores_to_take;
        desired_io -= cores_to_take;
        SCHEDULER_PRINTF("IO assigned %d E-cores\n", cores_to_take);
    }

    /* --- Spillover Logic --- */
    if (is_io_active && desired_io > 0 && available_pcores > 0) {
        int cores_to_take = MIN(desired_io, available_pcores);
        for (int i = 0; i < cores_to_take; i++) {
            io_cores[n_io++] = pcores_pool[p_pool_idx++];
        }
        available_pcores -= cores_to_take;
        desired_io -= cores_to_take;
        SCHEDULER_PRINTF("IO assigned %d additional P-cores (spillover)\n", cores_to_take);
    }

    if (is_compute_active && desired_compute > 0 && available_pcores > 0) {
        int cores_to_take = MIN(desired_compute, available_pcores);
        for (int i = 0; i < cores_to_take; i++) {
            compute_cores[n_compute++] = pcores_pool[p_pool_idx++];
        }
        available_pcores -= cores_to_take;
        desired_compute -= cores_to_take;
        SCHEDULER_PRINTF("Compute assigned %d additional P-cores\n", cores_to_take);
    }
    
    if (is_memory_active && desired_memory > 0 && available_pcores > 0) {
        int cores_to_take = MIN(desired_memory, available_pcores);
        for (int i = 0; i < cores_to_take; i++) {
            memory_cores[n_memory++] = pcores_pool[p_pool_idx++];
        }
        available_pcores -= cores_to_take;
        desired_memory -= cores_to_take;
        SCHEDULER_PRINTF("Memory assigned %d additional P-cores\n", cores_to_take);
    }

    // Remaining E-cores to Compute/Memory
    if (is_compute_active && desired_compute > 0 && available_ecores > 0) {
        int cores_to_take = MIN(desired_compute, available_ecores);
        for (int i = 0; i < cores_to_take; i++) {
            compute_cores[n_compute++] = ecores_pool[i];
        }
        memmove(ecores_pool, ecores_pool + cores_to_take, (available_ecores - cores_to_take) * sizeof(int));
        available_ecores -= cores_to_take;
        desired_compute -= cores_to_take;
        SCHEDULER_PRINTF("Compute assigned %d E-cores\n", cores_to_take);
    }
    
    if (is_memory_active && desired_memory > 0 && available_ecores > 0) {
        int cores_to_take = MIN(desired_memory, available_ecores);
        for (int i = 0; i < cores_to_take; i++) {
            memory_cores[n_memory++] = ecores_pool[i];
        }
        memmove(ecores_pool, ecores_pool + cores_to_take, (available_ecores - cores_to_take) * sizeof(int));
        available_ecores -= cores_to_take;
        desired_memory -= cores_to_take;
        SCHEDULER_PRINTF("Memory assigned %d E-cores\n", cores_to_take);
    }

    // Convert arrays to CSV strings
    convert_cores_to_string(compute_cores, n_compute, out_masks->compute_coreset, sizeof(out_masks->compute_coreset));
    convert_cores_to_string(io_cores, n_io, out_masks->io_coreset, sizeof(out_masks->io_coreset));
    convert_cores_to_string(memory_cores, n_memory, out_masks->memory_coreset, sizeof(out_masks->memory_coreset));

    // Fallbacks
    if (out_masks->compute_coreset[0] == '\0' && is_compute_active) {
        strcpy(out_masks->compute_coreset, "0");
        n_compute = 1;
        SCHEDULER_PRINTF("Compute coreset fallback to 0\n");
    }
    if (out_masks->io_coreset[0] == '\0' && is_io_active) {
        strcpy(out_masks->io_coreset, "16");
        n_io = 1;
        SCHEDULER_PRINTF("IO coreset fallback to 16\n");
    }
    if (out_masks->memory_coreset[0] == '\0' && is_memory_active) {
        strcpy(out_masks->memory_coreset, "1");
        n_memory = 1;
        SCHEDULER_PRINTF("Memory coreset fallback to 1\n");
    }

    // Overlap Validation
    int collision_map[MAX_CORES] = {0};
    
    #define CHECK_COLLISION(arr, count, name) \
        for(int i=0; i<count; i++) { \
            if(collision_map[arr[i]]) { \
                SCHEDULER_PERROR("Core %d assigned multiple times\n", arr[i]); \
                strcpy(out_masks->compute_coreset, g_prev_masks.compute_coreset); \
                strcpy(out_masks->io_coreset, g_prev_masks.io_coreset); \
                strcpy(out_masks->memory_coreset, g_prev_masks.memory_coreset); \
                return; \
            } \
            collision_map[arr[i]] = 1; \
        }

    CHECK_COLLISION(compute_cores, n_compute, "compute");
    CHECK_COLLISION(io_cores, n_io, "io");
    CHECK_COLLISION(memory_cores, n_memory, "memory");

    if (n_compute + n_io + n_memory > MAX_CORES) {
        SCHEDULER_PERROR("Total cores %d exceeds MAX_CORES %d\n", n_compute + n_io + n_memory, MAX_CORES);
        strcpy(out_masks->compute_coreset, g_prev_masks.compute_coreset);
        strcpy(out_masks->io_coreset, g_prev_masks.io_coreset);
        strcpy(out_masks->memory_coreset, g_prev_masks.memory_coreset);
        return;
    }

    SCHEDULER_PRINTF("Updated: Compute=%s (%d), IO=%s (%d), Memory=%s (%d)\n",
                     out_masks->compute_coreset, n_compute,
                     out_masks->io_coreset, n_io,
                     out_masks->memory_coreset, n_memory);

    strcpy(g_prev_masks.compute_coreset, out_masks->compute_coreset);
    strcpy(g_prev_masks.io_coreset, out_masks->io_coreset);
    strcpy(g_prev_masks.memory_coreset, out_masks->memory_coreset);
}

static void compute_history_weighted_ratios(pid_t pid, MonitorData *data, MonitorData *history, 
                                   int history_count, MonitorData *last_used, int has_last_used) {
    if (!is_process_alive(pid)) {
        SCHEDULER_PRINTF("PID %d not alive, skipping ratio computation\n", pid);
        return;
    }

    double denominator = 1.0;
    // array size based on history size
    double weights[history_count + has_last_used + 1];
    
    weights[0] = 1.0;
    for (int i = 0; i < history_count; i++) {
        weights[i + 1] = 1.0 / (1 << (i + 1));
        denominator += weights[i + 1];
    }
    if (has_last_used) {
        weights[history_count + 1] = 1.0 / (1 << (history_count + 1));
        denominator += weights[history_count + 1];
    }

    // Accumulators
    double w_ipc = data->ratios.IPC * weights[0];
    double w_cache_miss = data->ratios.Cache_Miss_Ratio * weights[0];
    double w_uop = data->ratios.Uop_per_Cycle * weights[0];
    double w_mem_stall_mem = data->ratios.MemStallCycle_per_Mem_Inst * weights[0];
    double w_mem_stall_inst = data->ratios.MemStallCycle_per_Inst * weights[0];
    double w_fault = data->ratios.Fault_Rate_per_mem_instr * weights[0];
    double w_rchar = data->ratios.RChar_per_Cycle * weights[0];
    double w_wchar = data->ratios.WChar_per_Cycle * weights[0];
    double w_rbytes = data->ratios.RBytes_per_Cycle * weights[0];
    double w_wbytes = data->ratios.WBytes_per_Cycle * weights[0];

    for (int i = 0; i < history_count; i++) {
        double w = weights[i + 1];
        w_ipc += history[i].ratios.IPC * w;
        w_cache_miss += history[i].ratios.Cache_Miss_Ratio * w;
        w_uop += history[i].ratios.Uop_per_Cycle * w;
        w_mem_stall_mem += history[i].ratios.MemStallCycle_per_Mem_Inst * w;
        w_mem_stall_inst += history[i].ratios.MemStallCycle_per_Inst * w;
        w_fault += history[i].ratios.Fault_Rate_per_mem_instr * w;
        w_rchar += history[i].ratios.RChar_per_Cycle * w;
        w_wchar += history[i].ratios.WChar_per_Cycle * w;
        w_rbytes += history[i].ratios.RBytes_per_Cycle * w;
        w_wbytes += history[i].ratios.WBytes_per_Cycle * w;
    }

    if (has_last_used) {
        double w = weights[history_count + 1];
        w_ipc += last_used->ratios.IPC * w;
        w_cache_miss += last_used->ratios.Cache_Miss_Ratio * w;
        w_uop += last_used->ratios.Uop_per_Cycle * w;
        w_mem_stall_mem += last_used->ratios.MemStallCycle_per_Mem_Inst * w;
        w_mem_stall_inst += last_used->ratios.MemStallCycle_per_Inst * w;
        w_fault += last_used->ratios.Fault_Rate_per_mem_instr * w;
        w_rchar += last_used->ratios.RChar_per_Cycle * w;
        w_wchar += last_used->ratios.WChar_per_Cycle * w;
        w_rbytes += last_used->ratios.RBytes_per_Cycle * w;
        w_wbytes += last_used->ratios.WBytes_per_Cycle * w;
    }

    // Normalize
    #define SAFE_DIV(val, div) ((isnan(val) || isinf(val)) ? 0.0 : (val) / (div))

    data->ratios.IPC = SAFE_DIV(w_ipc, denominator);
    data->ratios.Cache_Miss_Ratio = SAFE_DIV(w_cache_miss, denominator);
    data->ratios.Uop_per_Cycle = SAFE_DIV(w_uop, denominator);
    data->ratios.MemStallCycle_per_Mem_Inst = SAFE_DIV(w_mem_stall_mem, denominator);
    data->ratios.MemStallCycle_per_Inst = SAFE_DIV(w_mem_stall_inst, denominator);
    data->ratios.Fault_Rate_per_mem_instr = SAFE_DIV(w_fault, denominator);
    data->ratios.RChar_per_Cycle = SAFE_DIV(w_rchar, denominator);
    data->ratios.WChar_per_Cycle = SAFE_DIV(w_wchar, denominator);
    data->ratios.RBytes_per_Cycle = SAFE_DIV(w_rbytes, denominator);
    data->ratios.WBytes_per_Cycle = SAFE_DIV(w_wbytes, denominator);

    if (!is_process_alive(pid)) {
        memset(&data->ratios, 0, sizeof(data->ratios));
    }
}

static const char *determine_best_coreset(pid_t pid,
                                          MonitorData *d,
                                          int *ptr_last_on_p,
                                          int *ptr_has_last_on_p,
                                          double *out_score_p,
                                          double *out_score_e)
{
    const double dt_ms = 100.0;
    const double cycles = (double)d->total_values[2];
    const double cycles_per_ms = cycles / dt_ms;

    const double ipc  = d->ratios.IPC;
    const double cmr  = d->ratios.Cache_Miss_Ratio;
    const double mspm = d->ratios.MemStallCycle_per_Mem_Inst;
    const double mspi = d->ratios.MemStallCycle_per_Inst;

    if (!isfinite(ipc) || !isfinite(cmr) || !isfinite(mspm) || !isfinite(mspi) ||
        !isfinite(cycles_per_ms) || dt_ms <= 0.0) {

        if (out_score_p) *out_score_p = 0.0;
        if (out_score_e) *out_score_e = 0.0;

        SCHEDULER_PRINTF("Non-finite features (or dt_ms<=0), defaulting to ALL_CORESET\n", 0);
        return ALL_CORESET;
    }

    const double prediction_p = calculate_prediction_score(&g_model_P, cycles_per_ms, ipc, cmr, mspm, mspi);
    const double prediction_e = calculate_prediction_score(&g_model_E, cycles_per_ms, ipc, cmr, mspm, mspi);

    if (out_score_p) *out_score_p = prediction_p;
    if (out_score_e) *out_score_e = prediction_e;

    SCHEDULER_PRINTF(
        "PID features: cycles/ms=%.2f IPC=%.4f CMR=%.6f MSPM=%.4f MSPI=%.4f -> yP=%.4f yE=%.4f last=%c\n",
        cycles_per_ms, ipc, cmr, mspm, mspi, prediction_p, prediction_e, (*ptr_last_on_p ? 'P' : 'E')
    );

    // Initialize Hysteresis
    if (!*ptr_has_last_on_p) {
        *ptr_last_on_p = (prediction_p >= prediction_e) ? 1 : 0;
        *ptr_has_last_on_p = 1;
    }

    const char *selection;
    if (*ptr_last_on_p == 0) {
        // currently on E - switch only if P clearly better (migrate)
        selection = (prediction_p > (1.0 + HYST) * prediction_e) ? P_CORESET : E_CORESET;
    } else {
        // currently on P - switch only if E clearly better (migrate)
        selection = (prediction_e > (1.0 + HYST) * prediction_p) ? E_CORESET : P_CORESET;
    }

    SCHEDULER_PRINTF("MODEL_SCORES pid=%d yP=%.6f yE=%.6f\n", pid, prediction_p, prediction_e);

    if (prediction_e > prediction_p) {
        SCHEDULER_PRINTF("MODEL_PREFERS_E pid=%d yP=%.6f yE=%.6f\n", pid, prediction_p, prediction_e);
    } else if (prediction_p > prediction_e) {
        SCHEDULER_PRINTF("MODEL_PREFERS_P pid=%d yP=%.6f yE=%.6f\n", pid, prediction_p, prediction_e);
    } else {
        SCHEDULER_PRINTF("MODEL_TIE pid=%d yP=%.6f yE=%.6f\n", pid, prediction_p, prediction_e);
    }

    *ptr_last_on_p = (selection == P_CORESET);
    return selection;
}

static int init_logging_csv() {
    SCHEDULER_PRINTF("Initializing CSV file\n");
    FILE *file_ptr = fopen(CSV_FILE, "w");
    if (!file_ptr) {
        SCHEDULER_PERROR("Failed to open CSV file\n");
        return -1;
    }
    fprintf(file_ptr, "P-Threads,P-Cores,E-Cores,INST_RETIRED:ANY_P,PERF_COUNT_HW_CACHE_MISSES,UNHALTED_CORE_CYCLES,MEM_INST_RETIRED:ANY,FAULTS,CYCLES_MEM_ANY,UOPS_RETIRED,IPC,Cache_Miss_Ratio,Uop_per_Cycle,MemStallCycle_per_Mem_Inst,MemStallCycle_per_Inst,Fault_Rate_per_mem_instr,RChar_per_Cycle,WChar_per_Cycle,RBytes_per_Cycle,WBytes_per_Cycle,syscr,syscw,Execution Time (ms),rchar,wchar,read_bytes,write_bytes,Compute_Prob_CJSON,IO_Prob_CJSON,Memory_Prob_CJSON,Class_Time_CJSON (us),Expected_Class\n");
    fclose(file_ptr);
    return 0;
}

static int init_allocation_log() {
    SCHEDULER_PRINTF("Initializing core allocation CSV file\n");
    FILE *file_ptr = fopen(CORE_ALLOCATION_CSV, "w");
    if (!file_ptr) {
        SCHEDULER_PERROR("Failed to open core allocation CSV file\n");
        return -1;
    }
    fprintf(file_ptr, "Compute Bound Thread Num,I/O Bound Thread Num,Memory Bound Thread Num");
    for (int i = 0; i < MAX_CORES; i++) {
        fprintf(file_ptr, ",Core %d", i);
    }
    fprintf(file_ptr, "\n");
    fclose(file_ptr);
    return 0;
}

static void log_allocation_snapshot(DynamicCoreMasks *masks) {
    SCHEDULER_PRINTF("Logging core allocation to CSV\n");

    int core_map[MAX_CORES] = {0};
    char *dup_str;
    char *token;

    // Parse Compute
    dup_str = strdup(masks->compute_coreset);
    if (dup_str) {
        token = strtok(dup_str, ",");
        while (token) {
            if (strchr(token, '-')) {
                int start, end;
                if (sscanf(token, "%d-%d", &start, &end) == 2) {
                    for (int i = start; i <= end; i++) {
                        if (i >= 0 && i < MAX_CORES) core_map[i] = 0;
                    }
                }
            } else {
                int cpu = atoi(token);
                if (cpu >= 0 && cpu < MAX_CORES) core_map[cpu] = 0;
            }
            token = strtok(NULL, ",");
        }
        free(dup_str);
    }

    // Parse IO
    dup_str = strdup(masks->io_coreset);
    if (dup_str) {
        token = strtok(dup_str, ",");
        while (token) {
            if (strchr(token, '-')) {
                int start, end;
                if (sscanf(token, "%d-%d", &start, &end) == 2) {
                    for (int i = start; i <= end; i++) {
                        if (i >= 0 && i < MAX_CORES) core_map[i] = 1;
                    }
                }
            } else {
                int cpu = atoi(token);
                if (cpu >= 0 && cpu < MAX_CORES) core_map[cpu] = 1;
            }
            token = strtok(NULL, ",");
        }
        free(dup_str);
    }

    // Parse Memory
    dup_str = strdup(masks->memory_coreset);
    if (dup_str) {
        token = strtok(dup_str, ",");
        while (token) {
            if (strchr(token, '-')) {
                int start, end;
                if (sscanf(token, "%d-%d", &start, &end) == 2) {
                    for (int i = start; i <= end; i++) {
                        if (i >= 0 && i < MAX_CORES) core_map[i] = 2;
                    }
                }
            } else {
                int cpu = atoi(token);
                if (cpu >= 0 && cpu < MAX_CORES) core_map[cpu] = 2;
            }
            token = strtok(NULL, ",");
        }
        free(dup_str);
    }

    FILE *file_ptr = fopen(CORE_ALLOCATION_CSV, "a");
    if (!file_ptr) {
        SCHEDULER_PERROR("Failed to append to core allocation CSV\n");
        return;
    }
    fprintf(file_ptr, "%d,%d,%d", g_active_compute_threads, g_active_io_threads, g_active_memory_threads);
    for (int i = 0; i < MAX_CORES; i++) {
        fprintf(file_ptr, ",%d", core_map[i]);
    }
    fprintf(file_ptr, "\n");
    fclose(file_ptr);
}

void append_to_csv(const MonitorData *data, long class_time_us, const char *predicted_class_name) {
    FILE *file_ptr = fopen(CSV_FILE, "a");
    if (!file_ptr) {
        SCHEDULER_PERROR("Failed to append to CSV file\n");
        return;
    }
    fprintf(file_ptr, "%d,%d,%d,%lld,%lld,%lld,%lld,%lld,%lld,%lld,"
                "%.15lf,%.15lf,%.15lf,%.15lf,%.15lf,%.15lf,%.15lf,%.15lf,%.15lf,%.15lf,"
                "%llu,%llu,%lf,%llu,%llu,%llu,%llu,"
                "%.15lf,%.15lf,%.15lf,%ld,%s\n",
            data->pthread_count, data->pcore_count, data->ecore_count,
            data->total_values[0], data->total_values[1], data->total_values[2],
            data->total_values[3], data->total_values[4], data->total_values[5],
            data->total_values[6], data->ratios.IPC, data->ratios.Cache_Miss_Ratio,
            data->ratios.Uop_per_Cycle, data->ratios.MemStallCycle_per_Mem_Inst,
            data->ratios.MemStallCycle_per_Inst, data->ratios.Fault_Rate_per_mem_instr,
            data->ratios.RChar_per_Cycle, data->ratios.WChar_per_Cycle,
            data->ratios.RBytes_per_Cycle, data->ratios.WBytes_per_Cycle,
            data->io_delta.syscr, data->io_delta.syscw, data->exec_time_ms,
            data->io_delta.rchar, data->io_delta.wchar, data->io_delta.read_bytes,
            data->io_delta.write_bytes, data->compute_prob_cjson, data->io_prob_cjson,
            data->memory_prob_cjson, class_time_us, predicted_class_name);
    fclose(file_ptr);
}

static void process_scheduling_queue(DynamicCoreMasks *current_masks) {
    SCHEDULER_PRINTF("Processing queue with %d entries\n", g_queue_size);

    int i = 0;
    while (i < g_queue_size) {
        pid_t pid = g_process_queue[i].pid;

        if (!is_process_alive(pid)) {
            SCHEDULER_PRINTF("Process PID %d died, removing from queue\n", pid);
            remove_process_from_queue(i);
            continue;
        }

        MonitorData working_data = g_process_queue[i].current_data;
        int is_startup = g_process_queue[i].startup_flag;

        // Restore latest topology counts from history if available
        if (g_process_queue[i].history_count > 0) {
            int latest_idx = g_process_queue[i].history_count - 1;
            working_data.pthread_count = g_process_queue[i].history[latest_idx].pthread_count;
            working_data.pcore_count   = g_process_queue[i].history[latest_idx].pcore_count;
            working_data.ecore_count   = g_process_queue[i].history[latest_idx].ecore_count;
        }

        // Compute weighted ratios
        if (g_process_queue[i].history_count > 0 || g_process_queue[i].has_last_used) {
            compute_history_weighted_ratios(pid, &working_data, 
                                    g_process_queue[i].history,
                                    g_process_queue[i].history_count,
                                    &g_process_queue[i].last_used,
                                    g_process_queue[i].has_last_used);
        }

        if (!is_process_alive(pid)) {
            SCHEDULER_PRINTF("Process PID %d died during computation, removing\n", pid);
            remove_process_from_queue(i);
            continue;
        }

        // Timing measurement
        struct timespec ts_start, ts_end;
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        // ... Classification work would go here ...
        // it will be added in the second phase
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        long classification_time_us = (ts_end.tv_sec - ts_start.tv_sec) * 1000000
                                    + (ts_end.tv_nsec - ts_start.tv_nsec) / 1000;

        const char *class_label = "N/A";
        double score_p = 0.0, score_e = 0.0;
        const char *target_coreset = NULL;

        if (is_startup) {
            target_coreset = ALL_CORESET;
        } else {
            target_coreset = determine_best_coreset(
                pid,
                &working_data,
                &g_process_queue[i].last_on_p,
                &g_process_queue[i].has_last_on_p,
                &score_p, &score_e
            );
        }

        append_to_csv(&working_data, classification_time_us, class_label);

        // Apply placement
        apply_affinity_recursive(pid, target_coreset);
        SCHEDULER_PRINTF("PID %d placement -> %s\n", pid, target_coreset);
        verify_process_affinity(pid);

        // Evaluation Logging
        usleep(50 * 1000);
        ThreadDistributionSummary psr_summary = summarize_psr_for_process(pid);
        printf("SCHED_EVAL pid=%d yP=%.6f yE=%.6f chosen=%s actual_P=%d actual_E=%d actual_other=%d total=%d\n",
               pid, score_p, score_e, target_coreset,
               psr_summary.p_threads, psr_summary.e_threads, psr_summary.other_threads, psr_summary.total_threads);

        // Update Queue State
        g_process_queue[i].startup_flag = 0;
        g_process_queue[i].last_used = working_data;
        g_process_queue[i].has_last_used = 1;
        g_process_queue[i].current_data = working_data;
        g_process_queue[i].history_count = 0;

        strncpy(g_process_queue[i].predicted_class, class_label,
                sizeof(g_process_queue[i].predicted_class) - 1);
        g_process_queue[i].predicted_class[sizeof(g_process_queue[i].predicted_class) - 1] = '\0';

        i++;
    }
}



void perform_shutdown_cleanup(int server_fd) {
    SCHEDULER_PRINTF("Cleaning up scheduler\n");
    
    if (server_fd >= 0) {
        close(server_fd);
    }
    unlink(SOCKET_PATH);
    
    for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
        free_process_entry(&g_process_queue[i]);
    }
    g_queue_size = 0;
}



/* ==========================================================================
 * Main
 * ========================================================================== */

int main(int argc, char *argv[]) {
    if (argc != 2) {
        SCHEDULER_PERROR("Usage: %s <coreset>\n", argv[0]);
        return 1;
    }

    // Init Queue
    for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
        init_process_entry(&g_process_queue[i]);
    }

    // Set Scheduler Affinity
    set_process_affinity(getpid(), argv[1]);
    SCHEDULER_PRINTF("Scheduler bound to coreset %s\n", argv[1]);

    // Load Models
    if (load_prediction_model("model_P.json", &g_model_P) != 0) return 1;
    if (load_prediction_model("model_E.json", &g_model_E) != 0) return 1;

    SCHEDULER_PRINTF("Loaded models:\n");
    SCHEDULER_PRINTF(" P: b=%.3f w_cycles/ms=%.6f w_ipc=%.3f w_cmr=%.3f w_mspm=%.3f w_mspi=%.3f\n",
                     g_model_P.intercept, g_model_P.w_cycles_per_ms, g_model_P.w_ipc, g_model_P.w_cmr,
                     g_model_P.w_mspm, g_model_P.w_mspi);
    SCHEDULER_PRINTF(" E: b=%.3f w_cycles/ms=%.6f w_ipc=%.3f w_cmr=%.3f w_mspm=%.3f w_mspi=%.3f\n",
                     g_model_E.intercept, g_model_E.w_cycles_per_ms, g_model_E.w_ipc, g_model_E.w_cmr,
                     g_model_E.w_mspm, g_model_E.w_mspi);

    // Init Logs
    if (init_logging_csv() || init_allocation_log()) {
        SCHEDULER_PERROR("Failed to initialize CSV files\n");
        return 1;
    }

    // Socket Setup
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1) {
        SCHEDULER_PERROR("socket: %s\n", strerror(errno));
        perform_shutdown_cleanup(-1);
        return 1;
    }

    int flags = fcntl(server_fd, F_GETFL, 0);
    fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    unlink(SOCKET_PATH);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        SCHEDULER_PERROR("bind: %s\n", strerror(errno));
        perform_shutdown_cleanup(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) == -1) {
        SCHEDULER_PERROR("listen: %s\n", strerror(errno));
        perform_shutdown_cleanup(server_fd);
        return 1;
    }

    SCHEDULER_PRINTF("Running, listening on %s\n", SOCKET_PATH);

    // Main Loop
    while (1) {
        // Accept incoming connections non-blocking
        while (1) {
            int client_fd = accept(server_fd, NULL, NULL);
            if (client_fd == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                SCHEDULER_PERROR("Error accepting connection: %s\n", strerror(errno));
                continue;
            }

            pid_t pid;
            ssize_t bytes_read = read(client_fd, &pid, sizeof(pid));
            if (bytes_read != sizeof(pid)) {
                SCHEDULER_PERROR("Failed to read PID\n");
                close(client_fd);
                continue;
            }

            if (pid == -1) {
                SCHEDULER_PRINTF("Received shutdown request\n");
                close(client_fd);
                perform_shutdown_cleanup(server_fd);
                return 0;
            }

            int startup_flag;
            MonitorData data;
            bytes_read = read(client_fd, &startup_flag, sizeof(int));
            bytes_read += read(client_fd, &data, sizeof(MonitorData));

            if (bytes_read != sizeof(int) + sizeof(MonitorData)) {
                SCHEDULER_PERROR("Incomplete data received for PID %d\n", pid);
                close(client_fd);
                continue;
            }

            update_or_add_process(pid, data, startup_flag);
            close(client_fd);
        }

        // Logic Step
        DynamicCoreMasks masks;
        calculate_dynamic_coresets(&masks);
        
        SCHEDULER_PRINTF("Computed coresets: Compute=%s, I/O=%s, Memory=%s\n",
                         masks.compute_coreset, masks.io_coreset, masks.memory_coreset);
        
        log_allocation_snapshot(&masks);
        process_scheduling_queue(&masks);

        usleep(SCHEDULER_SLEEP_MILLISECONDS * 1000);
    }

    perform_shutdown_cleanup(server_fd);
    return 0;
}