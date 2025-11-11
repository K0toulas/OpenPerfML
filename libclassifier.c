#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "libclassifier.h"

#ifndef QUIET_CLASSIFIER
#define CLASSIFIER_PRINTF(fmt, ...) \
    printf("\033[34m[CLASSIFIER]\033[0m: " fmt, ##__VA_ARGS__)
#define CLASSIFIER_PERROR(fmt, ...) \
    fprintf(stderr, "\033[31m[CLASSIFIER ERROR]\033[0m: " fmt, ##__VA_ARGS__)
#else
#define CLASSIFIER_PRINTF(fmt, ...) /* No-op */
#define CLASSIFIER_PERROR(fmt, ...) \
    fprintf(stderr, "\033[31m[CLASSIFIER ERROR]\033[0m: " fmt, ##__VA_ARGS__)
#endif

#define MAX_NODES 10000
#define NUM_TREES 300

typedef struct {
    int is_leaf;
    int feature_idx;
    double threshold;
    int left, right;
    double class_probs[NUM_CLASSES];
} TreeNode;

typedef struct {
    TreeNode nodes[MAX_NODES];
    int node_count;
    int root;
} Tree;

static Tree trees[NUM_TREES];
static int tree_count = 0;
static int model_loaded = 0;
static const char *feature_names[] = {
    "P-Threads", "P-Cores", "E-Cores", "IPC", "Cache_Miss_Ratio", "Uop_per_Cycle",
    "MemStallCycle_per_Mem_Inst", "MemStallCycle_per_Inst", "Fault_Rate_per_mem_instr",
    "RChar_per_Cycle", "WChar_per_Cycle", "RBytes_per_Cycle", "WBytes_per_Cycle"
};
static const char *class_names[] = {"Compute", "I/O", "Memory"};

static void load_rf_model(const char *model_path) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s.json", model_path);
    CLASSIFIER_PRINTF("Loading CJSON model %s\n", filename);

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        CLASSIFIER_PERROR("Failed to open %s: %s\n", filename, strerror(errno));
        return;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *json_str = malloc(size + 1);
    if (!json_str) {
        CLASSIFIER_PERROR("Failed to allocate memory for JSON\n");
        fclose(fp);
        return;
    }
    fread(json_str, 1, size, fp);
    json_str[size] = '\0';
    fclose(fp);

    cJSON *json = cJSON_Parse(json_str);
    free(json_str);
    if (!json) {
        CLASSIFIER_PERROR("Failed to parse JSON: %s\n", cJSON_GetErrorPtr());
        return;
    }

    cJSON *trees_json = cJSON_GetObjectItem(json, "trees");
    if (!trees_json) {
        CLASSIFIER_PERROR("No 'trees' in JSON\n");
        cJSON_Delete(json);
        return;
    }
    tree_count = cJSON_GetArraySize(trees_json);
    if (tree_count > NUM_TREES) {
        tree_count = NUM_TREES;
    }

    for (int t = 0; t < tree_count; t++) {
        cJSON *tree_json = cJSON_GetArrayItem(trees_json, t);
        cJSON *nodes_json = cJSON_GetObjectItem(tree_json, "nodes");
        if (!nodes_json) {
            continue;
        }
        int node_count = cJSON_GetArraySize(nodes_json);
        if (node_count > MAX_NODES) {
            node_count = MAX_NODES;
        }
        trees[t].node_count = node_count;

        for (int n = 0; n < node_count; n++) {
            cJSON *node_json = cJSON_GetArrayItem(nodes_json, n);
            cJSON *type_json = cJSON_GetObjectItem(node_json, "type");
            TreeNode *node = &trees[t].nodes[n];
            node->is_leaf = strcmp(cJSON_GetStringValue(type_json), "leaf") == 0;

            if (node->is_leaf) {
                cJSON *value_json = cJSON_GetObjectItem(node_json, "value");
                for (int c = 0; c < NUM_CLASSES; c++) {
                    node->class_probs[c] = cJSON_GetArrayItem(value_json, c)->valuedouble;
                }
            } else {
                cJSON *feature_json = cJSON_GetObjectItem(node_json, "feature");
                const char *feature = cJSON_GetStringValue(feature_json);
                node->feature_idx = -1;
                for (int f = 0; f < NUM_FEATURES; f++) {
                    if (strcmp(feature, feature_names[f]) == 0) {
                        node->feature_idx = f;
                        break;
                    }
                }
                node->threshold = cJSON_GetObjectItem(node_json, "threshold")->valuedouble;
                node->left = cJSON_GetObjectItem(node_json, "left")->valueint;
                node->right = cJSON_GetObjectItem(node_json, "right")->valueint;
            }
        }
        cJSON *root_json = cJSON_GetObjectItem(tree_json, "root");
        trees[t].root = root_json ? root_json->valueint : 0;
    }
    cJSON_Delete(json);
    model_loaded = 1;
}

static void predict_rf(double *features, double *probs, int *pred_class) {
    CLASSIFIER_PRINTF("predict_rf\n");
    for (int c = 0; c < NUM_CLASSES; c++) probs[c] = 0.0;
    for (int t = 0; t < tree_count; t++) {
        int node_idx = trees[t].root;
        while (!trees[t].nodes[node_idx].is_leaf) {
            TreeNode *node = &trees[t].nodes[node_idx];
            if (node->feature_idx < 0 || node->feature_idx >= NUM_FEATURES) {
                break;
            }
            double feature_value = features[node->feature_idx];
            node_idx = feature_value <= node->threshold ? node->left : node->right;
        }
        for (int c = 0; c < NUM_CLASSES; c++) {
            probs[c] += trees[t].nodes[node_idx].class_probs[c];
        }
    }
    for (int c = 0; c < NUM_CLASSES; c++) {
        probs[c] /= tree_count;
    }
    // Normalize probs to sum = 1.0
    double prob_sum = 0.0;
    for (int c = 0; c < NUM_CLASSES; c++) {
        prob_sum += probs[c];
    }
    if (prob_sum > 0.0) {
        // for (int c = 0; c < NUM_CLASSES; c++) {
        //     probs[c] /= prob_sum;
        // }
    } else {
        for (int c = 0; c < NUM_CLASSES; c++) {
            probs[c] = 1.0 / NUM_CLASSES;
        }
    }
    *pred_class = 0;
    double max_prob = probs[0];
    for (int c = 1; c < NUM_CLASSES; c++) {
        if (probs[c] > max_prob) {
            max_prob = probs[c];
            *pred_class = c;
        }
    }
}

int init_classifier_cjson(const char *model_path) {
    CLASSIFIER_PRINTF("Initializing CJSON classifier\n");
    load_rf_model(model_path);
    if (tree_count == 0) {
        CLASSIFIER_PERROR("Failed to initialize CJSON classifier: no trees loaded\n");
        return -1;
    }
    CLASSIFIER_PRINTF("CJSON classifier initialized successfully with %d trees\n", tree_count);
    return 0;
}

void classify_workload_cjson(MonitorData *data) {
    CLASSIFIER_PRINTF("cjson classify_workload_cjson\n");
    if (!model_loaded) {
        CLASSIFIER_PERROR("CJSON classifier not initialized\n");
        data->compute_prob_cjson = 1.0 / NUM_CLASSES;
        data->io_prob_cjson = 1.0 / NUM_CLASSES;
        data->memory_prob_cjson = 1.0 / NUM_CLASSES;
        return;
    }

    double features[NUM_FEATURES] = {
        (double)data->pthread_count, (double)data->pcore_count, (double)data->ecore_count,
        data->ratios.IPC, data->ratios.Cache_Miss_Ratio, data->ratios.Uop_per_Cycle,
        data->ratios.MemStallCycle_per_Mem_Inst, data->ratios.MemStallCycle_per_Inst,
        data->ratios.Fault_Rate_per_mem_instr, data->ratios.RChar_per_Cycle,
        data->ratios.WChar_per_Cycle, data->ratios.RBytes_per_Cycle, data->ratios.WBytes_per_Cycle
    };

    for (int i = 0; i < NUM_FEATURES; i++) {
        CLASSIFIER_PRINTF("Feature %d (%s): %.15lf\n", i, feature_names[i], features[i]);
    }

    double probs[NUM_CLASSES];
    int pred_class;
    predict_rf(features, probs, &pred_class);

    data->compute_prob_cjson = probs[0];
    data->io_prob_cjson = probs[1];
    data->memory_prob_cjson = probs[2];

    CLASSIFIER_PRINTF("\n--- Workload Classification (CJSON) ---\n");
    CLASSIFIER_PRINTF("  Predicted Class: %s\n", class_names[pred_class]);
    for (int c = 0; c < NUM_CLASSES; c++) {
        CLASSIFIER_PRINTF("  Prob_%s: %.15lf\n", class_names[c], probs[c]);
    }
}

void cleanup_classifier_cjson(void) {
    CLASSIFIER_PRINTF("cleanup_classifier_cjson\n");
    if (model_loaded) {
        for (int t = 0; t < tree_count; t++) {
            trees[t].node_count = 0;
            trees[t].root = 0;
        }
        tree_count = 0;
        model_loaded = 0;
        CLASSIFIER_PRINTF("CJSON classifier resources cleaned up\n");
    }
}
