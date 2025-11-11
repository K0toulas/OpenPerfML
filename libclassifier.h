#ifndef LIBCLASSIFIER_H
#define LIBCLASSIFIER_H

#include "monitor.h"

#ifdef USE_CJSON

#ifdef USE_CJSON
#include "cJSON.h"
#endif
#ifdef USE_ONNX
#include <onnxruntime_c_api.h>
#endif
#endif
#ifdef USE_ONNX
#include <onnxruntime_c_api.h>
#endif

#define NUM_FEATURES 13
#define NUM_CLASSES 3

#define MODEL_PATH_CJSON "/srv/homes/ggantsios/eidiko/dynamic-library-interposition-for-monitoring/workload_classifier"
#define MODEL_PATH_CJSON_2STEP "/srv/homes/ggantsios/eidiko/dynamic-library-interposition-for-monitoring/workload_classifier"
#define MODEL_PATH_ONNX "/srv/homes/ggantsios/eidiko/dynamic-library-interposition-for-monitoring/workload_classifier"
#define MODEL_PATH_ONNX_2STEP "/srv/homes/ggantsios/eidiko/dynamic-library-interposition-for-monitoring/workload_classifier"

// CJSON classifier functions
int init_classifier_cjson(const char *model_path);
void classify_workload_cjson(MonitorData *data);
void cleanup_classifier_cjson(void);

// CJSON 2-step classifier functions
int init_classifier_cjson_2step(const char *model_path);
void classify_workload_cjson_2step(MonitorData *data);
void cleanup_classifier_cjson_2step(void);

// ONNX classifier functions
int init_classifier_onnx(const char *model_path);
void classify_workload_onnx(MonitorData *data);
void cleanup_classifier_onnx(void);

// ONNX 2-step classifier functions
int init_classifier_onnx_2step(const char *model_path);
void classify_workload_onnx_2step(MonitorData *data);
void cleanup_classifier_onnx_2step(void);

#endif