# OpenPerfML
**Cross Platform Performance Feature Extraction Toolkit for Machine & Deep Learning**

OpenPerfML is an **open-source C-based toolkit** designed to monitor, classify and extract low level system performance metrics across diverse platforms.  
It empowers the research and developer community to collect fine grained performance features for **machine learning, deep learning and systems analytics**.

> **NOTE:** This project is currently under active development and will be updated periodically.

---

## What It Does
OpenPerfML provides the building blocks for analyzing and classifying system-level performance data.  
It enables feature collection and can be extended to feed machine learning pipelines, rule-based systems, monitoring dashboards and much more (to be announced).

### Example Use Cases
- Collecting compute, memory, and I/O traces for **ML model optimization**.  
- Monitoring performance features for **MLOps observability** and system health tracking.  
- Providing datasets for **anomaly detection** or **intelligent resource management**.  
- Implementing **rule-based inference systems** or lightweight **embedded ML analyzers**.  

---

## Key Features
- **Written in C**.  
- **Modular architecture:**
  - `libmonitor.c/h`: platform monitoring and metric collection.  
  - `libclassifier.c/h`: feature classification and labeling logic.  
- **Cross platform support:** Linux, macOS and embedded environments (IoT-friendly).  
- **Future ready design:** planned Python bindings for data science workflows (will be added in the near future).  
- **Open-source**, extensible and research driven by design.  
  **Feel free to use it as you like.**  

---

## Vision
OpenPerfML is the foundation of a broader open source initiative focused on:
- Enabling **hardware aware optimization** for ML and AI workloads.  
- Democratizing **cross-platform performance profiling** tools.  
- Building an ecosystem for **real time performance feature extraction** in academic and industrial research.

---

## Dependencies
- **GCC** or any C99-compatible compiler   
- **Standard C library** (`libc`)  
- **Math library** (`libm`) — linked with `-lm`  

Optional (for future Python bindings):
- Python 3.x  
- `ctypes` or `cffi` (for interfacing with C libraries)

---

## Build & Run
```bash
gcc -o monitor libmonitor.c libclassifier.c -lm
./monitor
