// test_workload.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sched.h>
#include <unistd.h>

void high_miss_test(void) {
    size_t N = (size_t)512 * 1024 * 1024 / sizeof(int);
    int *a = malloc(N * sizeof(int));
    if (!a) {
        perror("malloc");
        return;
    }

    for (size_t i = 0; i < N; i++)
        a[i] = (int)i;

    volatile long long sum = 0;
    size_t stride = 64 / sizeof(int);  

    for (int pass = 0; pass < 100; pass++) {   
        for (size_t i = 0; i < N; i += stride) {
            sum += a[i];
        }
    }

    if (sum == -1) {
        printf("sum=%lld\n", sum);
    }

    free(a);
}

int main(int argc, char **argv) {
    int cpu;

    if (argc > 1) {
        cpu = atoi(argv[1]);
    } else {
        cpu = sched_getcpu();
    }

    if (cpu < 0) {
        perror("sched_getcpu");
        return 1;
    }

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        perror("sched_setaffinity");
        return 1;
    }

    printf("Pinned to CPU %d\n", cpu);
    printf("Running high-miss workload...\n");

    high_miss_test();

    printf("Done.\n");
    return 0;
}