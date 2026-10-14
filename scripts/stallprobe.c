// stallprobe: a guest program that measures how long the guest makes no
// progress, to see what a keep-running checkpoint's pause and the write
// faults after it cost the guest. Built static (musl) by scripts/faults.py
// and copied into the guest.
//
//   stallprobe KIB_PER_THREAD THREADS OUT
//
// Each thread is pinned to a CPU and spins: it reads CLOCK_MONOTONIC and
// writes a word into the next page of its own working set, in a stride that
// visits every page in turn but never two neighbours one after the other (as
// a guest's scattered writes do). Whenever the time between two iterations
// exceeds GAP_NS (an interrupt, a preemption, the pause, a write fault the
// host serves), it logs the gap's start and length. The pause shows as one
// long gap; write faults after it as many short ones.
//
// SIGUSR2 logs a marker (the host sends one before each checkpoint). SIGUSR1
// writes every marker and gap so far to OUT, as lines "m T" and
// "g THREAD START LEN" (ns, CLOCK_MONOTONIC), then "done".
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define PG 4096
#define GAP_NS 20000
#define RING (1 << 20)
#define MARKERS 4096

struct gap {
	uint64_t start, len;
};

struct worker {
	int id;
	uint64_t n, stride;
	uint8_t *buf;
	struct gap *gaps;
	_Atomic uint64_t ngaps;
	pthread_t th;
};

static uint64_t now_ns(void) {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000000000ULL + t.tv_nsec;
}

static uint64_t gcd(uint64_t a, uint64_t b) {
	while (b) {
		uint64_t t = a % b;
		a = b;
		b = t;
	}
	return a;
}

static void *run(void *arg) {
	struct worker *w = arg;
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(w->id % sysconf(_SC_NPROCESSORS_ONLN), &set);
	sched_setaffinity(0, sizeof set, &set);
	uint64_t last = now_ns(), p = 0, k = 0;
	for (;;) {
		uint64_t t = now_ns();
		if (t - last > GAP_NS) {
			uint64_t i = atomic_load_explicit(&w->ngaps, memory_order_relaxed);
			if (i < RING) {
				w->gaps[i] = (struct gap){last, t - last};
				atomic_store_explicit(&w->ngaps, i + 1, memory_order_release);
			}
		}
		last = t;
		((volatile uint64_t *)(w->buf + p * PG))[k & 511] = t;
		p += w->stride;
		if (p >= w->n) p -= w->n;
		k++;
	}
	return NULL;
}

int main(int argc, char **argv) {
	if (argc != 4) {
		fprintf(stderr, "usage: stallprobe KIB_PER_THREAD THREADS OUT\n");
		return 2;
	}
	uint64_t n = strtoull(argv[1], NULL, 10) * 1024 / PG;
	int threads = atoi(argv[2]);
	const char *out = argv[3];
	if (n < 2 || threads < 1) return 2;
	// Signals go to the main thread only.
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	// A stride coprime to n, far from 1 and from n - 1.
	uint64_t stride = n / 2 + 7;
	while (gcd(stride, n) != 1) stride++;
	struct worker *workers = calloc(threads, sizeof *workers);
	for (int i = 0; i < threads; i++) {
		struct worker *w = &workers[i];
		w->id = i;
		w->n = n;
		w->stride = stride % n;
		w->buf = mmap(NULL, n * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		w->gaps = mmap(NULL, RING * sizeof(struct gap), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		if (w->buf == MAP_FAILED || w->gaps == MAP_FAILED) return 1;
		memset(w->buf, 1, n * PG);
		pthread_create(&w->th, NULL, run, w);
	}
	static uint64_t markers[MARKERS];
	int nmarkers = 0;
	char tmp[4096];
	snprintf(tmp, sizeof tmp, "%s.tmp", out);
	for (;;) {
		int sig;
		if (sigwait(&set, &sig)) continue;
		if (sig == SIGUSR2) {
			if (nmarkers < MARKERS) markers[nmarkers++] = now_ns();
			continue;
		}
		FILE *f = fopen(tmp, "w");
		if (!f) continue;
		for (int i = 0; i < nmarkers; i++) fprintf(f, "m %llu\n", (unsigned long long)markers[i]);
		for (int i = 0; i < threads; i++) {
			struct worker *w = &workers[i];
			uint64_t m = atomic_load_explicit(&w->ngaps, memory_order_acquire);
			for (uint64_t j = 0; j < m; j++)
				fprintf(f, "g %d %llu %llu\n", i, (unsigned long long)w->gaps[j].start, (unsigned long long)w->gaps[j].len);
		}
		fprintf(f, "done\n");
		fclose(f);
		rename(tmp, out);
	}
}
