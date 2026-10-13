// memwriter: a guest program that rewrites its memory continuously in a
// known order, to check that a checkpoint of a running VM restores memory
// exactly as it was at the pause. Built static (musl) by scripts/faults.py
// and copied into the guest.
//
//   memwriter MIB_PER_THREAD THREADS STATUS_FILE
//
// Each thread owns N pages and a separate table of what it last wrote to
// each. Iteration k (from 1) rewrites page p(k) = k*S mod N (S coprime to N,
// so every page in turn): it first checks the page still holds what the
// table says it last wrote there, then writes a header (magic, thread, page,
// k, a random salt from RDRAND, a timestamp) and a body generated from
// (k, salt), then records (k, salt) in the table. Its state after iteration
// k is a function of k and the salts, all of it in memory or registers.
//
// A checkpoint pauses the VM at an arbitrary instruction; the restored copy
// carries on from there. Any page saved with contents from after the pause
// (or from before its last write before it) disagrees with the table, or the
// table with k: the restored writer finds it when it next comes to rewrite
// that page, before overwriting it (RDRAND makes the restored run write
// different contents than the original did after the pause), and a full
// check finds all of them.
//
// SIGUSR1: every thread, at its next iteration boundary (a quiesced instant
// for its pages), checks all its pages against the table and the table
// against its k, and checksums its memory; then STATUS_FILE is rewritten
// with each thread's k, error counts, first error, checksum and write
// latency histogram. SIGUSR2 resets the latency histograms.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
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
#define MAGIC 0x6d656d7772697465ULL
#define NBUCKETS 6  // <10us <100us <1ms <10ms <100ms >=100ms

struct header {
	uint64_t magic, thread, page, k, salt, ns;
};

struct meta {
	uint64_t k, salt;
};

struct stats {
	// continuous checks
	uint64_t errors, first_err_page, first_err_want, first_err_got;
	// full check results
	uint64_t full_errors, full_first, checksum, verified_k;
	// latency
	uint64_t hist[NBUCKETS], max_ns, iters;
};

struct worker {
	int id;
	uint64_t n, s, sinv;
	uint8_t *buf;
	struct meta *meta;
	uint64_t k;
	struct stats stats, snapshot;
	_Atomic uint64_t done_gen;
	_Atomic int reset;
	pthread_t th;
};

static struct worker *workers;
static int nthreads;
static _Atomic uint64_t want_gen;

static uint64_t now_ns(void) {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000000000ULL + t.tv_nsec;
}

__attribute__((target("rdrnd")))
static uint64_t rdrand(void) {
	unsigned long long v;
	for (int i = 0; i < 16; i++)
		if (__builtin_ia32_rdrand64_step(&v)) return v;
	return now_ns() * 0x9E3779B97F4A7C15ULL;
}

static void fill(uint64_t *w, uint64_t k, uint64_t salt, uint64_t page) {
	uint64_t x = (k * 0x9E3779B97F4A7C15ULL) ^ salt ^ (page << 32) ^ 1;
	for (size_t i = sizeof(struct header) / 8; i < PG / 8; i++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
		w[i] = x;
	}
}

// The last iteration <= k that wrote page p (0: none yet).
static uint64_t last_write(struct worker *w, uint64_t p, uint64_t k) {
	uint64_t base = (p * w->sinv) % w->n;  // first k with k*s = p mod n, as a residue
	if (base == 0) base = w->n;
	if (base > k) return 0;
	return base + (k - base) / w->n * w->n;
}

// Check both the record against the iteration and the page against the record.
static int page_ok(struct worker *w, uint64_t p) {
	uint64_t buf[PG / 8];
	struct header *h = (struct header *)(w->buf + p * PG);
	struct meta m = w->meta[p];
	if (m.k != last_write(w, p, w->k) || h->magic != MAGIC || h->thread != (uint64_t)w->id || h->page != p || h->k != m.k || h->salt != m.salt) return 0;
	fill(buf, m.k, m.salt, p);
	return memcmp((uint8_t *)h + sizeof *h, (uint8_t *)buf + sizeof *h, PG - sizeof *h) == 0;
}

static void write_page(struct worker *w, uint64_t p, uint64_t k, uint64_t salt) {
	uint64_t *pg = (uint64_t *)(w->buf + p * PG);
	fill(pg, k, salt, p);
	struct header h = {MAGIC, (uint64_t)w->id, p, k, salt, now_ns()};
	memcpy(pg, &h, sizeof h);
	w->meta[p] = (struct meta){k, salt};
}

static void full_check(struct worker *w) {
	uint64_t errors = 0, first = UINT64_MAX, sum = 0xcbf29ce484222325ULL;
	for (uint64_t p = 0; p < w->n; p++) {
		if (!page_ok(w, p)) {
			if (!errors) first = p;
			errors++;
		}
		uint64_t *pg = (uint64_t *)(w->buf + p * PG);
		for (size_t i = 0; i < PG / 8; i++) sum = (sum ^ pg[i]) * 0x100000001b3ULL;
	}
	w->stats.full_errors = errors;
	w->stats.full_first = first;
	w->stats.checksum = sum;
	w->stats.verified_k = w->k;
}

static uint64_t gcd(uint64_t a, uint64_t b) {
	while (b) {
		uint64_t t = a % b;
		a = b;
		b = t;
	}
	return a;
}

static uint64_t inverse(uint64_t s, uint64_t n) {
	__int128 t = 0, nt = 1, r = n, nr = s;
	while (nr) {
		__int128 q = r / nr, x;
		x = t - q * nt; t = nt; nt = x;
		x = r - q * nr; r = nr; nr = x;
	}
	return (uint64_t)(t < 0 ? t + n : t);
}

static void *run(void *arg) {
	struct worker *w = arg;
	for (uint64_t p = 0; p < w->n; p++) write_page(w, p, 0, 0);
	uint64_t last = now_ns();
	for (;;) {
		uint64_t g = atomic_load(&want_gen);
		if (g != atomic_load(&w->done_gen)) {
			full_check(w);
			// Publish immutable stats; main requests the next generation only
			// after finishing all reads of this snapshot.
			w->snapshot = w->stats;
			atomic_store(&w->done_gen, g);
			last = now_ns();
		}
		if (atomic_exchange(&w->reset, 0)) {
			memset(w->stats.hist, 0, sizeof w->stats.hist);
			w->stats.max_ns = 0;
			w->stats.iters = 0;
		}
		uint64_t k = w->k + 1;
		uint64_t p = (k % w->n) * w->s % w->n;
		if (!page_ok(w, p)) {
			if (!w->stats.errors) {
				w->stats.first_err_page = p;
				w->stats.first_err_want = last_write(w, p, w->k);
				w->stats.first_err_got = ((struct header *)(w->buf + p * PG))->k;
			}
			w->stats.errors++;
		}
		write_page(w, p, k, rdrand());
		w->k = k;
		uint64_t t = now_ns(), d = t - last;
		last = t;
		int b = d < 10000 ? 0 : d < 100000 ? 1 : d < 1000000 ? 2 : d < 10000000 ? 3 : d < 100000000 ? 4 : 5;
		w->stats.hist[b]++;
		if (d > w->stats.max_ns) w->stats.max_ns = d;
		w->stats.iters++;
	}
	return NULL;
}

int main(int argc, char **argv) {
	if (argc != 4) {
		fprintf(stderr, "usage: memwriter MIB_PER_THREAD THREADS STATUS_FILE\n");
		return 2;
	}
	uint64_t n = strtoull(argv[1], NULL, 10) * 256;
	nthreads = atoi(argv[2]);
	const char *status = argv[3];
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	workers = calloc(nthreads, sizeof *workers);
	for (int i = 0; i < nthreads; i++) {
		struct worker *w = &workers[i];
		w->id = i;
		w->n = n;
		w->s = 40503 % n ? 40503 % n : 1;
		while (gcd(w->s, n) != 1) w->s++;
		w->sinv = inverse(w->s, n);
		w->buf = mmap(NULL, n * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		w->meta = mmap(NULL, n * sizeof(struct meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		if (w->buf == MAP_FAILED || w->meta == MAP_FAILED) {
			perror("mmap");
			return 1;
		}
		pthread_create(&w->th, NULL, run, w);
	}
	char tmp[4096];
	snprintf(tmp, sizeof tmp, "%s.tmp", status);
	for (;;) {
		int sig;
		if (sigwait(&set, &sig)) continue;
		if (sig == SIGUSR2) {
			for (int i = 0; i < nthreads; i++) atomic_store(&workers[i].reset, 1);
			continue;
		}
		uint64_t g = atomic_fetch_add(&want_gen, 1) + 1;
		for (int i = 0; i < nthreads; i++)
			while (atomic_load(&workers[i].done_gen) != g) usleep(1000);
		FILE *f = fopen(tmp, "w");
		if (!f) continue;
		fprintf(f, "gen %llu threads %d pages %llu\n", (unsigned long long)g, nthreads, (unsigned long long)n);
		for (int i = 0; i < nthreads; i++) {
			const struct stats *w = &workers[i].snapshot;
			fprintf(f, "thread %d k %llu cont_errors %llu first %llu want %llu got %llu full_errors %llu full_first %lld checksum %016llx iters %llu",
			        i, (unsigned long long)w->verified_k, (unsigned long long)w->errors, (unsigned long long)w->first_err_page,
			        (unsigned long long)w->first_err_want, (unsigned long long)w->first_err_got, (unsigned long long)w->full_errors,
			        (long long)w->full_first, (unsigned long long)w->checksum, (unsigned long long)w->iters);
			fprintf(f, " max_us %llu hist", (unsigned long long)w->max_ns / 1000);
			for (int b = 0; b < NBUCKETS; b++) fprintf(f, " %llu", (unsigned long long)w->hist[b]);
			fprintf(f, "\n");
		}
		fclose(f);
		rename(tmp, status);
	}
}
