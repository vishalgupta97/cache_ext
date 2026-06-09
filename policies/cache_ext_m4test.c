#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cache_ext_m4test.skel.h"

struct cmdline_args {
	char *cgroup_path;
};

static struct argp_option options[] = {
	{ "cgroup_path", 'c', "PATH", 0, "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
	{ 0 },
};

static volatile sig_atomic_t exiting;

static void sig_handler(int signo) {
	exiting = 1;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'c':
		args->cgroup_path = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char **argv) {
	struct cmdline_args args = { 0 };
	struct cache_ext_m4test_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	struct sigaction sa;
	int cgroup_fd = -1;
	int ret = 1;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, &args);
	if (args.cgroup_path == NULL) {
		fprintf(stderr, "Missing required argument: cgroup_path\n");
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sig_handler;
	if (sigaction(SIGINT, &sa, NULL)) {
		perror("Failed to set up signal handling");
		return 1;
	}

	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	skel = cache_ext_m4test_bpf__open();
	if (!skel) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	if (cache_ext_m4test_bpf__load(skel)) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	link = bpf_map__attach_cache_ext_ops(skel->maps.m4test_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		goto cleanup;
	}

	printf("Attached. Polling BPF valid_folios_lookup counters (Ctrl-C to exit)...\n");
	while (!exiting) {
		printf("lookup: total=%llu found=%llu match=%llu miss=%llu | list: adds=%llu count=%llu\n",
		       (unsigned long long)skel->bss->lookup_total,
		       (unsigned long long)skel->bss->lookup_found,
		       (unsigned long long)skel->bss->lookup_match,
		       (unsigned long long)skel->bss->lookup_miss,
		       (unsigned long long)skel->bss->list_adds,
		       (unsigned long long)skel->bss->list_count);
		fflush(stdout);
		sleep(1);
	}
	ret = 0;

cleanup:
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_m4test_bpf__destroy(skel);
	return ret;
}
