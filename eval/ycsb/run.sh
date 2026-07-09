#!/bin/bash
# Reduced YCSB-D validation for the ported pure-BPF policies.
set -eu -o pipefail

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	echo "Please switch to the cache_ext kernel and try again."
	exit 1
fi

SCRIPT_PATH=$(realpath "$0")
BASE_DIR=$(realpath "$(dirname "$SCRIPT_PATH")/../../")
BENCH_PATH="$BASE_DIR/bench"
POLICY_PATH="$BASE_DIR/policies"
YCSB_PATH="$BASE_DIR/My-YCSB"
DB_PATH=${DB_PATH:-/home/vishal/ebpf/cache_ext_dbs/leveldb}
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=${ITERATIONS:-1}
WARMUP_SECONDS=${WARMUP_SECONDS:-45}
RUNTIME_SECONDS=${RUNTIME_SECONDS:-240}
BENCHMARKS=${BENCHMARKS:-ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f}
RESULTS_FILE=${RESULTS_FILE:-$RESULTS_PATH/ycsb_d_ported_policies_240s.json}
CPU_COUNT=${CPU_COUNT:-8}
EXPECTED_ACTIVE_THREADS=${EXPECTED_ACTIVE_THREADS:-8}
CPU_MONITOR_GRACE_SECONDS=${CPU_MONITOR_GRACE_SECONDS:-20}
CPU_MONITOR_BAD_SECONDS=${CPU_MONITOR_BAD_SECONDS:-20}
BENCH_EXTRA_ARGS=()
if [[ "${NO_REUSE_RESULTS:-0}" == 1 ]]; then
	BENCH_EXTRA_ARGS+=(--no-reuse-results)
fi

if [[ -n "${POLICY_LIST:-}" ]]; then
	read -r -a POLICIES <<< "$POLICY_LIST"
else
	POLICIES=(
		"cache_ext_fifo"
		"cache_ext_s3fifo"
		"cache_ext_mru"
	)
fi

mkdir -p "$RESULTS_PATH"

if [[ ! -x "$YCSB_PATH/build/run_leveldb" ]]; then
	echo "Building run_leveldb..."
	mkdir -p "$YCSB_PATH/build"
	cmake -S "$YCSB_PATH" -B "$YCSB_PATH/build"
	cmake --build "$YCSB_PATH/build" --target run_leveldb -j"$(nproc)"
fi

echo "Building policy loaders..."
make -C "$POLICY_PATH" -j"$(nproc)" \
	cache_ext_fifo.out cache_ext_s3fifo.out cache_ext_mru.out

if [[ ! -d "$DB_PATH" ]]; then
	echo "LevelDB DB directory not found: $DB_PATH"
	exit 1
fi

monitor_cpu() {
	local policy="$1"
	local log_file="$2"
	local done_file="${3:-}"
	local max_cpu=0
	local max_active_threads=0
	local met_expected_threads=0
	local saw_process=0
	local observed_seconds=0
	local bad_seconds=0

	{
		echo "# policy=$policy"
		echo "# expected_active_threads=$EXPECTED_ACTIVE_THREADS"
		echo "# columns: epoch pid total_cpu active_threads per_thread_cpu"
	} > "$log_file"

	while true; do
		local pid
		pid=$(pgrep -n -x run_leveldb || true)
		if [[ -z "$pid" ]]; then
			if [[ "$saw_process" == 1 ]]; then
				break
			fi
			if [[ -n "$done_file" && -f "$done_file" ]]; then
				echo "# no run_leveldb observed before benchmark command completed" >> "$log_file"
				return 0
			fi
			sleep 1
			continue
		fi

		saw_process=1
		local sample
		sample=$(ps -L -p "$pid" -o pcpu=,tid=,stat= | awk '
			{
				cpu += $1;
				if ($1 >= 50.0 && $3 !~ /Z/) active++;
				per = per sprintf("%s:%s:%s ", $2, $1, $3);
			}
			END {
				if (NR == 0) {
					print "0 0 -";
				} else {
					printf "%.1f %d %s\n", cpu, active, per;
				}
			}')

		local total_cpu active_threads per_thread
		read -r total_cpu active_threads per_thread <<< "$sample"
		printf "%(%s)T %s %s %s %s\n" -1 "$pid" "$total_cpu" "$active_threads" "$per_thread" >> "$log_file"

		max_cpu=$(awk -v a="$max_cpu" -v b="$total_cpu" 'BEGIN { print (a > b) ? a : b }')
		if (( active_threads > max_active_threads )); then
			max_active_threads=$active_threads
		fi
		if (( active_threads >= EXPECTED_ACTIVE_THREADS )); then
			met_expected_threads=1
			bad_seconds=0
		fi
		observed_seconds=$((observed_seconds + 1))
		# if (( met_expected_threads == 0 && observed_seconds > CPU_MONITOR_GRACE_SECONDS )); then
		# 	if (( active_threads < EXPECTED_ACTIVE_THREADS )); then
		# 		bad_seconds=$((bad_seconds + 1))
		# 	else
		# 		bad_seconds=0
		# 	fi
		# 	if (( bad_seconds >= CPU_MONITOR_BAD_SECONDS )); then
		# 		echo "CPU monitor aborting $policy: only $active_threads active run_leveldb threads after ${bad_seconds}s below threshold" >&2
		# 		kill -INT "$pid" 2>/dev/null || true
		# 		sleep 2
		# 		kill -TERM "$pid" 2>/dev/null || true
		# 		return 1
		# 	fi
		# fi
		sleep 1
	done

	{
		echo "# max_total_cpu=$max_cpu"
		echo "# max_active_threads=$max_active_threads"
	} >> "$log_file"

	if [[ "$saw_process" != 1 ]]; then
		echo "CPU monitor did not observe run_leveldb for $policy" >&2
		return 1
	fi
	# if (( max_active_threads < EXPECTED_ACTIVE_THREADS )); then
	# 	echo "CPU monitor saw only $max_active_threads active run_leveldb threads for $policy; expected $EXPECTED_ACTIVE_THREADS" >&2
	# 	return 1
	# fi
}

if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

for POLICY in "${POLICIES[@]}"; do
	echo "Running policy: ${POLICY}"
	CPU_LOG="$RESULTS_PATH/ycsb_d_${POLICY}_cpu.log"
	CPU_DONE="$RESULTS_PATH/.${POLICY}.cpu_done.$$"
	rm -f "$CPU_DONE"
	monitor_cpu "$POLICY" "$CPU_LOG" "$CPU_DONE" &
	MONITOR_PID=$!

	set +e
	python3 "$BENCH_PATH/bench_leveldb.py" \
		--cpu "$CPU_COUNT" \
		--policy-loader "$POLICY_PATH/${POLICY}.out" \
		--results-file "$RESULTS_FILE" \
		--leveldb-db "$DB_PATH" \
		--fadvise-hints "" \
		--iterations "$ITERATIONS" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--benchmark "$BENCHMARKS" \
		--runtime-seconds "$RUNTIME_SECONDS" \
		--warmup-runtime-seconds "$WARMUP_SECONDS" \
		--cache-ext-only \
		"${BENCH_EXTRA_ARGS[@]}"
	BENCH_RC=$?
	touch "$CPU_DONE"
	if (( BENCH_RC != 0 )); then
		kill "$MONITOR_PID" 2>/dev/null || true
	fi
	wait "$MONITOR_PID"
	MONITOR_RC=$?
	rm -f "$CPU_DONE"
	set -e

	if (( BENCH_RC != 0 )); then
		echo "Benchmark failed for $POLICY with exit code $BENCH_RC"
		exit "$BENCH_RC"
	fi
	if (( MONITOR_RC != 0 )); then
		echo "CPU validation failed for $POLICY; see $CPU_LOG"
		exit "$MONITOR_RC"
	fi
done

if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "YCSB-D validation completed. Results saved to $RESULTS_PATH."
