// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_KPROBE

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "policy_filter.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

/* 
 * Forward declarations: the kprobe_calls prog array below references
 * these programs before they are defined.
 */
int generic_kprobe_setup_event(void *ctx);
int generic_kprobe_process_event(void *ctx);
int generic_kprobe_process_event_2(void *ctx);
int generic_kprobe_process_filter(void *ctx);
int generic_kprobe_process_filter_2(void *ctx);
int generic_kprobe_filter_arg(void *ctx);
int generic_kprobe_filter_arg_2(void *ctx);
int generic_kprobe_actions(void *ctx);
int generic_kprobe_output(void *ctx);
int generic_kprobe_path(void *ctx);

/*
 * Jump table for bpf_tail_call(). Each TAIL_CALL_* index maps to one of
 * the stages of the generic kprobe pipeline (see the overview below).
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__type(key, __u32);
	__array(values, int(void *));
} kprobe_calls SEC(".maps") = {
	.values = {
		[TAIL_CALL_SETUP] = (void *)&generic_kprobe_setup_event,
		[TAIL_CALL_PROCESS] = (void *)&generic_kprobe_process_event,
		[TAIL_CALL_FILTER] = (void *)&generic_kprobe_process_filter,
		[TAIL_CALL_FILTER_2] = (void *)&generic_kprobe_process_filter_2,
		[TAIL_CALL_ARGS] = (void *)&generic_kprobe_filter_arg,
		[TAIL_CALL_ACTIONS] = (void *)&generic_kprobe_actions,
		[TAIL_CALL_SEND] = (void *)&generic_kprobe_output,
#ifndef __V61_BPF_PROG
		[TAIL_CALL_PATH] = (void *)&generic_kprobe_path,
#endif
#ifndef __LARGE_BPF_PROG
		[TAIL_CALL_PROCESS_2] = (void *)&generic_kprobe_process_event_2,
		[TAIL_CALL_ARGS_2] = (void *)&generic_kprobe_filter_arg_2,
#endif
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

/*
 * Section names. MAIN is the only program attached to the hooked
 * function; COMMON programs are only loaded and reached via tail calls.
 * OVERRIDE is the kprobe used for error injection.
 */
#ifdef __MULTI_KPROBE
#define MAIN	 "kprobe.multi/generic_kprobe"
#define OVERRIDE "kprobe.multi/generic_kprobe_override"
#define COMMON	 "kprobe.multi"
#else
#define MAIN	 "kprobe/generic_kprobe"
#define OVERRIDE "kprobe/generic_kprobe_override"
#define COMMON	 "kprobe"
#endif

/* Generic kprobe pseudocode is the following
 *
 *  filter_pids -> drop if no matches
 *  filter_namespaces -> drop if no matches
 *  filter_capabilities -> drop if no matches
 *  filter_namespace_changes -> drop if no matches
 *  filter_capability_changes -> drop if no matches
 *  copy arguments buffer
 *  filter selectors -> drop if no matches
 *  generate ring buffer event
 *
 * First we filter by pids this allows us to quickly drop events
 * that are not relevant. This is helpful if we end up copying
 * large string values.
 *
 * Then we copy arguments then run full selectors logic. We keep
 * track of pids that passed initial filter so we avoid running
 * pid filters twice.
 *
 * For 4.19 kernels we have to use the tail call infrastructure
 * to get below 4k insns. For 5.x+ kernels with 1m.insns its not
 * an issue.
*/

/*
 * Pipeline overview, in execution order (each stage tail-calls the next):
 *
 *  0. generic_kprobe_event         MAIN    entry point on the hooked function,
 *                                          cheap pid/namespace/capability filters
 *  1. generic_kprobe_process_filter(_2)    COMMON  remaining filter stages
 *  2. generic_kprobe_setup_event   COMMON  allocate the event buffer
 *  3. generic_kprobe_process_event(_2)     COMMON  copy the arguments
 *  4. generic_kprobe_filter_arg(_2)        COMMON  selectors on argument values
 *  5. generic_kprobe_actions       COMMON  run the configured actions
 *  6. generic_kprobe_path          COMMON  resolve path arguments
 *  7. generic_kprobe_output        COMMON  push the event to the ring buffer
 *
 * The (_2) variants exist only without __LARGE_BPF_PROG, to split the work
 * under the instruction limit of older kernels.
 */

/**
* SAME AS :
*
* SEC(MAIN)
* int generic_kprobe_event(struct pt_regs *ctx)
*/
/*
 * stage 0: entry point on every hooked function. Filters first so that
 * irrelevant calls cost as little as possible.
 */
__attribute__((section((MAIN)), used)) int
generic_kprobe_event(struct pt_regs *ctx)
{
	return generic_start_process_filter(ctx, (struct bpf_map_def *)&kprobe_calls);
}

/*
 * stage 2: allocate the event buffer. Only reached once the event passed the filters,
 * so no buffer is spent on dropped calls.
 */
__attribute__((section(COMMON), used)) int
generic_kprobe_setup_event(void *ctx)
{
	return generic_process_event_and_setup(ctx, (struct bpf_map_def *)&kprobe_calls);
}

/*
 * stage 3: copy all arguments at once. Only fits in the large prog budget.
 */
#ifdef __LARGE_BPF_PROG
__attribute__((section(COMMON), used)) int
generic_kprobe_process_event(void *ctx)
{
	return generic_process_event(ctx, (struct bpf_map_def *)&kprobe_calls, __READ_ARG_ALL);
}
#else
/*
 * stage 3: first half of the arguments. Split in two to stay under the
 * instruction limit of older kernels.
 */
__attribute__((section(COMMON), used)) int
generic_kprobe_process_event(void *ctx)
{
	return generic_process_event(ctx, (struct bpf_map_def *)&kprobe_calls, __READ_ARG_1);
}

/*
 * stage 3: second half of the arguments, see generic_kprobe_process_event.
 */
__attribute__((section(COMMON), used)) int
generic_kprobe_process_event_2(void *ctx)
{
	return generic_process_event(ctx, (struct bpf_map_def *)&kprobe_calls, __READ_ARG_2);
}
#endif

/*
 * stage 1: first filter pass. Fail drops the event, pass goes to the second pass.
 */
__attribute__((section(COMMON), used)) int
generic_kprobe_process_filter(void *ctx)
{
	return generic_process_filter_stage(ctx, GENERIC_FILTER_STAGE_1,
					    TAIL_CALL_FILTER, /* fail */
					    TAIL_CALL_FILTER_2, /* pass */
					    (struct bpf_map_def *)&kprobe_calls);
}

/*
 * stage 1, second pass: fail drops the event, pass goes to setup.
 */
__attribute__((section(COMMON), used)) int
generic_kprobe_process_filter_2(void *ctx)
{
	return generic_process_filter_stage(ctx, GENERIC_FILTER_STAGE_2,
					    TAIL_CALL_FILTER, /* fail */
					    TAIL_CALL_SETUP, /* pass */
					    (struct bpf_map_def *)&kprobe_calls);
}

/*
 * stage 4: argument selectors. Drops the event early when no selector matches.
 */
#ifdef __LARGE_BPF_PROG
__attribute__((section(COMMON), used)) int
generic_kprobe_filter_arg(void *ctx)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&kprobe_calls, true, __FILTER_ARG_ALL);
}
#else
__attribute__((section(COMMON), used)) int
generic_kprobe_filter_arg(void *ctx)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&kprobe_calls, true, __FILTER_ARG_1);
}

__attribute__((section(COMMON), used)) int
generic_kprobe_filter_arg_2(void *ctx)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&kprobe_calls, true, __FILTER_ARG_2);
}
#endif

/*
 * stage 5: run the actions of the matched policy, before the event is sent.
 */
__attribute__((section(COMMON), used)) int
generic_kprobe_actions(void *ctx)
{
	generic_actions(ctx, (struct bpf_map_def *)&kprobe_calls);
	return 0;
}

/*
 * stage 7: push the event to userspace through the ring buffer.
 */
__attribute__((section(COMMON), used)) int
generic_kprobe_output(void *ctx)
{
	return generic_output(ctx, MSG_OP_GENERIC_KPROBE);
}

/*
 * stage 6: resolve path arguments. Left out on __V61_BPF_PROG kernels.
 */
#ifndef __V61_BPF_PROG
__attribute__((section(COMMON), used)) int
generic_kprobe_path(void *ctx)
{
	return generic_path(ctx, (struct bpf_map_def *)&kprobe_calls);
}
#endif

/*
 * error injection, outside the event pipeline. Forces the hooked function
 * to return the stored error for tasks listed in override_tasks.
 */
__attribute__((section(OVERRIDE), used)) int
generic_kprobe_override(void *ctx)
{
	__u64 id = get_current_pid_tgid();
	__s32 *error;

	error = map_lookup_elem(&override_tasks, &id);
	if (!error)
		return 0;

	override_return(ctx, *error);
	map_delete_elem(&override_tasks, &id);
	return 0;
}

/*
 * same logic as generic_kprobe_override, as fmod_ret. Only here so that
 * contrib/verify/verify.sh finds security_task_prctl: tetragon sets the real one at runtime.
 */
__attribute__((section("fmod_ret/security_task_prctl"), used)) long
generic_fmodret_override(void *ctx)
{
	__u64 id = get_current_pid_tgid();
	__s32 *error;

	error = map_lookup_elem(&override_tasks, &id);
	if (!error)
		return 0;

	map_delete_elem(&override_tasks, &id);
	return (long)*error;
}
