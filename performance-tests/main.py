import argparse
from datetime import datetime, UTC
from enum import Enum
import json
import logging
from multiprocessing import Process
import os
import shlex
import signal
import subprocess
import time


logger = logging.getLogger(__name__)


# Metrics to be collected during the test
class Metric(Enum):
    # task-clock for fact process
    USER_SPACE_CPU = 'user_space_cpu'

    # heap allocations fact is doing
    USER_SPACE_MEM = 'user_space_mem'

    # average runtime of fact bpf programs
    KERNEL_SPACE_CPU = 'kernel_space_cpu'

    # amount of memory allocated for fact bpf maps
    KERNEL_SPACE_MEM = 'kernel_space_mem'


# Workloads to be applied during the test
class Workload(Enum):
    # write to monitored as well as ignored files, "real-world" scenario
    IGNORED_AND_MONITORED = 'ignored_and_monitored'

    # write only to monitored files, high load on event processing
    MONITORED = 'monitored'

    # write only to ignored files, overhead of fact staying on the way
    IGNORED = 'ignored'


def start_monitoring(args):
    def extract_cpu_usage(output):
        logger.debug("Extract CPU {}".format(output))

        data = json.loads(output)
        return data['run_time_ns'] / data['run_cnt']

    # identify if the bpf map, as returned by bpftool, belongs to fact
    def fact_map(data):
        logger.debug("Filter {}".format(data))

        if 'pids' not in data:
            return False

        return any((True
            for c in data['pids']
            if c['comm'] == 'fact'
        ))

    def extract_memory_usage(output):
        logger.debug("Extract Memory {}".format(output))

        data = json.loads(output)
        fact_maps = filter(fact_map, data)
        return sum(m['bytes_memlock'] for m in fact_maps)

    match args.metric:
        case Metric.KERNEL_SPACE_CPU:
            args_str = 'bpftool prog show name {} --json'.format(
                'trace_file_open'
            )
            proc_fn = extract_cpu_usage

        case Metric.KERNEL_SPACE_MEM:
            args_str = 'bpftool map --json'
            proc_fn = extract_memory_usage

        case Metric.USER_SPACE_CPU | Metric.USER_SPACE_MEM:
            # Monitoring for userspace is done via launching fact under the
            # monitoring tool, e.g. perf or valgrind. Hence it's noop here.
            return

    process_args = shlex.split(args_str)

    while True:
        logger.debug(f'Starting a process: {args_str}')
        p = subprocess.Popen(process_args, stdout=subprocess.PIPE)
        output, errors = p.communicate()

        if errors:
            logger.debug("Could not spin monitor: {}".format(errors))

        if not output:
            continue

        logger.debug("Monitor results: {}".format(output))

        with open('{}.data'.format(args.metric.value), 'a') as data:
            data.write("{}\n".format(proc_fn(output)))

        time.sleep(1)


def start_berserker(args):
    args_str = 'berserker -f {}/{}.ber'.format(
        args.workloads_path,
        args.workload.value
    )
    args = shlex.split(args_str)
    return subprocess.Popen(args)


def start_fact(args):
    """
    Spin up fact process, if needed wrapped into the monitoring tool, e.g.
    perf or valgrind.
    """
    def stop_perf(proc):
        # Somehow SIGINT is not propagated to perf, so just brutally stop fact to
        # trigger output.
        subprocess.Popen(['pkill', 'fact'])

        # Give it a moment to write the data. Perf will exit after the payload
        # process has finished.
        proc.wait()

    def stop_valgrind(proc):
        proc.terminate()
        proc.wait()

    def stop_fact(proc):
        proc.terminate()
        proc.wait()

    match args.metric:
        case Metric.USER_SPACE_CPU:
            args_str = 'perf stat -D {} -j -e {} -o {} -- fact {}'.format(
                5,
                'task-clock',
                'output.json',
                args.fact_cmdline
            )
            stop_fn = stop_perf

        case Metric.USER_SPACE_MEM:
            args_str = 'valgrind --tool=massif --massif-out-file={} fact {}'.format(
                'output.data',
                args.fact_cmdline
            )
            stop_fn = stop_valgrind

        case Metric.KERNEL_SPACE_CPU | Metric.KERNEL_SPACE_MEM:
            # Monitoring for kernel space is done via launching a monitoring
            # tool in parallel with fact. Hence it's noop here.
            args_str = 'fact {}'.format(args.fact_cmdline)
            stop_fn = stop_fact

    logger.debug(f'Starting a process: {args_str}')
    args = shlex.split(args_str)

    return subprocess.Popen(args, stdout=subprocess.DEVNULL), stop_fn


def get_version(args):
    """
	Get version of fact binary under the test. The assumption is that the
	output will be in format and sent to stderr:

	[INFO  2025-10-22T09:15:46Z] fact version: ...
	[INFO  2025-10-22T09:15:46Z] OS: ...
	[INFO  2025-10-22T09:15:46Z] Kernel version: ...
	[INFO  2025-10-22T09:15:46Z] Architecture: ...
	[INFO  2025-10-22T09:15:46Z] Hostname: ...
    """
    fact = subprocess.Popen(['fact'], stderr=subprocess.PIPE)
    output, errors = fact.communicate()

    logger.debug(f'Output of version command, {output}, {errors}')
    def version(line):
        if len(line) <= 3:
            return False

        return line[2] == b'fact' and line[3] == b'version:'

    def split(line):
        return line.split()

    output_list = map(split, errors.split(b'\n'))

    # filter will return a nested array, so unwrap it with next
    version_line = next(filter(version, output_list))

    if len(list(version_line)) <= 4:
        logger.error(f'No version line found, {output}')
        return ''

    return version_line[4]


def process_results(args):
    fact_version = get_version(args).decode('utf-8')

    match args.metric:
        case Metric.USER_SPACE_CPU:
            output = json.load(open('output.json', 'r'))

            return json.dumps([{
                'metric': args.metric.value,
                'workload': args.workload.value,
                'duration': args.duration,
                'timestamp': datetime.now(UTC).isoformat(),
                'value': output['metric-value'],
                'unit': output['metric-unit'],
                'version': fact_version,
            }])

        case Metric.USER_SPACE_MEM:
            def heap(line):
                return line.startswith('mem_heap_B')

            def get_heap_value(line):
                return int(line.split(sep='=')[1])

            heap_lines = filter(heap, open('output.data', 'r'))
            heap_values = list(map(get_heap_value, heap_lines))

            timestamp = datetime.now(UTC).isoformat()

            return json.dumps([{
                'metric': args.metric.value,
                'workload': args.workload.value,
                'duration': args.duration,
                'timestamp': timestamp,
                'value': heap_values,
                'unit': 'bytes',
                'version': fact_version,
            }])

        case Metric.KERNEL_SPACE_CPU:
            def convert(line):
                return float(line)

            data = open('{}.data'.format(args.metric.value), 'r')
            values = list(map(convert, data))
            timestamp = datetime.now(UTC).isoformat()

            return json.dumps([{
                'metric': args.metric.value,
                'workload': args.workload.value,
                'duration': args.duration,
                'timestamp': timestamp,
                'value': values,
                'unit': 'CPU utilization',
                'version': fact_version,
            }])

        case Metric.KERNEL_SPACE_MEM:
            def convert(line):
                return int(line)

            data = open('{}.data'.format(args.metric.value), 'r')
            values = list(map(convert, data))
            timestamp = datetime.now(UTC).isoformat()

            return json.dumps([{
                'metric': args.metric.value,
                'workload': args.workload.value,
                'duration': args.duration,
                'timestamp': timestamp,
                'value': values,
                'unit': 'bytes',
                'version': fact_version,
            }])


def main(args):
    logging.basicConfig(level=os.environ.get('LOGLEVEL', 'INFO').upper())

    fact, stop_fn = start_fact(args)
    berserker = start_berserker(args)
    monitor = Process(target=start_monitoring, args=(args,))
    monitor.start()

    time.sleep(args.duration)

    stop_fn(fact)

    berserker.terminate()
    monitor.terminate()

    with open(args.output_file, 'w') as f:
        logger.debug(f'Writing results to {args.output_file}')
        f.write(process_results(args))

    if not args.keep_traces:
        for trace in ('output.json', 'output.data'):
            try:
                os.unlink(trace)
            except FileNotFoundError:
                pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='performance-tests')
    parser.add_argument('metric', type=Metric, help='Metric to collect')
    parser.add_argument('workload', type=Workload, help='Berserker workload to apply')
    parser.add_argument('duration', type=int, help='Duration of the test')
    parser.add_argument('--fact-cmdline', required=False, help='How to invoke fact')
    parser.add_argument('--output-file', required=False, default='perf.json',
        help='File to store test results')
    parser.add_argument('--workloads-path', required=False, default='workloads',
        help='Where to find the workload descriptions')
    parser.add_argument('--keep-traces', required=False, default=False,
        help='Whether to keep intermediate files produced during the test')

    args = parser.parse_args()

    main(args)
