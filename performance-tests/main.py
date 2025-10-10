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
    match args.metric:
        case Metric.KERNEL_SPACE_CPU:
            args_str = 'bpftool prog show name {} --json | jq \'(.run_time_ns / .run_cnt)\''.format(
                'trace_file_open'
            )
        case Metric.KERNEL_SPACE_MEM:
            return

        case Metric.USER_SPACE_CPU | Metric.USER_SPACE_MEM:
            # Monitoring for userspace is done via launching fact under the
            # monitoring tool, e.g. perf or valgrind. Hence it's noop here.
            return

    args = shlex.split(args_str)
    with open('bpf.cpu.data', 'w+') as data:
        while True:
            p = subprocess.Popen(args, stdout=data)
            p.wait()
            time.sleep(1)


def start_berserker(args):
    args_str = 'berserker -f {}/{}.ber'.format(
        args.workloads_path,
        args.workload.value
    )
    args = shlex.split(args_str)
    return subprocess.Popen(args)


# Spin up fact process, if needed wrapped into the monitoring tool, e.g. perf
# or valgrind.
def start_fact(args):
    match args.metric:
        case Metric.USER_SPACE_CPU:
            args_str = 'perf stat -D {} -j -e {} -o {} -- fact {}'.format(
                5,
                'task-clock',
                'output.json',
                args.fact_cmdline
            )

        case Metric.USER_SPACE_MEM:
            return

        case Metric.KERNEL_SPACE_CPU | Metric.KERNEL_SPACE_MEM:
            # Monitoring for kernel space is done via launching a monitoring
            # tool in parallel with fact. Hence it's noop here.
            args_str = 'fact {}'.format(args.fact_cmdline)
            return

    logger.debug(f'Starting a process: {args_str}')
    args = shlex.split(args_str)

    return subprocess.Popen(args)


def process_results(args):
    match args.metric:
        case Metric.USER_SPACE_CPU:
            output = json.load(open('output.json', 'r'))

            return json.dumps({
                'metric': args.metric.value,
                'workload': args.workload.value,
                'duration': args.duration,
                'timestamp': datetime.now(UTC).isoformat(),
                'value': output['metric-value'],
                'unit': output['metric-unit'],
            })


def main(args):
    logging.basicConfig(level=os.environ.get('LOGLEVEL', 'INFO').upper())

    fact = start_fact(args)
    berserker = start_berserker(args)
    monitor = Process(target=start_monitoring, args=(args,))
    monitor.start()

    time.sleep(args.duration)

    # Somehow SIGINT is not propagated to perf, so just brutally stop fact to
    # trigger output.
    subprocess.Popen(['pkill', 'fact'])

    # Give it a moment to write the data.
    fact.wait()

    berserker.terminate()
    monitor.terminate()

    with open(args.output_file, 'w+') as f:
        logger.debug(f'Writing results to {args.output_file}')
        f.write(process_results(args))

    if not args.keep_traces:
        os.unlink('output.json')


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
