import subprocess
from math import ceil
from os.path import basename, join, splitext
from time import sleep

from benchmark.commands import CommandMaker
from benchmark.config import Key, TSSKey, LocalCommittee, NodeParameters, BenchParameters, ConfigError
from benchmark.logs import LogParser, ParseError
from benchmark.utils import Print, BenchError, PathMaker


class LocalBench:
    BASE_PORT = 10000

    def __init__(self, bench_parameters_dict, node_parameters_dict):
        try:
            self.bench_parameters = BenchParameters(bench_parameters_dict)
            self.node_parameters = NodeParameters(node_parameters_dict)
        except ConfigError as e:
            raise BenchError('Invalid nodes or bench parameters', e)

    def __getattr__(self, attr):
        return getattr(self.bench_parameters, attr)

    def _background_run(self, command, log_file):
        name = splitext(basename(log_file))[0]
        cmd = f'{command} 2> {log_file}'
        subprocess.run(['tmux', 'new', '-d', '-s', name, cmd], check=True)

    def _kill_nodes(self):
        try:
            cmd = CommandMaker.kill().split()
            subprocess.run(cmd, stderr=subprocess.DEVNULL)
        except subprocess.SubprocessError as e:
            raise BenchError('Failed to kill testbed', e)

    def run(self, debug=False):
        assert isinstance(debug, bool)
        Print.heading('Starting local benchmark')

        # Kill any previous testbed.
        self._kill_nodes()

        try:
            Print.info('Setting up testbed...')
            nodes, rate = self.nodes[0], self.rate[0]

            # Cleanup all files.
            cmd = f'{CommandMaker.clean_logs()} ; {CommandMaker.cleanup()}'
            subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)
            sleep(0.5) # Removing the store may take time.

            # Recompile the latest code.
            cmd = CommandMaker.compile().split()
            subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

            # Create alias for the client and nodes binary.
            cmd = CommandMaker.alias_binaries(PathMaker.binary_path())
            subprocess.run([cmd], shell=True)

            # Generate configuration files.
            keys = []
            key_files = [PathMaker.key_file(i) for i in range(nodes)]
            for filename in key_files:
                cmd = CommandMaker.generate_key(filename).split()
                subprocess.run(cmd, check=True)
                keys += [Key.from_file(filename)]

            # Generate threshold signature files.
            cmd = './node threshold_keys'
            for i in range(nodes):
                cmd += ' --filename ' + PathMaker.threshold_key_file(i)
            # print(cmd)
            cmd = cmd.split()
            subprocess.run(cmd, capture_output=True, check=True)

            names = [x.name for x in keys]
            tss_keys = []
            for i in range(nodes):
                tss_keys += [TSSKey.from_file(PathMaker.threshold_key_file(i))]
            ids = [x.id for x in tss_keys]
            committee = LocalCommittee(names, ids, self.BASE_PORT)
            committee.print(PathMaker.committee_file())

            self.node_parameters.print(PathMaker.parameters_file())

            # Do not boot faulty nodes.
            nodes = nodes - self.faults

            # Run the clients (they will wait for the nodes to be ready).
            addresses = committee.front
            rate_share = ceil(rate / nodes)
            timeout = self.node_parameters.timeout_delay
            synctime = self.node_parameters.node_sync_time
            client_logs = [PathMaker.client_log_file(i) for i in range(nodes)]
            for addr, log_file in zip(addresses, client_logs):
                cmd = CommandMaker.run_client(
                    addr,
                    self.tx_size,
                    rate_share,
                    timeout,
                    synctime
                )
                self._background_run(cmd, log_file)
            
            if self.node_parameters.protocol == 0:
                Print.info('Running HotStuff')
            elif self.node_parameters.protocol == 1:
                Print.info('Running Ipotane')
            elif self.node_parameters.protocol == 2:
                Print.info('Running SMVBA')
            else:
                Print.info('Wrong protocol type!')
                return

            Print.info(f'{self.faults} faults')
            Print.info(f'Timeout {self.node_parameters.timeout_delay} ms, Network delay {self.node_parameters.network_delay} ms')
            Print.info(f'DDOS attack {self.node_parameters.ddos}')

            # Run the nodes.
            dbs = [PathMaker.db_path(i) for i in range(nodes)]
            node_logs = [PathMaker.node_log_file(i) for i in range(nodes)]
            threshold_key_files = [PathMaker.threshold_key_file(i) for i in range(nodes)]
            for key_file, threshold_key_file, db, log_file in zip(key_files, threshold_key_files, dbs, node_logs):
                cmd = CommandMaker.run_node(
                    key_file,
                    threshold_key_file,
                    PathMaker.committee_file(),
                    db,
                    PathMaker.parameters_file(),
                    debug=debug
                )
                self._background_run(cmd, log_file)

            # Wait for the nodes to synchronize
            Print.info('Waiting for the nodes to synchronize...')
            sleep(2*self.node_parameters.node_sync_time/1000)

            # Wait for all transactions to be processed.
            Print.info(f'Running benchmark ({self.duration} sec)...')
            sleep(self.duration)
            self._kill_nodes()

            # Parse logs and return the parser.
            Print.info('Parsing logs...')
            return LogParser.process('./logs', self.faults, self.node_parameters.protocol, self.node_parameters.ddos)

        except (subprocess.SubprocessError, ParseError) as e:
            self._kill_nodes()
            raise BenchError('Failed to run benchmark', e)
