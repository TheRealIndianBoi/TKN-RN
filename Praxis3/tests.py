import docker
import queue
import ipaddress
import time
import logging

from ..common import exec_async, which, ExecAsyncHandler, TKNTestCase, run_tests
from ..node import DockerThread
from ..packet import DataPacket, ControlPacket, NullPacket, Packet
from ..mock import MockServer, MockClient, GeneralPktHandler, ControlPktHandler

import subprocess

ASSIGNMENT = 'Abgabe Block 6'

docker_cli = None
container_network = None
container_peer, container_mock = None, None


def collect_trace(handlers: [ExecAsyncHandler]):
    traces = []

    for i, h in enumerate(handlers):
        status, out, err = h.collect()
        traces.append(f'Stdout{i}: {out} // Stderr{i}: {err}')

    return ' '.join(traces)


def pseudo_hash(key: bytes):
    if len(key) >= 2:
        return int.from_bytes(key[0:2], 'big')
    elif len(key) == 0:
        return 0
    else:
        return key[0] << 8


class JoinAndFTTestCase(TKNTestCase):
    expected_files = ['peer']

    @classmethod
    def setUpClass(cls):
        super().setUpClass()  # Check binaries
        global docker_cli, container_network, container_peer, container_mock
        docker_cli = docker.from_env()
        container_peer = docker_cli.containers.get('hash-peer')
        container_mock = docker_cli.containers.get('mock-peer')

    def setUp(self):
        container_peer.stop(timeout=1)
        container_peer.restart(timeout=1)
        container_peer.reload()
        self.container_peer_ip = container_peer.attrs['NetworkSettings']['Networks']['testnet']['IPAddress']

        container_mock.reload()
        self.container_mock_ip = container_mock.attrs['NetworkSettings']['Networks']['testnet']['IPAddress']

    def start_peer(self, port, handler):
        """ Starts a peer running in the network namespace on the mock container
        :return: A tuple of the created DockerThread as well as a reference to the server instance
        :rtype: tuple(DockerThread, MockServer)
        """
        q = queue.Queue()

        def run_peer():
            p = MockServer(('0.0.0.0', port), handler)
            q.put(p)
            p.serve_forever()

        peer_thread = DockerThread(container_mock, target=run_peer)
        peer_thread.start()
        self.addCleanup(peer_thread.join)

        try:
            peer: MockServer = q.get(timeout=5)
            self.addCleanup(peer.server_close)
            self.addCleanup(peer.shutdown)
        except queue.Empty:
            raise RuntimeError("Could not setup mock peer. This should not happen!") from None

        return peer_thread, peer

    def start_client(self, packet: Packet, port=1400):
        c = MockClient(packet, port=port)

        client_thread = DockerThread(container_mock, target=c.run)
        client_thread.start()
        self.addCleanup(c.stop)

        resolved = c.resolvedName.wait(3.0)
        if not resolved:
            raise RuntimeError("Failed to resolve hostname! This should not happen!")

        connected = c.clientConnected.wait(3.0)
        if not connected:
            raise AssertionError(f"Could not connect to peer on port {port}")

        return c

    def start_student_peer(self, port: int, node_id, anchor_ip=None, anchor_port=None):
        peer_path = which(self.path, 'peer')
        ip = self.container_peer_ip

        if anchor_port is not None and anchor_ip is not None:
            handler: ExecAsyncHandler = exec_async(container_peer,
                                                   [f'{peer_path}', f'{ip}', f'{port}', f'{node_id}',
                                                    f'{anchor_ip}', f'{anchor_port}'])
        elif node_id is not None:
            handler: ExecAsyncHandler = exec_async(container_peer,
                                                   [f'{peer_path}', f'{ip}', f'{port}', f'{node_id}'])
        else:
            handler: ExecAsyncHandler = exec_async(container_peer,
                                                   [f'{peer_path}', f'{ip}', f'{port}'])

        return handler

    def setup_student_ring(self, node_ids, port_base=4000, ignore_first_id=False):
        handlers = []
        ports = []
        ip = self.container_peer_ip
        for i, node_id in enumerate(node_ids):
            ports.append(port_base + i)
            if i == 0 and not ignore_first_id:
                handlers.append(self.start_student_peer(port_base, node_id))
            elif i == 0 and ignore_first_id:
                handlers.append(self.start_student_peer(port_base, None))
            else:
                handlers.append(self.start_student_peer(port_base + i, node_id, ip, port_base))

        return handlers, ports

    def test_trigger_join_minimal(self):
        node_id = 42
        anchor_thread, anchor = self.start_peer(1400, ControlPktHandler)
        handler = self.start_student_peer(1400, node_id, self.container_mock_ip, 1400)

        join_pkt: ControlPacket = anchor.await_packet(ControlPacket, 2.0)
        if join_pkt is None:
            status, out, err = handler.collect()
            self.fail(f"Did not receive a JOIN msg within timeout! Stdout: {out}, Stderr:{err}")

    def test_join_correct(self):
        node_id = 42
        node_port = 2000
        anchor_thread, anchor = self.start_peer(1400, ControlPktHandler)
        handler = self.start_student_peer(node_port, node_id, self.container_mock_ip, 1400)

        join_pkt: ControlPacket = anchor.await_packet(ControlPacket, 2.0)
        if join_pkt is None:
            status, out, err = handler.collect()
            self.fail(f"Did not receive a JOIN msg within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(join_pkt.method, 'JOIN')
        self.assertEqual(join_pkt.node_id, node_id, msg="Peer sent wrong node id in JOIN msg.")
        self.assertEqual(join_pkt.ip, ipaddress.IPv4Address(self.container_peer_ip),
                         msg=f"Peer sent wrong ip in JOIN msg. Raw packet: {join_pkt.raw}")
        self.assertEqual(join_pkt.port, node_port, msg="Peer sent wrong port in JOIN msg.")

    def test_full_join_student(self):
        node_id = 42
        node_port = 2000

        succ_id = 100
        succ_ip = ipaddress.IPv4Address(self.container_mock_ip)
        succ_port = 1400

        pre_id = 10
        pre_ip = ipaddress.IPv4Address(self.container_mock_ip)
        pre_port = 1401

        anchor_thread, anchor = self.start_peer(1400, GeneralPktHandler)
        anchor.send_response = True
        notify = ControlPacket('NOTIFY', 0, succ_id, succ_ip, succ_port)
        anchor.resp_q.put((notify, self.container_peer_ip, node_port))

        handler = self.start_student_peer(node_port, node_id, self.container_mock_ip, 1400)

        join_pkt: ControlPacket = anchor.await_packet(ControlPacket, 2.0)
        if join_pkt is None:
            status, out, err = handler.collect()
            self.fail(f"Did not receive a JOIN msg within timeout! Stdout: {out}, Stderr:{err}")

        stabilize = ControlPacket('STABILIZE', 0, pre_id, pre_ip, pre_port)
        pre = self.start_client(stabilize, port=node_port)

        try:
            notify2 = pre.await_packet(2.5)
            if notify2 is None:
                status, out, err = handler.collect()
                self.fail(
                    f"Did not receive a NOTIFY response for stabilize msg within timeout! Stdout: {out}, Stderr:{err}")

        except AssertionError:
            raise AssertionError(
                'Peer closed connection after STABILIZE! Either it crashed or it tries to send NOTIFY in a separate connection! In the second case: This is stupid but might still be valid.')

        self.assertEqual(notify2.method, 'NOTIFY')

        stabilize2 = anchor.await_packet(ControlPacket, 5.0)
        if stabilize2 is None:
            status, out, err = handler.collect()
            self.fail(
                f"Did not receive a STABILIZE within timeout after JOIN! Stdout: {out}, Stderr:{err}")

        self.assertEqual(stabilize2.method, "STABILIZE")

        lookup1 = ControlPacket('LOOKUP', pre_id - 5, 9999, pre_ip, pre_port)  # Should be forwarded
        c1 = self.start_client(lookup1, port=node_port)

        forwarded_l: ControlPacket = anchor.await_packet(ControlPacket, 2.0)
        if not forwarded_l:
            status, out, err = handler.collect()
            self.fail(
                f"Peer did not forward lookup to succ within timeout! JOIN might not be completed. Stdout: {out}, Stderr:{err}")

        self.assertEqual(forwarded_l.method, 'LOOKUP',
                         msg=f"Expected LOOKUP but got {forwarded_l.method} instead. Is the peer spamming STABILIZE? ")

        lookup2 = ControlPacket('LOOKUP', succ_id - 1, 9999, succ_ip, succ_port)  # Should not be forwarded
        c2 = self.start_client(lookup2, port=node_port)

        reply: ControlPacket = anchor.await_packet(ControlPacket, 2.0)
        if not reply:
            status, out, err = handler.collect()
            self.fail(
                f"Peer did not reply to lookup within timeout! JOIN might not be completed. Stdout: {out}, Stderr:{err}")

        self.assertEqual(reply.method, 'REPLY')
        self.assertEqual(reply.node_id, succ_id)

    def test_initial_ring(self):
        node_id = 42
        node_port = 2000
        handler = self.start_student_peer(node_port, node_id)

        other_id = 123
        other_ip = ipaddress.IPv4Address(self.container_mock_ip)
        other_port = 1400
        _, other_peer = self.start_peer(other_port, GeneralPktHandler)

        join = ControlPacket('JOIN', 0, other_id, other_ip, other_port)
        c1 = self.start_client(join, port=node_port)

        notify: ControlPacket = other_peer.await_packet(ControlPacket, 2.0)
        if not notify:
            status, out, err = handler.collect()
            self.fail(
                f"Peer did not reply to JOIN within timeout! Expected NOTIFY. Stdout: {out}, Stderr:{err}")

        self.assertEqual(notify.method, 'NOTIFY')
        self.assertEqual(notify.node_id, node_id)
        self.assertEqual(notify.ip, ipaddress.IPv4Address(self.container_peer_ip))
        self.assertEqual(notify.port, node_port)

        stabilize: ControlPacket = other_peer.await_packet(ControlPacket, 2.5)
        if not stabilize:
            status, out, err = handler.collect()
            self.fail(
                f"Peer did not send STABILIZE within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(stabilize.method, 'STABILIZE')
        self.assertEqual(stabilize.node_id, node_id)

    def test_join_mock_peer(self):
        log = logging.getLogger(__name__)
        node1_id = 100
        node1_port = 2000
        node1_ip = ipaddress.IPv4Address(self.container_peer_ip)

        node2_id = 200
        node2_port = 2001
        node2_ip = ipaddress.IPv4Address(self.container_peer_ip)

        mock_id = 150
        mock_port = 1400
        mock_ip = ipaddress.IPv4Address(self.container_mock_ip)

        handler1 = self.start_student_peer(node1_port, node1_id)
        handler2 = self.start_student_peer(node2_port, node2_id, node1_ip, node1_port)

        _, mock = self.start_peer(mock_port, GeneralPktHandler)
        mock.send_response = True
        mock.resp_q.put(NullPacket())  # Do not respond to notify

        join = ControlPacket('JOIN', 0, mock_id, mock_ip, mock_port)
        c1 = self.start_client(join, port=node1_port)

        notify: ControlPacket = mock.await_packet(ControlPacket, 2.5)
        if not notify:
            _, out1, err1 = handler1.collect()
            _, out2, err2 = handler2.collect()
            self.fail(
                f"Peer did not reply to JOIN within timeout! Expected NOTIFY. Stdout1: {out1}, Stderr1:{err1}, Stdout2: {out2}, Stderr2:{err2}")

        self.assertEqual(notify.method, 'NOTIFY')
        self.assertEqual(notify.node_id, node2_id)

        stabilize: ControlPacket = mock.await_packet(ControlPacket, 5.0)
        if not stabilize:
            _, out1, err1 = handler1.collect()
            _, out2, err2 = handler2.collect()
            self.fail(
                f"Peer did not send STABILIZE within timeout! Stdout1: {out1}, Stderr1:{err1}, Stdout2: {out2}, Stderr2:{err2}")

        mock.resp_q.put(ControlPacket('NOTIFY', 0, stabilize.node_id, stabilize.ip, stabilize.port))

        self.assertEqual(stabilize.method, 'STABILIZE')

        i = 0
        while stabilize.node_id != node1_id and i < 3:  # We might have JOINed to early (before node2 finished). So try again
            log.debug("Trying again")
            stabilize: ControlPacket = mock.await_packet(ControlPacket, 5.0)
            if not stabilize:
                _, out1, err1 = handler1.collect()
                _, out2, err2 = handler2.collect()
                self.fail(
                    f"Peer did not send STABILIZE within timeout! Stdout1: {out1}, Stderr1:{err1}, Stdout2: {out2}, Stderr2:{err2}")

            self.assertEqual(stabilize.method, 'STABILIZE')
            mock.resp_q.put(ControlPacket('NOTIFY', 0, stabilize.node_id, stabilize.ip, stabilize.port))
            i += 1

        self.assertEqual(stabilize.node_id, node1_id)

    def test_student_code_only_set_get(self):
        nodes = [512, 1024, 2048, 4096]
        handlers, ports = self.setup_student_ring(nodes)
        time.sleep(len(nodes) * 2 + 0.5)

        value = b'You have invited all my friends!'
        key = b'Good Thinking!'
        c1 = self.start_client(DataPacket('SET', key=key, value=value), port=ports[0])

        try:
            c1.await_packet(2.0)
        except AssertionError:
            trace = collect_trace(handlers)
            self.fail(f'Did not receive ACK packet. Trace: {trace}')

        c2 = self.start_client(DataPacket('GET', key=key), ports[3])
        get = c2.await_packet(2.0)
        if not get:
            trace = collect_trace(handlers)
            self.fail(f'Did not receive response for GET request! {trace}')

        self.assertEqual(get.value, value)

    def test_FT_minimal(self):
        nodes = [512, 1024, 2048, 4096]
        handlers, ports = self.setup_student_ring(nodes)
        time.sleep(len(nodes) * 2 + 0.5)

        key = b"Where's the money, Donny!!"
        value = b'Oh! Hi, Marc!'
        c1 = self.start_client(DataPacket('SET', key=key, value=value), port=ports[0])

        try:
            c1.await_packet(2.0)
        except AssertionError:
            trace = collect_trace(handlers)
            self.fail(f'Did not receive ACK packet. Trace: {trace}')

        c2 = self.start_client(ControlPacket('FINGER', 0, 0, ipaddress.IPv4Address('0.0.0.0'), 0), port=ports[0])

        try:
            c2.await_packet(2.0)
        except AssertionError:
            trace = collect_trace(handlers)
            self.fail(f'Did not receive ACK packet. Trace: {trace}')

        c3 = self.start_client(DataPacket('GET', key=key), ports[0])
        get = c3.await_packet(2.0)
        if not get:
            trace = collect_trace(handlers)
            self.fail(f'Did not receive response for GET request! {trace}')

        self.assertEqual(get.value, value)

    def test_FT_no_ack(self):
        nodes = [512, 1024, 2048, 4096]
        handlers, ports = self.setup_student_ring(nodes)
        time.sleep(len(nodes) * 2 + 0.5)

        key = b"Where's the money, Donny!!"
        value = b'Oh! Hi, Marc!'
        c1 = self.start_client(DataPacket('SET', key=key, value=value), port=ports[0])

        try:
            c1.await_packet(2.0)
        except AssertionError:
            trace = collect_trace(handlers)
            self.fail(f'Did not receive ACK packet. Trace: {trace}')

        c2 = self.start_client(ControlPacket('FINGER', 0, 0, ipaddress.IPv4Address('0.0.0.0'), 0), port=ports[0])

        time.sleep(0.5)

        c3 = self.start_client(DataPacket('GET', key=key), ports[0])
        get = c3.await_packet(2.0)
        if not get:
            trace = collect_trace(handlers)
            self.fail(f'Did not receive response for GET request! {trace}')

        self.assertEqual(get.value, value)

    def test_student_code_only_sg_no_id(self):
        nodes = [0, 1024, 2048, 4096]
        handlers, ports = self.setup_student_ring(nodes, ignore_first_id=True)
        time.sleep(len(nodes) * 2 + 0.5)

        value = b'You have invited all my friends!'
        key = b'Good Thinking!'
        c1 = self.start_client(DataPacket('SET', key=key, value=value), port=ports[0])

        try:
            c1.await_packet(2.0)
        except AssertionError:
            trace = collect_trace(handlers)
            self.fail(f'Did not receive ACK packet. Trace: {trace}')

        c2 = self.start_client(DataPacket('GET', key=key), ports[3])
        get = c2.await_packet(2.0)
        if not get:
            trace = collect_trace(handlers)
            self.fail(f'Did not receive response for GET request! {trace}')

        self.assertEqual(get.value, value)


def main():

    def pre():
        global docker_cli, container_network, container_peer, container_mock

        dockercli = docker.from_env()
        container_network = dockercli.networks.create('testnet',
                                                      internal=True)

        dockercli.volumes.create('src_vol')
        volumes = {'src_vol': {'bind': '/mnt/src', 'mode': 'rw'}}
        container_peer = dockercli.containers.run('ubuntu:bionic',
                                                  '/bin/bash',
                                                  name='hash-peer',
                                                  detach=True,
                                                  volumes=volumes,
                                                  working_dir='/mnt/src',
                                                  network='testnet',
                                                  restart_policy={"Name": "unless-stopped"},
                                                  stdin_open=True)

        container_mock = dockercli.containers.run('ubuntu:bionic',
                                                  '/bin/bash',
                                                  name='mock-peer',
                                                  detach=True,
                                                  volumes=volumes,
                                                  working_dir='/mnt/src',
                                                  network='testnet',
                                                  restart_policy={"Name": "unless-stopped"},
                                                  stdin_open=True)

    def post():
        subprocess.run(['bash', '-c',
                        'docker stop hash-peer; docker stop mock-peer; docker container prune -f; docker network prune -f'])

    run_tests(ASSIGNMENT, 'src_vol', pre=pre, post=post)



if __name__ == '__main__':
    main()
