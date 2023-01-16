import ipaddress
import queue
import subprocess
import logging

import docker

from ..common import which, exec_async, TKNTestCase, run_tests, log_test, port_ready
from ..node import DockerThread
from ..packet import Packet, DataPacket, ControlPacket
from ..mock import MockServer, MockClient, ControlPktHandler, GeneralPktHandler, DataPktHandler

ASSIGNMENT = 'Projekt 2 DHT'

docker_cli = None
container_network = None
container_peer = None
container_mock = None


def pseudo_hash(key: bytes):
    if len(key) >= 2:
        return int.from_bytes(key[0:2], 'big')
    elif len(key) == 0:
        return 0
    else:
        return key[0] << 8


class PeerTestCase(TKNTestCase):
    startupTimeout = 3
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
            peer = q.get(timeout=5)
            self.addCleanup(peer.server_close)
            self.addCleanup(peer.shutdown)
        except queue.Empty:
            raise RuntimeError("Could not setup mock peer. This should not happen!") from None

        return peer_thread, peer

    def basic_setup(self, req_handler, id, pre_id, suc_id):
        """ Starts the students peer with a Mock-Successor (no predecessor is started).
        :param req_handler: A instance of the PacketHandler handed to the MockServer
        :param id: ID of the started peer
        :param pre_id: ID of the predecessor given to the started peer
        :param suc_id: ID of the successor given to the started peer
        :return: Returns a tupel of the ExecAsyncHandler for the started peer and the MockServer started as successor
        :rtype: tuple(ExecAsyncHandler, MockServer)
        """
        peer_path = which(self.path, 'peer')

        suc_thread, succ = self.start_peer(1401, req_handler)

        ip = self.container_peer_ip
        pre_ip = self.container_mock_ip
        pre_port = 1400

        suc_ip = pre_ip
        suc_port = pre_port + 1

        handler = exec_async(container_peer, [f'{peer_path}', f'{id}', f'{ip}', '1400',
                                              f'{pre_id}', f'{pre_ip}', f'{pre_port}',
                                              f'{suc_id}', f'{suc_ip}', f'{suc_port}'])

        ready = port_ready(container_peer, 1400, self.startupTimeout)
        self.assertTrue(ready,
                        msg=f'Peer did not open port {1400} within {self.startupTimeout} seconds after starting!')

        return handler, succ

    def setup_student_peers(self, ids):
        """Starts multiple instances of the students peer with the ID taken from ids.
        Instances are started in the supplied order with a small delay in between.
        :param ids: List of IDs, one for each node to be started. Make sure this is sorted!
        :return: A tuple of a list of handlers for the started peers and a list of ports used for each node.
        :rtype: tuple(list(ExecAsyncHandler), list(int))
        """
        peer_path = which(self.path, 'peer')
        ip = self.container_peer_ip
        port_base = 1400

        ports = [port_base + n for n in range(len(ids))]
        handlers = []
        for i in range(len(ids)):
            handler = exec_async(container_peer, [f'{peer_path}', f'{ids[i]}', f'{ip}', f'{ports[i]}',
                                                  f'{ids[i - 1]}', f'{ip}', f'{ports[-1]}',
                                                  f'{ids[(i + 1) % len(ids)]}', f'{ip}',
                                                  f'{ports[(i + 1) % len(ids)]}'])

            ready = port_ready(container_peer, ports[i], self.startupTimeout)
            self.assertTrue(ready,
                            msg=f'Peer {ids[i]} did not open port {ports[i]} within {self.startupTimeout} '
                                f'seconds after starting!')

            handlers.append(handler)

        return handlers, ports

    def start_client(self, packet: Packet, port=1400):
        """Starts a client in the Mock container network namespace to send to send a given packet
        :param packet: Packet to be send
        :param port: Port to connect to on the peer container
        :return The created MockClient instance
        :raises AssertionError() if the client cannot connect to the server
        """
        c = MockClient(packet, port=port)

        client_thread = DockerThread(container_mock, target=c.run)
        client_thread.start()
        self.addCleanup(client_thread.join)
        self.addCleanup(c.stop)

        resolved = c.resolvedName.wait(3.0)
        if not resolved:
            raise RuntimeError("Failed to resolve hostname! This should not happen!")

        connected = c.clientConnected.wait(3.0)
        if not connected:
            raise AssertionError()

        return c

    @log_test
    def test_trigger_lookup_minimal(self):
        """Test whether a GET request from an unknown range triggers a lookup.

        The students peer is started similar to the following command:

        ./peer 10 {MyIP} 1400 1 {OtherIP} 1401 21616 {OtherIP} 1400

        Then a client is started from the mock container namespace and sends a GET request for the following key:

        key = b'Trigger_dat_lookup'  # ID: 21618

        Since this key maps *beyond* the successors ID range this should trigger a lookup to the successor.
        This test fails if:
            - We do not receive a ControlPacket (Ctrl-bit == 1) at the successor within 2.0 seconds

        NOTE: We do not check anything in the LOOKUP. Not even if it IS a lookup.
              It just needs to be a valid control packet.
        """
        key = b'Trigger_dat_lookup'  # ID: 21618
        hash = pseudo_hash(key)

        handler, succ = self.basic_setup(ControlPktHandler, 10, 1, hash - 2)

        try:
            self.start_client(DataPacket('GET', key=key))
        except AssertionError:
            status, out, err = handler.collect()
            if out.startswith(b'cannot exec in a stopped state: unknown'):
                raise RuntimeError(f'Shitty docker error with unknown cause: {out}')
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        ctrl_packet = succ.await_packet(ControlPacket, 2.0)
        if ctrl_packet is None:
            status, out, err = handler.collect()
            self.fail(msg=f"Did not receive a lookup request within timeout! Stdout: {out}, Stderr:{err}")

    @log_test
    def test_trigger_get_minimal(self):
        """Test whether a Client GET request triggers a proxy-GET request to the successor.

        The students peer is started similar to the following command:

        ./peer 10 {MyIP} 1400 1 {OtherIP} 1401 18282 {OtherIP} 1400

        Then a client is started from the mock container namespace and sends a GET request for the following key:

        key = b'Gimme_a_GET!'  # ID: 18281

        Since this key maps into the successors ID range this should trigger a proxy GET request to the successor.
        This test fails if:
            - We do not receive a DataPacket (Ctrl-bit == 0) at the successor within 2.0 seconds

        NOTE: We do not check anything in the GET request. It just needs to be a data packet and must be valid in terms
        of size.
        """
        key = b'Gimme_a_GET!'  # ID: 18281
        hash = pseudo_hash(key)

        handler, succ = self.basic_setup(DataPktHandler, 10, 1, hash + 1)

        try:
            self.start_client(DataPacket('GET', key=key))
        except AssertionError:
            status, out, err = handler.collect()
            if out.startswith(b'cannot exec in a stopped state: unknown'):
                raise RuntimeError(f'Shitty docker error with unknown cause: {out}')
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        data_packet = succ.await_packet(DataPacket, 2.0)
        if data_packet is None:
            status, out, err = handler.collect()
            self.fail(f"Did not receive a GET request within timeout! Stdout: {out}, Stderr:{err}")

    @log_test
    def test_forward_lookup(self):
        """Test whether the peer forwards lookup requests correctly on the ring.
        The students peer is started similar to the following command:

        ./peer 10 {MyIP} 1400 1 {OtherIP} 1401 1025 {OtherIP} 1400

        Then a LOOKUP request is sent to the peer with following data:
        Hash ID: 2000
        Node ID: 10000
        Node IP: {IP of mock container}
        Node Port: 4096

        A correct peer should forward this request since it is not in his ID interval.

        This test fails if:
            - We do not receive a CtrlPacket (Ctrl-bit == 1) at the successor within 2.0 seconds


        NOTE: We do not check anything in the LOOKUP request. It just needs to be a valid control packet.
        """
        hash = 2000
        imaginary_id = 10000
        imaginary_ip = ipaddress.IPv4Address(self.container_mock_ip)
        imaginary_port = 4096
        handler, succ = self.basic_setup(ControlPktHandler, 10, 1, 1025)

        try:
            self.start_client(ControlPacket('LOOKUP', hash, imaginary_id, imaginary_ip, imaginary_port))
        except AssertionError:
            status, out, err = handler.collect()
            if out.startswith(b'cannot exec in a stopped state: unknown'):
                raise RuntimeError(f'Shitty docker error with unknown cause: {out}')
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        lookup = succ.await_packet(ControlPacket, 2.0)
        if lookup is None:
            status, out, err = handler.collect()
            self.fail(f"Peer did not forward lookup to successor! Stdout: {out}, Stderr:{err}")

    @log_test
    def test_get_full_circle(self):
        """Tests a full sequence for client GET request that needs to be fetched from another node.

        First, the students peer is started similar to the following command:

        ./peer 10 {MyIP} 1400 1 {OtherIP} 1401 21607 {OtherIP} 1400

        Now a GET request by a client is sent to the peer with the following key:

        key = b'The ciiirrcle of Chord!'  # ID: 21608

        The TB now expects the peer to send a LOOKUP to its successor within 2.0 seconds.
        At this stage the TB fails if:
            - No Lookup is received within the timeout
            - The hash ID in the lookup does not match the hash for the key
            - The node ID in the lookup does not match the peers ID
            - The node IP in the lookup does not match the peer containers IP.
              This is often caused by messing up the byte order.
            - The node port in the lookup does not match the peers port

        The successor will respond (immediately) with a REPlY packet with following values:
        hash ID = 21608
        Node ID = 21609
        Node IP = {IP of the mock container}
        Node Port = 1500

        Now the TB expects the peer to send a GET request to supplied IP+port within 2.0 seconds.
        At this stage the TB fails if:
            - No GET is received within the timeout
              (most probably IP and port are parsed wrong and the connection fails)
            - The key for the GET request does not match the initial key requested.

        Once the GET requested was received the responsible not will respond with GET-ACK packet:
        key = b'The ciiirrcle of Chord!'
        value = b'What goes around comes around!'

        At last the peer must respond to the client within two seconds (after receiving the answer).
        At this final stage the TB fails if:
           - No answer is received by the client
           - The key for the GET request does not match the initial key requested.
           - The value for the GET request does not match the value supplied by the other peer.
        """
        key = b'The ciiirrcle of Chord!'  # ID: 21608
        hash = pseudo_hash(key)
        value = b'What goes around comes around!'

        handler, succ = self.basic_setup(GeneralPktHandler, 10, 1, hash - 1)
        succ.send_response = True

        rp_thread, responsible_peer = self.start_peer(1500, GeneralPktHandler)
        responsible_peer.send_response = True

        student_peer_ip = self.container_peer_ip

        succ.resp_q.put((ControlPacket('REPLY', hash, hash + 1, responsible_peer.ip, 1500), student_peer_ip, 1400))
        responsible_peer.resp_q.put(DataPacket('GET', key=key, value=value, ack=True))

        try:
            c = self.start_client(DataPacket('GET', key=key))
        except AssertionError:
            status, out, err = handler.collect()
            if out.startswith(b'cannot exec in a stopped state: unknown'):
                raise RuntimeError(f'Shitty docker error with unknown cause: {out}')
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        lookup = succ.await_packet(ControlPacket, 2.0)
        if lookup is None:
            status, out, err = handler.collect()
            self.fail(f"Did not receive a Lookup request within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(lookup.hash_id, hash, msg='Peer requested lookup for wrong hash id!')
        self.assertEqual(lookup.node_id, 10, msg='Peer filled in wrong node id in lookup request!')
        self.assertEqual(lookup.ip, ipaddress.IPv4Address(student_peer_ip),
                         msg=f'Peer filled in wrong IP in lookup request! Raw: {lookup.raw}')
        self.assertEqual(lookup.port, 1400, msg='Peer filled in wrong port in lookup request!')

        get = responsible_peer.await_packet(DataPacket, 2.0)
        if get is None:
            status, out, err = handler.collect()
            self.fail(f"Responsible peer did not receive a get request within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(get.key, key, msg="Peer requested wrong key!")

        try:
            resp = c.await_packet(2.0)
        except AssertionError:
            status, out, err = handler.collect()
            raise AssertionError(f'Peer did not answer the client correctly! Stdout: {out}, Stderr:{err}')

        if resp is None:
            status, out, err = handler.collect()
            self.fail(f"Peer did not answer the client within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(resp.key, key, msg='Peer answered to client with wrong key!')
        self.assertEqual(resp.value, value, msg='Peer answered to client with wrong value!')

    def not_a_test_get_full_circle_ipreversed(self):
        handler, succ = self.basic_setup(GeneralPktHandler, 10, 1, 1000)
        succ.send_response = True

        rp_thread, responsible_peer = self.start_peer(1500, GeneralPktHandler)
        responsible_peer.send_response = True

        key = b'\x04\x00The ciiirrcle of Chord!'  # ID: 1024
        value = b'What goes around comes around!'

        student_peer_ip = self.container_peer_ip
        reversed_ip_peer = ipaddress.IPv4Address(".".join(reversed(str(responsible_peer.ip).split('.'))))

        succ.resp_q.put((ControlPacket('REPLY', 1024, 1200, reversed_ip_peer, 1500), student_peer_ip, 1400))
        responsible_peer.resp_q.put(DataPacket('GET', key=key, value=value, ack=True))
        try:
            c = self.start_client(DataPacket('GET', key=key))
        except AssertionError:
            status, out, err = handler.collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        lookup = succ.await_packet(ControlPacket, 2.0)
        if lookup is None:
            status, out, err = handler.collect()
            self.fail(f"Did not receive a Lookup request within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(lookup.hash_id, 1024, msg='Peer requested lookup for wrong hash id!')
        self.assertEqual(lookup.node_id, 10, msg='Peer filled in wrong node id in lookup request!')
        # self.assertEqual(lookup.ip, ipaddress.IPv4Address(student_peer_ip),
        #                 msg=f'Peer filled in wrong IP in lookup request! Raw: {lookup.raw}')
        self.assertEqual(lookup.port, 1400, msg='Peer filled in wrong port in lookup request!')

        get = responsible_peer.await_packet(DataPacket, 2.0)
        if get is None:
            status, out, err = handler.collect()
            self.fail(f"Responsible peer did not receive a get request within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(get.key, key, msg="Peer requested wrong key!")

        resp = c.await_packet(2.0)
        if resp is None:
            status, out, err = handler.collect()
            self.fail(f"Peer did not answer the client within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(resp.key, key, msg='Peer answered to client with wrong key!')
        self.assertEqual(resp.value, value, msg='Peer answered to client with wrong value!')

    @log_test
    def test_student_ring_set_get_basic(self):
        """Test simple SET-GET sequence among multiple instances of the student's peer.

        First, five instances of the students peer are started in quick succession with the following IDs:

        1000 --> 14107 --> 27214 --> 40321 --> 53428

        Then a SET request is sent to peer 1000 with the following data:
        key = b'How do I exit vim?'
        value = b'https://stackoverflow.com/questions/11828270/how-do-i-exit-the-vim-editor'

        The TB awaits an acknowledgement to the client within 2.0 seconds.
        Once the client has received the ACK a GET request for the same key is sent by another client to peer 40321.

        The client waits for an answer for 3.0 seconds.
        This test fails if the value does not match the initial value set by the first client.
        """
        ids = [1000, 14107, 27214, 40321, 53428]
        handlers, ports = self.setup_student_peers(ids)  # Starts 5 equally spaced peers in a ring

        key = b'How do I exit vim?'
        value = b'https://stackoverflow.com/questions/11828270/how-do-i-exit-the-vim-editor'

        try:
            c1 = self.start_client(DataPacket('SET', key=key, value=value), port=ports[0])  # Set value in first peer
        except AssertionError:
            status, out, err = handlers[0].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        c1.await_packet(timeout=2.0)  # Wait for ACK before we query 2nd time

        try:
            c2 = self.start_client(DataPacket('GET', key=key), port=ports[3])  # Retrieve value from 4th peer
        except AssertionError:
            status, out, err = handlers[4].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        resp = c2.await_packet(3.0)
        if resp is None:
            status, out, err = handlers[4].collect()
            self.fail(f"Peer did not answer the client within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(resp.value, value, msg='Peer answered to client with wrong value!')

    @log_test
    def test_student_ring_set_del_set_get(self):
        """Test SET-DELETE followed by SET-GET  on the same key among multiple instances of the student's peer.

        First, five instances of the students peer are started in quick succession with the following IDs:

        1000 --> 14107 --> 27214 --> 40321 --> 53428

        Then a SET request is sent to peer 1000 with the following data:

        key = b'My C-Programming-Skillz'
        value1 = b'100% !!11einself!'

        The TB awaits an acknowledgement to the client within 2.0 seconds.
        Once the client has received the ACK a DELETE for the same key is sent by another client to peer 53428.
        The TB awaits an acknowledgement to the client within 2.0 seconds.

        Once the client has received the ACK a SET for the same key is sent by another client to peer 14107 with value
        value2 = b'sendto()sendto()sendto()sendto()'
        The TB awaits an acknowledgement to the client within 2.0 seconds.

        Once the client has received the ACK a final GET request is made for the same key to peer 1000.
        The TB awaits an acknowledgement to the client within 2.0 seconds.
        The response is checked for the correct value (value2).
        """

        ids = [1000, 14107, 27214, 40321, 53428]
        handlers, ports = self.setup_student_peers(ids)  # Starts 5 equally spaced peers in a ring

        key = b'My C-Programming-Skillz'
        whatIthink = b'100% !!11einself!'
        whatMyTutorSees = b'sendto()sendto()sendto()sendto()'

        try:
            c1 = self.start_client(DataPacket('SET', key=key, value=whatIthink),
                                   port=ports[0])  # Set value in first peer
        except AssertionError:
            status, out, err = handlers[0].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        c1.await_packet(timeout=2.0)  # Wait for ACK before we query 2nd time

        try:
            c2 = self.start_client(DataPacket('DELETE', key=key), port=ports[4])  # Delete value from 5th peer
        except AssertionError:
            status, out, err = handlers[4].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        c2.await_packet(timeout=3.0)  # Wait for ACK before we query 3rd time

        try:
            c3 = self.start_client(DataPacket('SET', key=key, value=whatMyTutorSees), port=ports[1])  # Second peer
        except AssertionError:
            status, out, err = handlers[1].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        c3.await_packet(timeout=2.0)  # Wait for ACK before we query 4th time

        try:
            c4 = self.start_client(DataPacket('GET', key=key), port=ports[0])  # Retrieve value from first peer again
        except AssertionError:
            status, out, err = handlers[0].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        resp = c4.await_packet(3.0)
        if resp is None:
            status, out, err = handlers[4].collect()
            self.fail(f"Peer did not answer the client within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(resp.value, whatMyTutorSees, msg='Peer answered to client with wrong value!')

    @log_test
    def test_student_ring_long_value(self):
        """Test SET-GET on the ring for long values.
        Functionally identical to test_student_set_get_basic but with different values:

        key = b'Fresh Prince of Bel Air'
        value = (b"Now, this is a story all about how\n" ... --> full lyrics of the song repeated 100 times

        The value is exactly 173700 bytes long.
        """
        key = b'Fresh Prince of Bel Air'
        value = (b"Now, this is a story all about how\n"
                 b"My life got flipped-turned upside down\n"
                 b"And I'd like to take a minute\n"
                 b"Just sit right there\n"
                 b"I'll tell you how I became the prince of a town called Bel Air\n"
                 b"\n"
                 b"In west Philadelphia born and raised\n"
                 b"On the playground was where I spent most of my days\n"
                 b"Chillin' out maxin' relaxin' all cool\n"
                 b"And all shootin some b-ball outside of the school\n"
                 b"When a couple of guys who were up to no good\n"
                 b"Started making trouble in my neighborhood\n"
                 b"I got in one little fight and my mom got scared\n"
                 b"She said 'You're movin' with your auntie and uncle in Bel Air'\n"
                 b"\n"
                 b"I begged and pleaded with her day after day\n"
                 b"But she packed my suit case and sent me on my way\n"
                 b"She gave me a kiss and then she gave me my ticket.\n"
                 b"I put my Walkman on and said, 'I might as well kick it'.\n"
                 b"\n"
                 b"First class, yo this is bad\n"
                 b"Drinking orange juice out of a champagne glass.\n"
                 b"Is this what the people of Bel-Air living like?\n"
                 b"Hmmmmm this might be alright.\n"
                 b"\n"
                 b"But wait I hear they're prissy, bourgeois, all that\n"
                 b"Is this the type of place that they just send this cool cat?\n"
                 b"I don't think so\n"
                 b"I'll see when I get there\n"
                 b"I hope they're prepared for the prince of Bel-Air\n"
                 b"\n"
                 b"Well, the plane landed and when I came out\n"
                 b"There was a dude who looked like a cop standing there with my name out\n"
                 b"I ain't trying to get arrested yet\n"
                 b"I just got here\n"
                 b"I sprang with the quickness like lightning, disappeared\n"
                 b"\n"
                 b"I whistled for a cab and when it came near\n"
                 b"The license plate said fresh and it had dice in the mirror\n"
                 b"If anything I could say that this cab was rare\n"
                 b"But I thought 'Nah, forget it' - 'Yo, homes to Bel Air'\n"
                 b"\n"
                 b"I pulled up to the house about 7 or 8\n"
                 b"And I yelled to the cabbie 'Yo homes smell ya later'\n"
                 b"I looked at my kingdom\n"
                 b"I was finally there\n"
                 b"To sit on my throne as the Prince of Bel Air\n") * 100

        ids = [1000, 14107, 27214, 40321, 53428]
        handlers, ports = self.setup_student_peers(ids)  # Starts 5 equally spaced peers in a ring

        try:
            c1 = self.start_client(DataPacket('SET', key=key, value=value), port=ports[0])  # Set value in first peer
        except AssertionError:
            status, out, err = handlers[0].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        c1.await_packet(timeout=2.0)  # Wait for ACK before we query 2nd time

        try:
            c2 = self.start_client(DataPacket('GET', key=key), port=ports[3])  # Retrieve value from 4th peer
        except AssertionError:
            status, out, err = handlers[4].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        resp = c2.await_packet(3.0)
        if resp is None:
            status, out, err = handlers[4].collect()
            self.fail(f"Peer did not answer the client within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(resp.value, value, msg='Peer answered to client with wrong value!')

    @log_test
    def test_student_ring_long_fixed_buffer(self):
        """Test SET-GET on the ring for long values.
        Functionally identical to test_student_set_get_basic but with different values:

        key = b'Daft Punk'
        value = b"Around the world!" * n

        where n depends on the buffer size found in your source code.
        """
        import random
        n = random.randint(0, 1337)

        key = b'Daft Punk'

        try:
            value = b"Around the world!" * n
        except MemoryError:
            log = logging.getLogger(__name__)
            log.warning('Ran out of memory for allocating value!')
            self.skipTest(f"Could not allocate enough memory for n == {n}!")

        ids = [1000, 14107, 27214, 40321, 53428]
        handlers, ports = self.setup_student_peers(ids)  # Starts 5 equally spaced peers in a ring

        try:
            c1 = self.start_client(DataPacket('SET', key=key, value=value), port=ports[0])  # Set value in first peer
        except AssertionError:
            status, out, err = handlers[0].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        c1.await_packet(timeout=2.0)  # Wait for ACK before we query 2nd time

        try:
            c2 = self.start_client(DataPacket('GET', key=key), port=ports[3])  # Retrieve value from 4th peer
        except AssertionError:
            status, out, err = handlers[4].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        resp = c2.await_packet(3.0)
        if resp is None:
            status, out, err = handlers[4].collect()
            self.fail(f"Peer did not answer the client within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(resp.value, value, msg='Peer answered to client with wrong value!')

    @log_test
    def test_student_ring_set_get_null(self):
        """Test handling of \0-bytes (a third time) on the Chord ring.

        Functionally identical to test_student_set_get_basic but with different values:

        key = b'You still cannot handle \0 Bytes?'
        value = b'https://www.tu-berlin.de/?id=76320'
        """
        ids = [1000, 14107, 27214, 40321, 53428]
        handlers, ports = self.setup_student_peers(ids)  # Starts 5 equally spaced peers in a ring

        key = b'You still cannot handle \0 Bytes?'
        value = b'https://www.tu-berlin.de/?id=76320'

        try:
            c1 = self.start_client(DataPacket('SET', key=key, value=value), port=ports[0])  # Set value in first peer
        except AssertionError:
            status, out, err = handlers[0].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        c1.await_packet(timeout=2.0)  # Wait for ACK before we query 2nd time

        try:
            c2 = self.start_client(DataPacket('GET', key=key), port=ports[3])  # Retrieve value from 4th peer
        except AssertionError:
            status, out, err = handlers[4].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        resp = c2.await_packet(3.0)
        if resp is None:
            status, out, err = handlers[4].collect()
            self.fail(f"Peer did not answer the client within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(resp.value, value, msg='Peer answered to client with wrong value!')

    @log_test
    def test_student_ring_set_set_get(self):
        """Test overwriting of values on the Chord ring.

        First, five instances of the students peer are started in quick succession with the following IDs:

        1000 --> 14107 --> 27214 --> 40321 --> 53428

        Then a SET request is sent to peer 1000 with the following data:

        key = b'How do I exit vim?'
        value1 = b'RTFM!'  # Use shorter value first to see if the value length is adjusted
        The TB awaits an acknowledgement to the client within 2.0 seconds.

        Once the client has received the ACK another  SET for the same key is sent by another client to peer 14107.
        value2 = b'https://stackoverflow.com/questions/11828270/how-do-i-exit-the-vim-editor'
        The TB awaits an acknowledgement to the client within 2.0 seconds.

        Once the client has received the ACK a final GET request is made for the same key to peer 40321.
        The TB awaits an acknowledgement to the client within 2.0 seconds.
        The response is checked for the correct value (value2).
        """
        ids = [1000, 14107, 27214, 40321, 53428]
        handlers, ports = self.setup_student_peers(ids)  # Starts 5 equally spaced peers in a ring

        key = b'How do I exit vim?'

        value1 = b'RTFM!'  # Use shorter value first to see if they adjust the value length
        value2 = b'https://stackoverflow.com/questions/11828270/how-do-i-exit-the-vim-editor'

        try:
            c1 = self.start_client(DataPacket('SET', key=key, value=value1), port=ports[0])  # Set value in first peer
        except AssertionError:
            status, out, err = handlers[0].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        c1.await_packet(timeout=2.0)  # Wait for ACK before we query 2nd time

        try:
            c2 = self.start_client(DataPacket('SET', key=key, value=value2), port=ports[1])  # Set value in 2nd peer
        except AssertionError:
            status, out, err = handlers[1].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        c2.await_packet(timeout=2.0)  # Wait for ACK before we query 3rd time

        try:
            c3 = self.start_client(DataPacket('GET', key=key), port=ports[3])  # Retrieve value from 4th peer
        except AssertionError:
            status, out, err = handlers[3].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        resp = c3.await_packet(3.0)
        if resp is None:
            status, out, err = handlers[3].collect()
            self.fail(f"Peer did not answer the client within timeout! Stdout: {out}, Stderr:{err}")

        self.assertEqual(resp.value, value2, msg='Peer answered to client with wrong value!')

    @log_test
    def test_student_ring_set_get_cross_zero(self):
        """Test simple SET-GET sequence among multiple instances of the student's peer reaching across zero.

        First, five instances of the students peer are started in quick succession with the following IDs:

        1000 --> 14107 --> 27214 --> 40321 --> 53428

        Then a SET request is sent to peer 53428 with the following data:
        key = b'How do I exit vim?' # maps to 18543 --> node 27214
        value = b'https://stackoverflow.com/questions/11828270/how-do-i-exit-the-vim-editor'

        This means the lookup should be sent across 0 via node 1000 and node 14107.

        The TB awaits an acknowledgement to the client within 2.0 seconds.
        Once the client has received the ACK a GET request for the same key is sent by another client to peer 14107.

        The client waits for an answer for 3.0 seconds.
        This test fails if the value does not match the initial value set by the first client.
        """
        ids = [1000, 14107, 27214, 40321, 53428]
        handlers, ports = self.setup_student_peers(ids)  # Starts 5 equally spaced peers in a ring

        key = b'How do I exit vim?'  # maps to 18543 -> 3rd node
        value = b'https://stackoverflow.com/questions/11828270/how-do-i-exit-the-vim-editor'

        try:
            c1 = self.start_client(DataPacket('SET', key=key, value=value),
                                   port=ports[4])  # Set value in fifth peer
        except AssertionError:
            status, out, err = handlers[4].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        c1.await_packet(timeout=2.0)  # Wait for ACK before we query 2nd time

        try:
            c2 = self.start_client(DataPacket('GET', key=key), port=ports[1])  # Retrieve value from 2nd peer
        except AssertionError:
            status, out, err = handlers[1].collect()
            raise AssertionError(f"Client could not connect to peer! Stdout: {out}, Stderr:{err}") from None

        resp = c2.await_packet(3.0)
        if resp is None:
            status, out, err = handlers[1].collect()
            self.fail(f"Peer did not answer the client within timeout! Stdout: {out}, Stderr:{err}")

        # self.assertEqual(resp.key, key, msg='Peer answered to client with wrong key!')
        self.assertEqual(resp.value, value, msg='Peer answered to client with wrong value!')


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
                        'docker stop hash-peer; docker stop mock-peer; docker container prune -f; '
                        'docker network prune -f'])

    run_tests(ASSIGNMENT, 'src_vol', pre=pre, post=post)


if __name__ == '__main__':
    main()
