#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Tests for the multi-stream wfb_tx mode (-y stream specs): one TX process,
# several streams with independent radio_port / FEC / session, per-stream
# control commands. Uses the same no-radio harness as test_txrx: the TX
# emulates wlans via -D (stream i, wlan w -> debug_port + i*W + w) and the
# tests relay captured packets into per-stream wfb_rx aggregators.
#
# Strict-priority drain ordering is not deterministically observable through
# two debug UDP sockets, so it is covered by code review and manual burst
# tests only.

import time
import os
import struct
import errno

from twisted.python import log
from twisted.trial import unittest
from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol

from ..common import df_sleep
from ..protocols import RXProtocol, TXProtocol
from .. import call_and_check_rc
from .test_txrx import UDP_TXRX, FakeAntennaProtocol, TXCommandClient, gen_req_id


class MultiStreamTXCommandClient(TXCommandClient):
    CMD_SET_FEC_STREAM = 5
    CMD_SET_RADIO_STREAM = 6
    CMD_GET_FEC_STREAM = 7
    CMD_GET_RADIO_STREAM = 8

    @gen_req_id
    def set_fec_stream(self, req_id, radio_port, k, n):
        return self._do_cmd(req_id, struct.pack('!IBBBB', req_id, self.CMD_SET_FEC_STREAM, radio_port, k, n))\
                   .addCallback(lambda data: None)

    @gen_req_id
    def get_fec_stream(self, req_id, radio_port):
        def _got_response(data):
            return dict(zip(('k', 'n'), struct.unpack('!BB', data)))

        return self._do_cmd(req_id, struct.pack('!IBB', req_id, self.CMD_GET_FEC_STREAM, radio_port))\
                   .addCallback(_got_response)

    @gen_req_id
    def set_radio_stream(self, req_id, radio_port, stbc, ldpc, short_gi, bandwidth, mcs_index, vht_mode, vht_nss):
        return self._do_cmd(req_id, struct.pack('!IBBB??BB?B', req_id, self.CMD_SET_RADIO_STREAM, radio_port,
                                                stbc, ldpc, short_gi, bandwidth, mcs_index, vht_mode, vht_nss))\
                   .addCallback(lambda data: None)

    @gen_req_id
    def get_radio_stream(self, req_id, radio_port):
        def _got_response(data):
            return dict(zip(('stbc', 'ldpc', 'short_gi', 'bandwidth', 'mcs_index', 'vht_mode', 'vht_nss'),
                            struct.unpack('!B??BB?B', data)))

        return self._do_cmd(req_id, struct.pack('!IBB', req_id, self.CMD_GET_RADIO_STREAM, radio_port))\
                   .addCallback(_got_response)


class MultiStreamTestCase(unittest.TestCase):
    """One wfb_tx with two -y streams:

    stream A: udp 10003, radio_port 16, FEC 2/4, debug wlan on 10004
    stream B: udp 10013, radio_port 17, FEC 1/2, debug wlan on 10005

    Each stream has its own wfb_rx aggregator (10001 -> 10002 for A,
    10011 -> 10012 for B).
    """

    @defer.inlineCallbacks
    def setUp(self):
        bindir = os.path.join(os.path.dirname(__file__), '../..')
        yield call_and_check_rc(os.path.join(bindir, 'wfb_keygen'))

        self.rxp0 = UDP_TXRX(('127.0.0.1', 10001))
        self.rxp1 = UDP_TXRX(('127.0.0.1', 10011))
        self.txp0 = UDP_TXRX(('127.0.0.1', 10003))
        self.txp1 = UDP_TXRX(('127.0.0.1', 10013))
        self.cmdp = MultiStreamTXCommandClient(('127.0.0.1', 7003))

        self.rx0_ep = reactor.listenUDP(10002, self.rxp0)
        self.rx1_ep = reactor.listenUDP(10012, self.rxp1)
        self.tx0_ep = reactor.listenUDP(10004, self.txp0)
        self.tx1_ep = reactor.listenUDP(10005, self.txp1)
        self.cmd_ep = reactor.listenUDP(0, self.cmdp)

        link_id = int.from_bytes(os.urandom(3), 'big')
        epoch = int(time.time())

        cmd_rx0 = [os.path.join(bindir, 'wfb_rx'), '-K', 'drone.key', '-a', '10001', '-u', '10002', '-p', '16',
                   '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']
        cmd_rx1 = [os.path.join(bindir, 'wfb_rx'), '-K', 'drone.key', '-a', '10011', '-u', '10012', '-p', '17',
                   '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']
        cmd_tx = [os.path.join(bindir, 'wfb_tx'), '-K', 'gs.key', '-D', '10004', '-T', '30', '-F', '3000', '-C', '7003',
                  '-y', 'u=10003,p=16,k=2,n=4',
                  '-y', 'u=10013,p=17,k=1,n=2',
                  '-i', str(link_id), '-e', str(epoch), '-R', str(512 * 1024), '-s', str(512 * 1024), 'wlan0']

        ap = FakeAntennaProtocol()
        self.rx0_pp = RXProtocol(ap, cmd_rx0, 'debug rx0')
        self.rx1_pp = RXProtocol(ap, cmd_rx1, 'debug rx1')
        self.tx_pp = TXProtocol(ap, cmd_tx, 'debug tx')

        self.rx0_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        self.rx1_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))
        self.tx_pp.start().addErrback(lambda f: f.trap('twisted.internet.error.ProcessTerminated'))

        # Wait for tx/rx processes to initialize
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def tearDown(self):
        self.rx0_pp.transport.signalProcess('KILL')
        self.rx1_pp.transport.signalProcess('KILL')
        self.tx_pp.transport.signalProcess('KILL')
        self.rx0_ep.stopListening()
        self.rx1_ep.stopListening()
        self.tx0_ep.stopListening()
        self.tx1_ep.stopListening()
        self.cmd_ep.stopListening()
        # Wait for tx/rx processes to die
        yield df_sleep(0.1)

    @defer.inlineCallbacks
    def test_per_stream_delivery(self):
        # 16 msgs on stream A (k=2: 8 full blocks), 6 on stream B (k=1).
        # Running both streams through one TX process also exercises the
        # stdout stats protocol: TXProtocol's parser must accept the new
        # PKT_S / TX_ANT_S lines (it ignores unknown tags) or this test
        # errors out.
        for i in range(16):
            self.txp0.send_msg(b'a%d' % (i + 1,))
        for i in range(6):
            self.txp1.send_msg(b'b%d' % (i + 1,))

        yield df_sleep(0.1)

        # stream A: 1 session + 8 blocks * (2 data + 2 fec)
        self.assertEqual(len(self.txp0.rxq), 33)
        # stream B: 1 session + 6 blocks * (1 data + 1 fec)
        self.assertEqual(len(self.txp1.rxq), 13)

        for pkt in self.txp0.rxq:
            self.rxp0.send_msg(pkt)
        for pkt in self.txp1.rxq:
            self.rxp1.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'a%d' % (i + 1,) for i in range(16)], self.rxp0.rxq)
        self.assertEqual([b'b%d' % (i + 1,) for i in range(6)], self.rxp1.rxq)

    @defer.inlineCallbacks
    def test_per_stream_fec_isolation(self):
        # Loss on one stream must not affect the other, and each stream
        # recovers according to its own FEC profile.
        for i in range(4):
            self.txp0.send_msg(b'a%d' % (i + 1,))
        for i in range(3):
            self.txp1.send_msg(b'b%d' % (i + 1,))

        yield df_sleep(0.1)
        # stream A: 1 session + 2 blocks * 4; stream B: 1 session + 3 blocks * 2
        self.assertEqual(len(self.txp0.rxq), 9)
        self.assertEqual(len(self.txp1.rxq), 7)

        # stream A: drop 2 of the 4 packets of block #1 (recoverable, k=2/n=4)
        for i, pkt in enumerate(self.txp0.rxq):
            if i not in (1, 3):
                self.rxp0.send_msg(pkt)

        # stream B: drop a whole block (data + fec of message b2) - lost
        for i, pkt in enumerate(self.txp1.rxq):
            if i not in (3, 4):
                self.rxp1.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'a%d' % (i + 1,) for i in range(4)], self.rxp0.rxq)
        self.assertEqual([b'b1', b'b3'], self.rxp1.rxq)

    @defer.inlineCallbacks
    def test_cross_stream_isolation(self):
        # Packets of stream A fed into stream B's aggregator must not
        # decode: different channel_id, different session.
        for i in range(4):
            self.txp0.send_msg(b'a%d' % (i + 1,))

        yield df_sleep(0.1)
        self.assertEqual(len(self.txp0.rxq), 9)

        for pkt in self.txp0.rxq:
            self.rxp1.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual(self.rxp1.rxq, [])

    @defer.inlineCallbacks
    def test_per_stream_cmd_fec(self):
        res = yield self.cmdp.get_fec_stream(16)
        self.assertEqual((res['k'], res['n']), (2, 4))

        res = yield self.cmdp.get_fec_stream(17)
        self.assertEqual((res['k'], res['n']), (1, 2))

        # legacy command addresses the first stream
        res = yield self.cmdp.get_fec()
        self.assertEqual((res['k'], res['n']), (2, 4))

        yield self.cmdp.set_fec_stream(17, 4, 8)

        res = yield self.cmdp.get_fec_stream(17)
        self.assertEqual((res['k'], res['n']), (4, 8))

        # the other stream is untouched
        res = yield self.cmdp.get_fec_stream(16)
        self.assertEqual((res['k'], res['n']), (2, 4))

        # data still flows with the new FEC profile (k=4: send 4 msgs)
        for i in range(4):
            self.txp1.send_msg(b'b%d' % (i + 1,))

        yield df_sleep(0.1)
        for pkt in self.txp1.rxq:
            self.rxp1.send_msg(pkt)

        yield df_sleep(0.1)
        self.assertEqual([b'b%d' % (i + 1,) for i in range(4)], self.rxp1.rxq)

    @defer.inlineCallbacks
    def test_per_stream_cmd_radio(self):
        yield self.cmdp.set_radio_stream(17, stbc=1, ldpc=True, short_gi=False,
                                         bandwidth=40, mcs_index=3, vht_mode=False, vht_nss=0)

        res = yield self.cmdp.get_radio_stream(17)
        self.assertEqual(res['bandwidth'], 40)
        self.assertEqual(res['mcs_index'], 3)
        self.assertEqual(res['stbc'], 1)
        self.assertEqual(res['ldpc'], True)

        # the other stream keeps its own radiotap settings
        res = yield self.cmdp.get_radio_stream(16)
        self.assertNotEqual(res['mcs_index'], 3)

    @defer.inlineCallbacks
    def test_per_stream_cmd_unknown_radio_port(self):
        try:
            yield self.cmdp.get_fec_stream(99)
            self.fail('Should fail')
        except OSError as v:
            self.assertEqual(str(v), 'Error: ENODEV')

        try:
            yield self.cmdp.set_fec_stream(99, 2, 4)
            self.fail('Should fail')
        except OSError as v:
            self.assertEqual(str(v), 'Error: ENODEV')
