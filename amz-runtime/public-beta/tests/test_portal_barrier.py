"""Synthetic native source tests only: no MultiServer/game import or sockets."""
import asyncio
import copy
import hashlib
import io
import json
import logging
from pathlib import Path
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
from gateway_barrier import NativeBarrier, BarrierError, initial_state, connect_password, canonical, iso, CONTROL
from gateway_hooks import PublicHooks, RedactedConnect, Redactor, ControlPump, install_log_redaction

def uid():
    return str(uuid.uuid4())

class Client:
    __slots__ = ('auth', 'team', 'slot', 'tags', '__weakref__')
    def __init__(self):
        self.auth, self.team, self.slot, self.tags = False, None, None, set()

class Fixture:
    def __init__(self):
        room = uid()
        self.identity = {'appVariant': 'public-beta', 'policyId': 'public-disposable-beta-v1', 'environmentId': uid(), 'dataEpoch': uid(), 'roomId': room,
                         'externalId': f'ap-beta-{room}-r1', 'allocationRevision': 1, 'serverId': 'synthetic_server', 'attemptId': uid(), 'seedRevision': 1, 'credentialEpoch': 1, 'runtimeLaunchId': uid()}
        self.master = 'synthetic_native_master_' + 'm' * 40
        self.now, self.persisted = 1893553445000, []
        self.barrier = NativeBarrier(self.identity, self.master, initial_state(self.identity), self.persisted.append, lambda: self.now)
        self.actual = []
        self.barrier.bind_observer(lambda: list(self.actual))
        self.barrier.mark_ready()

    def material(self, **changes):
        value = {'schema': 'amz.ap.public-beta.native-connect.v1', 'identity': copy.deepcopy(self.identity), 'reservationId': uid(), 'connectionId': uid(), 'gatewayProcessId': uid(),
                 'grantId': uid(), 'actorUuid': uid(), 'slotAlias': 'Alice', 'game': 'Yacht Dice', 'team': 0, 'slot': 1, 'bindingRevision': 1, 'configurationRevision': 1,
                 'credentialRevision': 1, 'reservationExpiresAt': iso(self.now + 10000), 'grantExpiresAt': iso(self.now + 60000), 'expiresAt': iso(self.now + 10000)}
        value.update(changes)
        return value

    def command(self, kind, payload=None, gate=None):
        return {'schema': CONTROL, 'operationId': uid(), 'command': kind, 'identity': copy.deepcopy(self.identity), 'gate': gate, 'payload': payload,
                'issuedAt': iso(self.now), 'expiresAt': iso(self.now + 5000)}

    def prepare(self, value=None):
        value = value or self.material()
        proof = connect_password(self.master, value)
        payload = {'material': value, 'credentialSha256': hashlib.sha256(proof.encode()).hexdigest()}
        result = self.barrier.control(self.command('prepare_connection', payload))
        return value, proof, payload, result

    def args(self, value, proof):
        return {'cmd': 'Connect', 'name': value['slotAlias'], 'game': value['game'], 'password': proof, 'tags': ['AP'], 'version': (0, 6, 8), 'items_handling': 7, 'uuid': 1}

    def idle(self):
        request = {**self.identity, 'schema': 'amz.ap.public-beta.idle-fence.v1', 'operationId': uid(), 'action': 'idle_sleep', 'expectedObservationRevision': 1,
                   'expectedConnectionGeneration': self.barrier.state['generation'], 'provenInitialReadyAt': self.barrier.state['initialReadyAt'], 'provenLastDisconnectAt': self.barrier.state['lastDisconnectAt']}
        digest = hashlib.sha256(request['schema'].encode() + b'\n' + canonical(request)).hexdigest()
        gate = {'id': uid(), 'operationId': request['operationId'], 'requestSha256': digest, 'kind': 'idle'}
        return self.command('idle_fence', request, gate)

class BarrierTests(unittest.TestCase):
    def test_old_delayed_proof_cannot_consume_new_prepare_same_slot(self):
        f = Fixture()
        old, old_proof, payload, _ = f.prepare()
        closed = f.barrier.control(f.command('detach_slot', payload))
        self.assertEqual(closed['result']['state'], 'closed')
        new, proof, _, _ = f.prepare()
        with self.assertRaises(BarrierError):
            f.barrier.consume(Client(), f.args(old, old_proof))
        self.assertEqual(f.barrier.state['preparations'][new['reservationId']]['status'], 'prepared')
        f.barrier.consume(Client(), f.args(new, proof))

    def test_same_proof_consumed_once_and_before_original_await(self):
        f = Fixture(); value, proof, _, _ = f.prepare()
        client = Client(); f.barrier.consume(client, f.args(value, proof))
        self.assertEqual(f.persisted[-1]['preparations'][value['reservationId']]['status'], 'consumed')
        for other in (Client(), client):
            with self.assertRaises(BarrierError): f.barrier.consume(other, f.args(value, proof))

    def test_slotted_engine_shape_refuses_second_attempt_without_mutating_client(self):
        f = Fixture(); value, proof, _, _ = f.prepare(); client = Client()
        self.assertFalse(hasattr(client, '__dict__'))
        with self.assertRaises(AttributeError): client._amz_native_attempted = True
        wrong = f.args(value, proof); wrong['name'] = 'Different'
        with self.assertRaises(BarrierError): f.barrier.consume(client, wrong)
        with self.assertRaises(BarrierError): f.barrier.consume(client, f.args(value, proof))
        self.assertEqual(f.barrier.state['preparations'][value['reservationId']]['status'], 'prepared')
        f.barrier.consume(Client(), f.args(value, proof))

    def test_plain_master_wrong_fields_tags_and_expiry_refused(self):
        for change in ('master', 'name', 'game', 'tags', 'expired', 'proof'):
            f = Fixture(); value, proof, _, _ = f.prepare(); args = f.args(value, proof)
            if change == 'master': args['password'] = f.master
            elif change == 'tags': args['tags'] = ['Tracker']
            elif change == 'expired': f.now += 10000
            elif change == 'proof': args['password'] = proof[:-1] + ('A' if proof[-1] != 'A' else 'B')
            else: args[change] = 'Different'
            with self.assertRaises(BarrierError): f.barrier.consume(Client(), args)

    def test_idle_closure_blocks_consumption_without_cancelling_prepared_uncertainty(self):
        f = Fixture(); value, proof, _, _ = f.prepare()
        result = f.barrier.control(f.idle())
        self.assertEqual(result['result']['state'], 'unknown')
        f.now += 10000
        with self.assertRaises(BarrierError): f.barrier.consume(Client(), f.args(value, proof))
        self.assertEqual(f.barrier.state['preparations'][value['reservationId']]['status'], 'prepared')

    def test_wall_clock_rollback_and_repeated_prepare_cannot_extend_admission(self):
        f = Fixture(); elapsed = [0.0]; f.barrier._mono = lambda: elapsed[0]
        value, proof, payload, _ = f.prepare(); elapsed[0] = 9.0
        f.barrier.control(f.command('prepare_connection', payload))
        elapsed[0] = 11.0; f.now -= 1000
        with self.assertRaises(BarrierError): f.barrier.consume(Client(), f.args(value, proof))
        self.assertEqual(f.barrier.state['preparations'][value['reservationId']]['status'], 'prepared')

    def test_expired_closed_gc_then_clock_rollback_cannot_recreate_old_prepare(self):
        f = Fixture(); original_now = f.now; value = f.material()
        proof = connect_password(f.master, value)
        payload = {'material': value, 'credentialSha256': hashlib.sha256(proof.encode()).hexdigest()}
        original = f.command('prepare_connection', payload)
        f.barrier.control(original)
        self.assertEqual(f.barrier.control(f.command('detach_slot', payload))['result']['state'], 'closed')
        f.now += 11000
        current, _, _, _ = f.prepare()
        self.assertNotIn(value['reservationId'], f.barrier.state['preparations'])
        self.assertNotIn(original['operationId'], f.barrier.state['controls'])
        retained = copy.deepcopy(f.persisted[-1])
        f.now = original_now
        with self.assertRaisesRegex(BarrierError, '^native_clock_rollback$'):
            f.barrier.control(original)
        self.assertNotIn(value['reservationId'], f.barrier.state['preparations'])
        self.assertEqual(f.barrier.state['preparations'][current['reservationId']]['status'], 'prepared')
        with self.assertRaisesRegex(BarrierError, '^native_clock_rollback$'):
            NativeBarrier(f.identity, f.master, retained, f.persisted.append, lambda: f.now)

    def test_native_accepted_generation_precedes_handler_completion_and_idle_is_busy(self):
        f = Fixture(); value, proof, _, _ = f.prepare(); client = Client()
        f.barrier.consume(client, f.args(value, proof)); client.auth, client.team, client.slot = True, 0, 1; f.actual.append(client)
        f.barrier.accepted(client)
        self.assertEqual(f.barrier.state['generation'], 1); self.assertIsNone(f.barrier.state['initialReadyAt'])
        f.barrier.handler_finished(client)
        request = f.idle(); request['payload']['provenLastDisconnectAt'] = iso(f.now - 1000)
        request['gate']['requestSha256'] = hashlib.sha256(request['payload']['schema'].encode() + b'\n' + canonical(request['payload'])).hexdigest()
        self.assertEqual(f.barrier.control(request)['result']['state'], 'busy')
        self.assertIn(client, f.actual)

    def test_disconnect_waits_for_pending_handler_and_preserves_original_clock(self):
        f = Fixture(); value, proof, _, _ = f.prepare(); client = Client()
        f.barrier.consume(client, f.args(value, proof)); client.auth, client.team, client.slot = True, 0, 1; f.actual.append(client); f.barrier.accepted(client)
        f.actual.remove(client); f.now += 2000; f.barrier.disconnected(client)
        self.assertEqual(f.barrier.state['generation'], 1)
        f.barrier.handler_finished(client)
        self.assertEqual(f.barrier.state['generation'], 2); baseline = f.barrier.state['lastDisconnectAt']
        f.barrier.shutdown(); f.now += 10000
        restarted = NativeBarrier(f.identity, f.master, f.persisted[-1], f.persisted.append, lambda: f.now)
        restarted.bind_observer(lambda: []); restarted.mark_ready()
        self.assertEqual(restarted.state['lastDisconnectAt'], baseline); self.assertIsNone(restarted.state['initialReadyAt'])

    def test_unclean_restart_never_creates_fresh_zero_or_reusable_proof(self):
        f = Fixture(); value, proof, _, _ = f.prepare()
        restarted = NativeBarrier(f.identity, f.master, f.persisted[-1], f.persisted.append, lambda: f.now)
        restarted.bind_observer(lambda: [])
        with self.assertRaises(BarrierError): restarted.mark_ready()
        with self.assertRaises(BarrierError): restarted.consume(Client(), f.args(value, proof))

    def test_missing_observer_is_unknown_and_persistence_failure_never_acknowledges(self):
        f = Fixture(); f.barrier._observe = None
        self.assertEqual(f.barrier.control(f.idle())['result']['state'], 'unknown')
        f = Fixture()
        def fail(_): raise OSError('private filesystem failure')
        f.barrier._persist = fail
        with self.assertRaisesRegex(BarrierError, '^native_journal_uncertain$'): f.prepare()
        self.assertTrue(f.barrier.state['uncertain'])

    def test_v1_and_changed_identity_command_are_rejected(self):
        f = Fixture(); command = f.idle(); command['schema'] = 'amz.ap.public-beta.gateway-control.v1'
        with self.assertRaises(BarrierError): f.barrier.control(command)
        command = f.idle(); command['identity']['dataEpoch'] = uid()
        with self.assertRaises(BarrierError): f.barrier.control(command)

class HookTests(unittest.IsolatedAsyncioTestCase):
    async def test_durable_consume_crossing_deadline_never_calls_original(self):
        f = Fixture(); elapsed = [0.0]; f.barrier._mono = lambda: elapsed[0]
        value, proof, _, _ = f.prepare(); called = []
        class Context: pass
        ctx = Context(); ctx.password, ctx.endpoints, ctx.connect_names, ctx.games = f.master, [], {'Alice': (0, 1)}, {1: 'Yacht Dice'}
        async def original(*_): called.append(True)
        async def noop(*_): pass
        hooks = PublicHooks(f.barrier, original, noop, noop); f.barrier._observe = None; hooks.bind_context(ctx)
        def durable_slow_commit(state):
            f.persisted.append(copy.deepcopy(state)); f.now += 11000; elapsed[0] += 11.0
        f.barrier._persist = durable_slow_commit
        with self.assertRaisesRegex(BarrierError, '^native_connect_rejected$'):
            await hooks.process_client_cmd(ctx, Client(), f.args(value, proof))
        self.assertEqual(called, [])
        self.assertEqual(f.persisted[-1]['preparations'][value['reservationId']]['status'], 'consumed')
        self.assertEqual(f.barrier.control(f.idle())['result']['state'], 'unknown')

    async def test_parallel_proof_replay_and_cancellation_never_repeat_original(self):
        f = Fixture(); value, proof, _, _ = f.prepare(); entered, release = asyncio.Event(), asyncio.Event(); count = []
        class Context: pass
        ctx = Context(); ctx.password, ctx.endpoints, ctx.connect_names, ctx.games = f.master, [], {'Alice': (0, 1)}, {1: 'Yacht Dice'}
        async def original(*_): count.append(True); entered.set(); await release.wait()
        async def noop(*_): pass
        hooks = PublicHooks(f.barrier, original, noop, noop); f.barrier._observe = None; hooks.bind_context(ctx)
        first = asyncio.create_task(hooks.process_client_cmd(ctx, Client(), f.args(value, proof)))
        await entered.wait()
        with self.assertRaises(BarrierError): await hooks.process_client_cmd(ctx, Client(), f.args(value, proof))
        first.cancel()
        with self.assertRaises(BarrierError): await first
        self.assertEqual(len(count), 1); self.assertEqual(f.barrier.state['preparations'][value['reservationId']]['status'], 'unknown')
        self.assertEqual(f.barrier.control(f.idle())['result']['state'], 'unknown')

    async def test_all_refusal_labels_and_unexpected_exception_logging_are_redacted(self):
        for refusal in ('InvalidGame', 'IncompatibleVersion', 'InvalidItemsHandling'):
            f = Fixture(); value, proof, _, _ = f.prepare(); stream = io.StringIO(); handler = logging.StreamHandler(stream)
            logger = logging.getLogger('synthetic-public-native'); logger.addHandler(handler); logger.setLevel(logging.INFO); logger.propagate = False
            stop = install_log_redaction(f.master)
            class Context: pass
            ctx = Context(); ctx.password, ctx.endpoints, ctx.connect_names, ctx.games = f.master, [], {'Alice': (0, 1)}, {1: 'Yacht Dice'}
            async def original(context, client, args):
                logger.info('Refused %s %s', refusal, args)
                try: raise RuntimeError(f.master + proof)
                except RuntimeError: logger.exception('Synthetic unexpected %s', proof)
            async def noop(*_): pass
            hooks = PublicHooks(f.barrier, original, noop, noop); f.barrier._observe = None; hooks.bind_context(ctx)
            try:
                await hooks.process_client_cmd(ctx, Client(), f.args(value, proof))
                output = stream.getvalue(); self.assertIn(refusal, output); self.assertNotIn(f.master, output); self.assertNotIn(proof, output); self.assertNotIn('Traceback', output)
            finally:
                stop(); logger.removeHandler(handler); handler.close()
    async def test_real_mapping_is_private_redacted_and_original_context_unchanged(self):
        f = Fixture(); value, proof, _, _ = f.prepare(); calls, logs = [], []
        class Context: pass
        ctx = Context(); ctx.password, ctx.endpoints, ctx.connect_names, ctx.games = f.master, [], {'Alice': (0, 1)}, {1: 'Yacht Dice'}
        async def original(context, client, args):
            self.assertIs(context, ctx); self.assertIsInstance(args, dict); self.assertEqual(args['password'], f.master)
            logs.append(str(args)); logs.append(repr(args)); calls.append(dict(args))
        async def noop(*_): pass
        hooks = PublicHooks(f.barrier, original, noop, noop)
        # Fixture already bound its synthetic observer; replace only in test.
        f.barrier._observe = None; hooks.bind_context(ctx)
        args = f.args(value, proof); await hooks.process_client_cmd(ctx, Client(), args)
        self.assertEqual(args['password'], proof); self.assertEqual(ctx.password, f.master)
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(f.master not in line and proof not in line for line in logs))
        redact = Redactor(f.master)
        self.assertNotIn(f.master, redact(f.master + ' ' + proof)); self.assertNotIn(proof, redact(proof))

    async def test_join_callback_commits_generation_before_original_join_await(self):
        f = Fixture(); value, proof, _, _ = f.prepare(); started, release = asyncio.Event(), asyncio.Event()
        class Context: pass
        ctx = Context(); ctx.password, ctx.endpoints, ctx.connect_names, ctx.games = f.master, [], {'Alice': (0, 1)}, {1: 'Yacht Dice'}
        async def joined(context, client): started.set(); await release.wait()
        async def disconnected(*_): pass
        async def original(context, client, args):
            client.auth, client.team, client.slot, client.tags = True, 0, 1, {'AP'}; ctx.endpoints.append(client)
            await hooks.on_client_joined(ctx, client)
        hooks = PublicHooks(f.barrier, original, joined, disconnected); f.barrier._observe = None; hooks.bind_context(ctx)
        client = Client(); task = asyncio.create_task(hooks.process_client_cmd(ctx, client, f.args(value, proof)))
        await started.wait(); self.assertEqual(f.persisted[-1]['generation'], 1); self.assertIsNone(f.persisted[-1]['initialReadyAt'])
        with self.assertRaises(BarrierError): await hooks.process_client_cmd(ctx, client, f.args(value, proof))
        release.set(); await task

    async def test_unexpected_original_exception_is_fixed_and_spent_proof_stays_unknown(self):
        f = Fixture(); value, proof, _, _ = f.prepare()
        class Context: pass
        ctx = Context(); ctx.password, ctx.endpoints, ctx.connect_names, ctx.games = f.master, [], {'Alice': (0, 1)}, {1: 'Yacht Dice'}
        async def original(*_): raise RuntimeError(f.master + proof)
        async def noop(*_): pass
        hooks = PublicHooks(f.barrier, original, noop, noop); f.barrier._observe = None; hooks.bind_context(ctx)
        with self.assertRaisesRegex(BarrierError, '^native_connect_failed$'): await hooks.process_client_cmd(ctx, Client(), f.args(value, proof))
        self.assertEqual(f.barrier.state['preparations'][value['reservationId']]['status'], 'unknown')

    async def test_control_pump_stopped_during_drain_does_not_publish_late_ack(self):
        f = Fixture(); entered, release = asyncio.Event(), asyncio.Event(); acks = []
        command = f.idle()
        class Files:
            def read_control(self): return copy.deepcopy(command)
            def publish_ack(self, value): acks.append(value)
        class Hooks:
            async def drain(self, value): entered.set(); await release.wait()
        pump = ControlPump(Files(), f.barrier, Hooks())
        task = asyncio.create_task(pump.poll_once()); await entered.wait(); stop = asyncio.create_task(pump.close()); await asyncio.sleep(0)
        release.set()
        with self.assertRaises(BarrierError): await task
        await stop; self.assertEqual(acks, [])

if __name__ == '__main__':
    if sys.argv[1:] == ['--vectors']:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536: raise SystemExit(2)
        values = json.loads(raw)
        print(json.dumps([connect_password(item['master'], item['material']) for item in values]))
    elif sys.argv[1:] == ['--control-vectors']:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536: raise SystemExit(2)
        value = json.loads(raw)
        barrier = NativeBarrier(value['identity'], value['master'], initial_state(value['identity']), lambda _: None, lambda: value['now'])
        barrier.bind_observer(lambda: []); barrier.mark_ready()
        print(json.dumps([barrier.control(command) for command in value['commands']]))
    else:
        result = unittest.TextTestRunner(stream=io.StringIO()).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
        print(json.dumps({'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors), 'skips': len(result.skipped)}))
        if not result.wasSuccessful():
            for case, detail in result.failures + result.errors:
                print(case.id() + '\n' + detail, file=sys.stderr)
            raise SystemExit(1)
