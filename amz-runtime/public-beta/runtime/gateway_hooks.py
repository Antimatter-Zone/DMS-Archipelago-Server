"""Pure owned hook adapters for pinned MultiServer54803/e157abab only.

No engine import, source patching, production loader, timer or automatic start.
The separately reviewed loader must hash source BEFORE importing/installing.
"""
import asyncio
import copy
import hmac
import logging
import re
from gateway_barrier import BarrierError, canonical, require

class RedactedConnect(dict):
    def __repr__(self):
        return '<redacted native Connect>'
    __str__ = __repr__

class Redactor:
    """Mandatory Public log defense in addition to the refusal mapping."""
    def __init__(self, master):
        self._master = master
    def __call__(self, value):
        text = str(value).replace(self._master, '[REDACTED]')
        return re.sub(r'amz1_[a-f0-9-]{36}_[A-Za-z0-9_-]{43}', '[REDACTED]', text)

def install_log_redaction(master):
    """Explicit Public lifecycle, required BEFORE the gated engine import."""
    redact, previous = Redactor(master), logging.getLogRecordFactory()
    def factory(*args, **kwargs):
        record = previous(*args, **kwargs)
        try:
            record.msg = redact(record.getMessage())
        except BaseException:
            record.msg = 'native_log_redacted'
        record.args = ()
        if record.exc_info or record.exc_text:
            record.msg += ' [sanitized exception]'
        record.exc_info, record.exc_text, record.stack_info = None, None, None
        return record
    logging.setLogRecordFactory(factory)
    def stop():
        if logging.getLogRecordFactory() is factory:
            logging.setLogRecordFactory(previous)
    return stop

class PublicHooks:
    def __init__(self, barrier, process_client_cmd, on_client_joined, on_client_disconnected):
        require(all(callable(fn) for fn in (process_client_cmd, on_client_joined, on_client_disconnected)))
        self.barrier = barrier
        self._process, self._joined, self._disconnected = process_client_cmd, on_client_joined, on_client_disconnected
        self._context = None
        self._tasks = {}

    def bind_context(self, context):
        require(self._context is None, 'native_context_changed')
        self._context = context
        def observe():
            require(context is self._context)
            return [client for client in context.endpoints if client.auth and not {'Tracker', 'TextOnly', 'HintGame'}.intersection(client.tags)]
        self.barrier.bind_observer(observe)

    async def process_client_cmd(self, context, client, args):
        require(context is self._context and type(args) is dict and type(args.get('cmd')) is str, 'native_packet_rejected')
        command = args['cmd']
        if command == 'Connect':
            # consume() is synchronous and durable before the first await.
            value = self.barrier.consume(client, args)
            self._tasks[client] = asyncio.current_task()
            try:
                require(hmac.compare_digest(context.password, self.barrier._master) and
                        context.connect_names.get(value['slotAlias']) == (value['team'], value['slot']) and context.games.get(value['slot']) == value['game'], 'native_context_changed')
                private = RedactedConnect(args)
                private['password'] = context.password
                await self._process(context, client, private)
            except BaseException:
                # Do not allow an upstream exception's text/args/traceback to
                # carry either the native master or correlation proof outward.
                raise BarrierError('native_connect_failed') from None
            finally:
                self._tasks.pop(client, None)
                self.barrier.handler_finished(client)
            return
        if command == 'ConnectUpdate':
            require(set(args) <= {'cmd', 'tags', 'items_handling'} and
                    ('tags' not in args or type(args['tags']) in (set, list) and all(type(tag) is str for tag in args['tags']) and
                     not {'Tracker', 'TextOnly', 'HintGame'}.intersection(args['tags'])), 'native_packet_rejected')
        require(getattr(client, 'auth', False) or command == 'GetDataPackage', 'native_packet_rejected')
        await self._process(context, client, args)

    async def on_client_joined(self, context, client):
        require(context is self._context, 'native_context_changed')
        # Original Connect already changed native lists/auth, before awaiting
        # this hook. Generation/baseline commit precedes any original join IO.
        self.barrier.accepted(client)
        await self._joined(context, client)

    async def on_client_disconnected(self, context, client):
        require(context is self._context, 'native_context_changed')
        # Context.disconnect removed native endpoint/slot membership first.
        self.barrier.disconnected(client)
        await self._disconnected(context, client)

    async def drain(self, command, timeout=1.0):
        """Retained gate exists before this call. Timeout is never success."""
        require(0 < timeout <= 3)
        selected = []
        for client, key in list(self.barrier._clients.items()):
            row = self.barrier.state['preparations'][key]
            if command['command'] == 'idle_fence':
                match = not row['accepted']  # Never evict a joined game for idle.
            elif command['command'] == 'detach_slot':
                match = key == command['payload']['material']['reservationId']
            elif command['command'] == 'revoke_slot':
                match = all(row['material'][field] == command['payload'][field] for field in ('actorUuid', 'slotAlias', 'credentialRevision'))
            else:
                match = False
            if match:
                selected.append(client)
        async def close(client):
            await client.socket.close()
            task = self._tasks.get(client)
            if task and task is not asyncio.current_task():
                await asyncio.shield(task)
        try:
            await asyncio.wait_for(asyncio.gather(*(close(client) for client in selected), return_exceptions=False), timeout)
            return True
        except BaseException:
            return False

class ControlPump:
    """Explicit single-flight lifecycle over the concrete fixed file transport.

    No timer on import, no implicit NativeFiles creation or empty journal.
    """
    def __init__(self, files, barrier, hooks):
        self.files, self.barrier, self.hooks = files, barrier, hooks
        self._last, self._task, self._closed = None, None, False

    async def poll_once(self):
        require(not self._closed, 'native_control_stopped')
        if self._task:
            return await asyncio.shield(self._task)
        async def work():
            command = self.files.read_control()
            if command is None:
                return False
            digest = canonical(command)
            if digest == self._last:
                return False
            result = self.barrier.control(command)
            if command['command'] in ('idle_fence', 'detach_slot', 'revoke_slot'):
                await self.hooks.drain(command)
                # Re-evaluate native state; an elapsed command or unknown
                # handler cannot be converted into a successful receipt.
                result = self.barrier.control(command)
            require(not self._closed, 'native_control_stopped')
            self.files.publish_ack(result)
            self._last = digest
            return True
        self._task = asyncio.create_task(work())
        try:
            return await asyncio.shield(self._task)
        finally:
            if self._task and self._task.done():
                self._task = None

    async def close(self):
        self._closed = True
        if self._task:
            await asyncio.gather(self._task, return_exceptions=True)
