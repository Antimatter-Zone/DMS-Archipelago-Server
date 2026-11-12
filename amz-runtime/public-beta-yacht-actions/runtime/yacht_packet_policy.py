"""Fresh Yacht action-runtime frame policy. No engine imports or IO on import.

The loader installs this only in the separately pinned Yacht-only image. Every
packet is checked before native decode returns anything to the dispatch loop.
"""
import hashlib
import json

SCHEMA = 'amz.ap.public-beta.yacht-read-only-packets.v1'
ENGINE_SHA = 'e157abab8a56351d58f1cf5a84c6c2a9144d295956d6be08cbd5811c7a2932de'
NETUTILS_SHA = '0c4acb2e0a434bcd91ed03d6e9c66f5d119597b3feb300620241f206bd7f0b06'
MAXIMUM = 256 * 1024
COMMANDS = frozenset(('Connect', 'ConnectUpdate', 'Sync', 'GetDataPackage'))


class PacketRefused(RuntimeError):
    pass


def need(value):
    if not value:
        raise PacketRefused('yacht_frame_refused')


def exact(value, required, optional=()):
    need(type(value) is dict and set(required) <= set(value) <= set(required) | set(optional))


def integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def string(value, maximum):
    if type(value) is not str or not 0 < len(value) <= maximum:
        return False
    try:
        # ASCII JSON escapes can decode to non-scalar surrogate code points
        # even though the raw frame itself was valid UTF8.
        value.encode('utf-8', errors='strict')
    except UnicodeError:
        return False
    return all(32 <= ord(c) != 127 for c in value)


def tags(value):
    # Fixed full item stream; no tracker/text/hint/death-link mode negotiation.
    need(type(value) is list and value == ['AP'])


def packet(value):
    need(type(value) is dict and type(value.get('cmd')) is str and value['cmd'] in COMMANDS)
    command = value['cmd']
    if command == 'Connect':
        exact(value, ('cmd', 'name', 'game', 'password', 'uuid', 'version', 'tags', 'items_handling'), ('slot_data',))
        need(string(value['name'], 16) and all(c.isascii() and (c.isalnum() or c in '_-') for c in value['name']))
        need(value['game'] == 'Yacht Dice' and string(value['password'], 128) and string(value['uuid'], 128))
        tags(value['tags']); need(type(value['items_handling']) is int and value['items_handling'] == 7)
        need('slot_data' not in value or value['slot_data'] is True)
        version = value['version']; exact(version, ('class', 'major', 'minor', 'build'))
        need(version['class'] == 'Version' and all(integer(version[k], 1000) for k in ('major', 'minor', 'build')))
        need((version['major'], version['minor'], version['build']) == (0, 6, 8))
    elif command == 'ConnectUpdate':
        exact(value, ('cmd',), ('tags', 'items_handling'))
        need(len(value) > 1)
        if 'tags' in value: tags(value['tags'])
        if 'items_handling' in value: need(type(value['items_handling']) is int and value['items_handling'] == 7)
    elif command == 'Sync':
        exact(value, ('cmd',))
    else:
        exact(value, ('cmd', 'games'))
        games = value['games']
        need(type(games) is list and 1 <= len(games) <= 2 and all(type(v) is str for v in games) and
             len(set(games)) == len(games) and set(games) <= {'Archipelago', 'Yacht Dice'})


def validate_frame(raw):
    need(type(raw) is str and 0 < len(raw) <= MAXIMUM)
    try:
        need(len(raw.encode('utf-8', errors='strict')) <= MAXIMUM)
        def pairs(values):
            out = {}
            for key, value in values:
                need(key not in out); out[key] = value
            return out
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: need(False))
        need(type(value) is list and 1 <= len(value) <= 32)
        for item in value: packet(item)
        return value
    except (UnicodeError, ValueError, RecursionError, TypeError, KeyError):
        raise PacketRefused('yacht_frame_refused') from None


def _decode_frame(raw, original, version_type):
    """Data-only transform; install supplies only the exact enrolled decoder."""
    parsed = validate_frame(raw)  # Validate ALL packets before any object hook.
    result = original(raw)
    need(type(result) is list and len(result) == len(parsed))
    for before, after in zip(parsed, result):
        need(type(after) is dict and set(after) == set(before))
        projected = dict(after)
        if before['cmd'] == 'Connect':
            version = projected['version']
            need(type(version) is version_type and tuple(version) == (0, 6, 8))
            projected['version'] = before['version']
        need(projected == before)
    return result


def install(module, netutils, native_source, net_source, code_identity):
    """Enroll exact ABI, then replace ONLY this Yacht module's decode binding.

    NetUtils itself and generic runtime profiles remain unchanged. Current
    per-client authorization/Connect consumption stays in the enrolled hooks.
    """
    need(type(native_source) is bytes and type(net_source) is bytes and callable(code_identity))
    need(hashlib.sha256(native_source.replace(b'\r\n', b'\n')).hexdigest() == ENGINE_SHA and
         hashlib.sha256(net_source.replace(b'\r\n', b'\n')).hexdigest() == NETUTILS_SHA)
    original, version_type = netutils.decode, netutils.Version
    expected = compile(net_source, '/engine/NetUtils.py', 'exec', dont_inherit=True, optimize=0)
    expected_decode = next((v for v in expected.co_consts if type(v).__name__ == 'code' and v.co_name == 'decode'), None)
    expected_server = next((v for v in compile(native_source, '/engine/MultiServer.py', 'exec', dont_inherit=True, optimize=0).co_consts
                            if type(v).__name__ == 'code' and v.co_name == 'server'), None)
    need(expected_decode is not None and expected_server is not None and module.decode is original and
         original.__module__ == 'NetUtils' and code_identity(original.__code__) == code_identity(expected_decode) and
         code_identity(module.server.__code__) == code_identity(expected_server))
    def decode(raw):
        need(module.decode is decode and netutils.decode is original and
             code_identity(original.__code__) == code_identity(expected_decode))
        return _decode_frame(raw, original, version_type)
    module.decode = decode
    def current():
        need(module.decode is decode and netutils.decode is original and
             code_identity(original.__code__) == code_identity(expected_decode) and
             code_identity(module.server.__code__) == code_identity(expected_server))
    return current
