"""Spam checks shared with the template filter.

Copied so this app stands alone. A transaction that fails to parse is kept.
The sidecar does not build a template. It only uses tx_reject_reason.
"""
from __future__ import annotations

import hashlib
from typing import Optional

# A shape file may name one of these. The function is compiled into this
# program. A downloaded file that names anything else is stored and does not run.
# Shape files are data. Nothing in this program executes text from one.
CHECKERS = frozenset({
    "ark-exit",
    "package-paid",
    "commitment-32",
    "empty-runestone",
    "empty-opreturn",
    "dust-sweep",
    "lightning-anchor-sweep",
    "p2a-sweep",
    "powpeg-flyover",
    "consolidation",
    "cat21",
    "runestone",
    "counterparty",
    "stamps",
    "fake-multisig",
    "unverified-key",
    "dead-branch",
    "bare-envelope",
    "bare-inscription",
    "json-token",
    "omni",
    "dust-p2wsh-run",
    "dust-output",
    "min-fee",
    "fan-out",
    "dust-spray",
    "opreturn-stack",
    "data-heavy",
    "opreturn-text",
    "opreturn-data",
    "swap-memo",
    "babylon-tag",
    "core-dao-tag",
    "many-sigs",
})
SHAPE_FIELDS = ("id", "slug", "kind", "carry", "title", "from", "schema", "note", "checker", "parent", "child")


def sanitize_shape(shape: dict) -> dict:
    """Keep data fields only. Drop a code string, or a checker this copy does not have."""
    if not isinstance(shape, dict):
        return {}
    row = {key: shape[key] for key in SHAPE_FIELDS if key in shape}
    if not isinstance(row.get("schema"), dict):
        row.pop("schema", None)
    checker = row.get("checker")
    if not isinstance(checker, str) or checker not in CHECKERS:
        row.pop("checker", None)
    return row


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _read_varint(buf: bytes, off: int) -> tuple[int, int]:
    if off >= len(buf):
        raise ValueError("varint")
    n = buf[off]
    off += 1
    if n < 0xFD:
        return n, off
    if n == 0xFD:
        if off + 2 > len(buf):
            raise ValueError("varint")
        return int.from_bytes(buf[off:off + 2], "little"), off + 2
    if n == 0xFE:
        if off + 4 > len(buf):
            raise ValueError("varint")
        return int.from_bytes(buf[off:off + 4], "little"), off + 4
    raise ValueError("varint")


def _push_len(script: bytes, off: int) -> tuple[int, int]:
    if off >= len(script):
        raise ValueError("push")
    op = script[off]
    off += 1
    if 0 < op < 0x4C:
        return op, off
    if op == 0x4C:
        if off >= len(script):
            raise ValueError("push")
        return script[off], off + 1
    if op == 0x4D:
        if off + 2 > len(script):
            raise ValueError("push")
        return int.from_bytes(script[off:off + 2], "little"), off + 2
    if op == 0x4E:
        if off + 4 > len(script):
            raise ValueError("push")
        n = int.from_bytes(script[off:off + 4], "little")
        if n > 1_000_000:
            raise ValueError("push")
        return n, off + 4
    raise ValueError("not a push")


def _bytes_repeat(data: bytes) -> bool:
    if len(data) < 6:
        return False
    counts = [0] * 256
    run = 1
    for i, b in enumerate(data):
        counts[b] += 1
        if i and b == data[i - 1]:
            run += 1
            if run >= 6:
                return True
        else:
            run = 1
    return any(c >= 8 for c in counts)


def _program_is_data(script: bytes) -> bool:
    if len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
        prog = script[2:]
    elif len(script) == 34 and script[0] in (0x00, 0x51) and script[1] == 0x20:
        prog = script[2:]
    else:
        return False
    if not any(prog):
        return False
    return _bytes_repeat(prog)


def _payload_is_token(payload: bytes, flags: dict) -> bool:
    if flags.get("rejecttokenmessages") and len(payload) >= 4 and payload[:4] == b"omni":
        return True
    if flags.get("rejectcounterparty") and len(payload) >= 8 and payload[:8] == b"CNTRPRTY":
        return True
    if flags.get("rejectstamps") and len(payload) >= 6 and payload[:6] == b"stamp:":
        return True
    if flags.get("rejecttokenmessages") and len(payload) >= 8 and payload[0] == ord("{"):
        window = payload[:48]
        for i in range(1, len(window) - 3):
            if window[i:i + 4] == b'"p":':
                return True
    return False


def _script_spam(script: bytes, as_output: bool, flags: dict) -> Optional[str]:
    if flags.get("rejectrunestones") and len(script) >= 2 and script[0] == 0x6A and script[1] == 0x5D:
        return "runestone"
    if len(script) >= 2 and script[0] == 0x6A:
        try:
            off = 1
            push, off = _push_len(script, off)
            if off + push <= len(script) and _payload_is_token(script[off:off + push], flags):
                return "token"
        except ValueError:
            return None
        if flags.get("datacarrier") is False:
            return "datacarrier"
        limit = flags.get("datacarriersize")
        if isinstance(limit, int) and limit >= 0:
            try:
                off = 1
                total = 0
                while off < len(script):
                    push, off = _push_len(script, off)
                    total += push
                    off += push
                if flags.get("datacarrierfullcount"):
                    total = max(0, len(script) - 1)
                if total > limit:
                    return "datacarriersize"
            except ValueError:
                return None
    if flags.get("rejectfakeoutputs") and _program_is_data(script):
        return "fakeoutput"
    if flags.get("permitbarepubkey") is False and as_output and len(script) in (35, 67):
        if script[0] in (0x21, 0x41) and script[-1] == 0xAC and script[0] == len(script) - 2:
            return "barepubkey"
    off = 0
    keys = 0
    only_pushes = True
    try:
        while off < len(script):
            op = script[off]
            if 0 < op <= 0x4E:
                push, off = _push_len(script, off)
                if push == 33:
                    keys += 1
                if off + push > len(script):
                    return None
                off += push
                continue
            off += 1
            if op in (0x75, 0x6D) and only_pushes and flags.get("rejectbareenvelopes"):
                return "bareenvelope"
            if op in (0xAE, 0xAF) and flags.get("rejectfakemultisig"):
                if as_output or keys > 10:
                    return "fakemultisig"
            if flags.get("permitbaremultisig") is False and op in (0xAE, 0xAF) and as_output:
                return "baremultisig"
            if op != 0x00 and not (0x51 <= op <= 0x60):
                only_pushes = False
            if flags.get("rejectdeadbranches") and op == 0x64 and off >= 2 and script[off - 2] == 0x51:
                return "deadbranch"
            if flags.get("rejectdeadbranches") and op == 0x63 and off >= 2 and script[off - 2] == 0x00:
                return "deadbranch"
            if flags.get("rejecttokens") and op == 0x63 and off >= 2 and script[off - 2] == 0x00 and b"\x03ord" in script[:80]:
                return "token"
    except ValueError:
        return None
    return None


def _dust_threshold(script: bytes, sat_per_kvb: int) -> int:
    if not script or script[0] == 0x6A:
        return 0
    n_size = 8 + (1 if len(script) < 0xFD else 3) + len(script)
    witness = (
        (len(script) in (22, 34) and script[0] in (0x00, 0x51))
    )
    if witness:
        n_size += 32 + 4 + 1 + (107 // 4) + 4
    else:
        n_size += 32 + 4 + 1 + 107 + 4
    fee = sat_per_kvb * n_size // 1000
    if fee == 0 and sat_per_kvb > 0:
        fee = 1
    return fee


def _is_taproot_control_block(item: bytes) -> bool:
    """BIP341 tapscript control block: 33 + 32*n bytes, leaf version 0xc0."""
    if len(item) < 33 or (len(item) - 33) % 32:
        return False
    return (item[0] & 0xFE) == 0xC0


def _tapscript(items: list[bytes]) -> Optional[bytes]:
    """The revealed tapscript, when this witness spends a taproot script path."""
    if not items:
        return None
    stack = items[:-1] if items[-1][:1] == b"\x50" else items
    if len(stack) >= 2 and _is_taproot_control_block(stack[-1]):
        return stack[-2]
    return None


def _witness_script(items: list[bytes]) -> Optional[bytes]:
    """The witness item that is a script, or None when the witness has no script.

    Signatures and public keys are not scripts. Parsing them flags ordinary
    spends when those bytes happen to contain OP_DROP or OP_0 OP_IF.
    """
    if not items:
        return None
    stack = items
    if stack[-1][:1] == b"\x50":
        stack = stack[:-1]
    if not stack:
        return None
    if len(stack) >= 2 and _is_taproot_control_block(stack[-1]):
        return stack[-2]
    if len(stack) == 1:
        # A lone 64 or 65 byte item is a Taproot key-path signature.
        if len(stack[0]) in (64, 65):
            return None
        return stack[0]
    if len(stack) == 2 and len(stack[1]) in (33, 65):
        # P2WPKH, and P2SH-P2WPKH: signature then pubkey.
        return None
    return stack[-1]


def _legacy_sigops(script: bytes) -> int:
    count = 0
    off = 0
    while off < len(script):
        op = script[off]
        if 0 < op <= 0x4E:
            push, off = _push_len(script, off)
            off += push
            continue
        off += 1
        if op in (0xAC, 0xAD):
            count += 1
        elif op in (0xAE, 0xAF):
            count += 20
    return count


def _datacarrier_bytes(script: bytes, fullcount: bool) -> int:
    if not script or script[0] != 0x6A:
        return 0
    if fullcount:
        return max(0, len(script) - 1)
    total = 0
    off = 1
    while off < len(script):
        push, off = _push_len(script, off)
        total += push
        off += push
    return total


CONSENSUS_MAX_BLOCK_WEIGHT = 4_000_000
CONSENSUS_MAX_BLOCK_SIGOPS = 80_000
ANCHOR_SCRIPT = bytes.fromhex("51024e73")
# BOLT 3 to_local_anchor / to_remote_anchor, after the 33-byte compressed key.
LIGHTNING_ANCHOR_TAIL = bytes.fromhex("ac736460b268")


def _opreturn_payload(script: bytes) -> bytes | None:
    if not script or script[0] != 0x6A or script == b"\x6a\x5d":
        return None
    try:
        return script[1:] if len(script) == 1 else _pushed(script)
    except ValueError:
        return None


def _pushed(script: bytes) -> bytes:
    out = b""
    off = 1
    while off < len(script):
        push, off = _push_len(script, off)
        out += script[off:off + push]
        off += push
    return out


def _printable(payload: bytes) -> bool:
    return bool(payload) and all(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in payload)


def _named_opreturn(script: bytes, flags: dict) -> str | None:
    payload = _opreturn_payload(script)
    if payload is None:
        return None
    if flags.get("rejectswapmemo") and (payload.startswith(b"=:") or payload.startswith(b"to:")):
        return "swapmemo"
    if flags.get("rejectbabylon") and payload.startswith(b"bbn1"):
        return "babylon"
    if flags.get("rejectcoredao") and payload.startswith(b"SAT+"):
        return "coredao"
    named = payload.startswith((b"omni", b"CNTRPRTY", b"stamp:", b"{", b"bbn1", b"SAT+", b"=:", b"to:"))
    if named or len(payload) > 83:
        return None
    if flags.get("rejectopreturntext") and _printable(payload):
        return "opreturntext"
    if flags.get("rejectopreturndata") and payload and not _printable(payload):
        return "opreturndata"
    return None


def _bare_inscription(script: bytes) -> bool:
    return b"ord" in script and script.endswith(b"\x6d") and b"\x00\x63" not in script


def _ops(script: bytes) -> list[tuple[int, bytes]] | None:
    """Opcodes and the bytes each push carries. None when the script does not parse."""
    ops: list[tuple[int, bytes]] = []
    off = 0
    try:
        while off < len(script):
            op = script[off]
            off += 1
            if 1 <= op <= 75:
                data = script[off:off + op]
                if len(data) != op:
                    return None
                off += op
                ops.append((op, data))
                continue
            if op == 76:
                if off >= len(script):
                    return None
                size = script[off]
                off += 1
                data = script[off:off + size]
                if len(data) != size:
                    return None
                off += size
                ops.append((op, data))
                continue
            if op == 77:
                if off + 2 > len(script):
                    return None
                size = int.from_bytes(script[off:off + 2], "little")
                off += 2
                data = script[off:off + size]
                if len(data) != size:
                    return None
                off += size
                ops.append((op, data))
                continue
            ops.append((op, b""))
        return ops
    except (ValueError, IndexError):
        return None


def _small_number(op: int, data: bytes) -> bool:
    """OP_0, OP_1NEGATE, OP_1 through OP_16, or a push of at most 5 bytes."""
    if op in (0x00, 0x4F) or 0x51 <= op <= 0x60:
        return True
    return 1 <= op <= 75 and 1 <= len(data) <= 5


def _lightning_anchor_script(script: bytes) -> bool:
    """BOLT 3 anchor witness script: a compressed key, then CHECKSIG IFDUP NOTIF 16 CSV ENDIF."""
    return (
        len(script) == 40
        and script[0] == 0x21
        and script[1] in (2, 3)
        and script[34:] == LIGHTNING_ANCHOR_TAIL
    )


def _p2sh(script: bytes) -> bytes:
    digest = hashlib.new("ripemd160", hashlib.sha256(script).digest()).digest()
    return b"\xa9\x14" + digest + b"\x87"


def _input_scripts(raw: bytes) -> list[bytes] | None:
    """The scriptSig of each input, in order."""
    if not raw or len(raw) < 10:
        return None
    try:
        off = 4
        if off + 2 <= len(raw) and raw[off] == 0x00 and raw[off + 1] == 0x01:
            off += 2
        vin, off = _read_varint(raw, off)
        scripts = []
        for _ in range(vin):
            off += 36
            slen, off = _read_varint(raw, off)
            scripts.append(raw[off:off + slen])
            off += slen + 4
        return scripts
    except (ValueError, IndexError):
        return None


def _pushed_script(script_sig: bytes) -> bytes | None:
    """The one item a P2SH scriptSig pushes, when that is all it contains."""
    if not script_sig:
        return None
    op = script_sig[0]
    if 1 <= op <= 75 and len(script_sig) == 1 + op:
        return script_sig[1:]
    return None


def _bare_timelock(script: bytes) -> bool:
    """A leaf that is only a small number and CHECKSEQUENCEVERIFY or CHECKLOCKTIMEVERIFY."""
    ops = _ops(script)
    if ops is None or len(ops) != 2:
        return False
    return _small_number(ops[0][0], ops[0][1]) and ops[1][0] in (0xB1, 0xB2)


def _legacy_multisig_end(ops: list[tuple[int, bytes]], start: int) -> int | None:
    """Index after m <33-byte key>... n CHECKMULTISIG, or None."""
    if start >= len(ops) or not (0x51 <= ops[start][0] <= 0x60):
        return None
    need = ops[start][0] - 0x50
    index = start + 1
    keys = 0
    while index < len(ops) and ops[index][0] == 0x21 and len(ops[index][1]) == 33:
        keys += 1
        index += 1
    if index + 1 >= len(ops) or not (0x51 <= ops[index][0] <= 0x60):
        return None
    total = ops[index][0] - 0x50
    if ops[index + 1][0] != 0xAE or keys != total or need > total or keys < 1:
        return None
    return index + 2


def _is_powpeg_script(script: bytes) -> bool:
    """Rootstock PowPeg: NOTIF multisig ELSE <n> CSV DROP multisig ENDIF, with an optional dropped 32 bytes."""
    ops = _ops(script)
    if not ops:
        return False
    index = 0
    if len(ops) >= 2 and len(ops[0][1]) == 32 and ops[1][0] == 0x75:
        index = 2
    if index >= len(ops) or ops[index][0] != 0x64:
        return False
    index = _legacy_multisig_end(ops, index + 1)
    if index is None or index + 4 > len(ops):
        return False
    if ops[index][0] != 0x67 or not _small_number(ops[index + 1][0], ops[index + 1][1]):
        return False
    if ops[index + 2][0] != 0xB2 or ops[index + 3][0] != 0x75:
        return False
    index = _legacy_multisig_end(ops, index + 4)
    if index is None or index + 1 != len(ops):
        return False
    return ops[index][0] == 0x68


def _key_push(op: int, data: bytes, tapscript: bool) -> bool:
    """A pubkey push: 32 bytes in tapscript, 33 bytes everywhere else."""
    if tapscript:
        return len(data) == 32
    return op == 0x21 and len(data) == 33


def _unverified_key(script: bytes, satisfaction: list[bytes], tapscript: bool) -> bool:
    """Lion's bypass of the key count, without running the script.

    A key beside CHECKSIG is only treated as proven when this spend shows a
    signature-shaped item for it. The two shapes that slip the old count are
    matched directly: OP_DEPTH OP_0NOTEQUAL OP_NOTIF around a key, and a key
    then CHECKSIG DROP fed an empty signature. A tapscript key is 32 bytes.
    A full-size item still counts as a signature here. Verifying it is the
    node's job.
    """
    ops = _ops(script)
    if not ops:
        return False
    for index, (op, _data) in enumerate(ops):
        if op != 0x74 or index + 2 >= len(ops):
            continue
        if ops[index + 1][0] != 0x92 or ops[index + 2][0] != 0x64:
            continue
        level = 1
        for later in ops[index + 3:]:
            if later[0] in (0x63, 0x64):
                level += 1
            elif later[0] == 0x68:
                level -= 1
                if level == 0:
                    break
            elif level == 1 and _key_push(later[0], later[1], tapscript):
                return True
    if any(item == b"" for item in satisfaction):
        for index in range(len(ops) - 2):
            if ops[index + 1][0] == 0xAC and ops[index + 2][0] == 0x75 and _key_push(ops[index][0], ops[index][1], tapscript):
                return True
    if tapscript:
        keys = sum(
            1 for index, (op, data) in enumerate(ops[:-1])
            if len(data) == 32 and ops[index + 1][0] in (0xAC, 0xAD, 0xBA)
        )
        signatures = sum(1 for item in satisfaction if len(item) in (64, 65))
        if keys - signatures > 10:
            return True
    return False


def _powpeg_excuses(script: bytes, flags: dict) -> bool:
    """True when this script is the PowPeg shape and that whitelist is on."""
    return flags.get("whitelist_powpeg") is True and _is_powpeg_script(script)


def _p2wsh(script: bytes) -> bytes:
    return b"\x00\x20" + hashlib.sha256(script).digest()


def _tx_parts(raw: bytes) -> tuple[int, list[tuple[int, bytes]], list[list[bytes]]] | None:
    """Input count, outputs, and one witness stack per input. None when the tx cannot be read."""
    if not raw or len(raw) < 10:
        return None
    try:
        off = 4
        segwit = off + 2 <= len(raw) and raw[off] == 0x00 and raw[off + 1] == 0x01
        if segwit:
            off += 2
        vin, off = _read_varint(raw, off)
        for _ in range(vin):
            off += 36
            slen, off = _read_varint(raw, off)
            off += slen + 4
        vout, off = _read_varint(raw, off)
        outputs = []
        for _ in range(vout):
            value = int.from_bytes(raw[off:off + 8], "little")
            off += 8
            slen, off = _read_varint(raw, off)
            outputs.append((value, raw[off:off + slen]))
            off += slen
        witnesses: list[list[bytes]] = []
        if segwit:
            for _ in range(vin):
                count, off = _read_varint(raw, off)
                items = []
                for _item in range(count):
                    item_len, off = _read_varint(raw, off)
                    items.append(raw[off:off + item_len])
                    off += item_len
                witnesses.append(items)
        return vin, outputs, witnesses
    except (ValueError, IndexError):
        return None


def _output_scripts(raw: bytes) -> list[bytes] | None:
    parts = _tx_parts(raw)
    if parts is None:
        return None
    return [script for _value, script in parts[1]]


def single_opreturn(raw: bytes) -> bool:
    """True when the transaction has one output and that output is an OP_RETURN."""
    parts = _tx_parts(raw)
    if parts is None or len(parts[1]) != 1:
        return False
    return parts[1][0][1][:1] == b"\x6a"


def prevout_scripts(raw: bytes, fetch) -> list[bytes] | None:
    """Script of each input's parent output. fetch(txid) returns that parent as hex, or None."""
    points = tx_input_outpoints(raw)
    if not points:
        return None
    found = []
    cached: dict[str, list[bytes] | None] = {}
    for prev, vout in points:
        txid = prev[::-1].hex()
        if txid not in cached:
            parent = fetch(txid)
            if not isinstance(parent, str) or not parent:
                return None
            try:
                cached[txid] = _output_scripts(bytes.fromhex(parent))
            except ValueError:
                return None
        scripts = cached[txid]
        if scripts is None or vout < 0 or vout >= len(scripts):
            return None
        found.append(scripts[vout])
    return found


def _only_opreturn(outputs: list[tuple[int, bytes]], cap: int) -> bool:
    if len(outputs) != 1:
        return False
    payload = _opreturn_payload(outputs[0][1])
    return payload is not None and len(payload) <= cap


def _lightning_parent(script: bytes, prevout: bytes, script_sig: bytes) -> bool:
    """The parent locks the BOLT 3 anchor script, as P2WSH or as P2SH of that program."""
    program = _p2wsh(script)
    if prevout == program:
        return True
    redeem = _pushed_script(script_sig)
    return redeem == program and prevout == _p2sh(program)


def _is_lightning_anchor_sweep(
    raw: bytes, outputs: list[tuple[int, bytes]], prevouts: list[bytes] | None, flags: dict,
) -> bool:
    """A sweep whose inputs spend BOLT 3 anchors and whose only output is a short OP_RETURN."""
    if flags.get("whitelist_lightning_anchor_sweep") is not True or not prevouts:
        return False
    cap = flags.get("lightning_sweep_payload_max")
    if not isinstance(cap, int) or cap < 0:
        cap = 3
    if not _only_opreturn(outputs, cap):
        return False
    parts = _tx_parts(raw)
    scripts = _input_scripts(raw)
    if (
        parts is None or scripts is None or parts[0] < 1
        or len(prevouts) != parts[0] or len(parts[2]) != parts[0] or len(scripts) != parts[0]
    ):
        return False
    for items, prevout, script_sig in zip(parts[2], prevouts, scripts):
        script = _witness_script(items)
        if script is None or not _lightning_anchor_script(script) or not _lightning_parent(script, prevout, script_sig):
            return False
    return True


def _anchor_leaf(items: list[bytes], prevout: bytes) -> bool:
    """A taproot leaf that is OP_TRUE, or only a small number and a timelock, spent with an empty stack."""
    if len(prevout) != 34 or prevout[:1] != b"\x51":
        return False
    stack = items[:-1] if items and items[-1][:1] == b"\x50" else items
    if len(stack) != 2 or not _is_taproot_control_block(stack[-1]):
        return False
    script = stack[0]
    return script == b"\x51" or _bare_timelock(script)


def _is_p2a_sweep(
    raw: bytes, outputs: list[tuple[int, bytes]], prevouts: list[bytes] | None, flags: dict,
) -> bool:
    """A sweep of a pay-to-anchor output, an OP_TRUE leaf, or a bare timelock leaf."""
    if flags.get("whitelist_p2a_sweep") is not True or not prevouts:
        return False
    cap = flags.get("p2a_sweep_payload_max")
    if not isinstance(cap, int) or cap < 0:
        cap = 4
    if not _only_opreturn(outputs, cap):
        return False
    parts = _tx_parts(raw)
    if parts is None or parts[0] < 1 or len(prevouts) != parts[0] or len(parts[2]) != parts[0]:
        return False
    pairs = list(zip(parts[2], prevouts))
    if all(not items and prevout == ANCHOR_SCRIPT for items, prevout in pairs):
        return True
    return all(_anchor_leaf(items, prevout) for items, prevout in pairs)


def _is_dust_sweep(outputs: list[tuple[int, bytes]], flags: dict) -> bool:
    """One OP_RETURN and nothing else, with a short payload."""
    if flags.get("whitelist_dust_sweep") is not True or len(outputs) != 1:
        return False
    payload = _opreturn_payload(outputs[0][1])
    if payload is None:
        return False
    cap = flags.get("dustsweep_payload_max")
    if not isinstance(cap, int) or cap < 0:
        cap = 4
    return len(payload) <= cap


def _output_whitelisted(script: bytes, reason: str, flags: dict) -> bool:
    """True when an enabled whitelist keeps this output's spam reason."""
    if reason == "runestone" and flags.get("whitelist_empty_runestone") is True and script == b"\x6a\x5d":
        return True
    if reason not in ("datacarrier", "datacarriersize") or not script or script[0] != 0x6A:
        return False
    try:
        payload = _datacarrier_bytes(script, False)
    except ValueError:
        return False
    if flags.get("whitelist_commitment_32") is True and payload == 32:
        return True
    if flags.get("whitelist_empty_opreturn") is True and payload == 0 and script != b"\x6a\x5d":
        return True
    return False


def _is_consolidation(vin: int, outputs: list[tuple[int, bytes]], flags: dict) -> bool:
    """Many inputs and few kept outputs. It does not cancel a runestone or a token."""
    if flags.get("whitelist_consolidation") is not True:
        return False
    need = flags.get("consolidation_inputs_min")
    cap = flags.get("consolidation_outputs_max")
    if not isinstance(need, int) or need <= 0:
        need = 25
    if not isinstance(cap, int) or cap < 0:
        cap = 3
    kept = sum(1 for _value, script in outputs if not script or script[:1] != b"\x6a")
    return vin >= need and kept <= cap


def tx_is_ark_whitelist(raw: bytes, flags: dict, fee: int | None = None) -> bool:
    """True when this tx is the Ark parent the whitelist keeps."""
    if flags.get("whitelist_ark_zero_anchor") is False or not raw or len(raw) < 10:
        return False
    try:
        off = 4
        if off + 2 <= len(raw) and raw[off] == 0x00 and raw[off + 1] == 0x01:
            off += 2
        _vin, off = _read_varint(raw, off)
        for _ in range(_vin):
            off += 36
            slen, off = _read_varint(raw, off)
            off += slen + 4
        vout, off = _read_varint(raw, off)
        outputs = []
        for _ in range(vout):
            value = int.from_bytes(raw[off:off + 8], "little")
            off += 8
            slen, off = _read_varint(raw, off)
            outputs.append((value, raw[off:off + slen]))
            off += slen
    except Exception:
        return False
    return _ark_zero_fee_parent(raw, outputs, fee)


def _ark_zero_fee_parent(raw: bytes, outputs: list[tuple[int, bytes]], fee: int | None) -> bool:
    """True for the low-fee Ark parent this pool wants, not today's high-fee rounds."""
    if fee != 0 or len(raw) < 4:
        return False
    version = int.from_bytes(raw[:4], "little")
    if version != 3:
        return False
    anchors = [(value, script) for value, script in outputs if script == ANCHOR_SCRIPT and value == 0]
    return len(anchors) == 1


def clamp_template_request(req: dict, flags: dict) -> dict:
    """Copy Knots block limits onto the template request, never above consensus."""
    out = dict(req)
    weight = flags.get("blockmaxweight")
    if isinstance(weight, int) and weight > 0:
        out["blockmaxweight"] = min(weight, CONSENSUS_MAX_BLOCK_WEIGHT)
    size = flags.get("blockmaxsize")
    if isinstance(size, int) and size > 0:
        out["blockmaxsize"] = min(size, CONSENSUS_MAX_BLOCK_WEIGHT)
    reserved_weight = flags.get("blockreservedweight")
    if isinstance(reserved_weight, int) and reserved_weight >= 0:
        cap = out.get("blockmaxweight", CONSENSUS_MAX_BLOCK_WEIGHT)
        out["blockreservedweight"] = min(reserved_weight, cap)
    reserved_size = flags.get("blockreservedsize")
    if isinstance(reserved_size, int) and reserved_size >= 0:
        cap = out.get("blockmaxsize", CONSENSUS_MAX_BLOCK_WEIGHT)
        out["blockreservedsize"] = min(reserved_size, cap)
    reserved_sigops = flags.get("blockreservedsigops")
    if isinstance(reserved_sigops, int) and reserved_sigops >= 0:
        out["blockreservedsigops"] = min(reserved_sigops, CONSENSUS_MAX_BLOCK_SIGOPS)
    return out


def package_from_entry(entry: dict) -> tuple[int | None, int | None]:
    """Descendant package fee and vsize when a child is paying for this transaction."""
    if not isinstance(entry, dict) or (entry.get("descendantcount") or 0) <= 1:
        return None, None
    fees = (entry.get("fees") or {}).get("descendant")
    vsize = entry.get("descendantsize")
    if fees is None or not isinstance(vsize, int) or vsize <= 0:
        return None, None
    return int(round(float(fees) * 100_000_000)), vsize


def paid_by_descendant(
    flags: dict, fee_sat: int | None, vsize: int | None,
    package_fee_sat: int | None, package_vsize: int | None,
) -> bool:
    """This transaction is under the fee line and a descendant has lifted the package over it."""
    if not isinstance(fee_sat, int) or not isinstance(vsize, int) or vsize <= 0:
        return False
    if not isinstance(package_fee_sat, int) or not isinstance(package_vsize, int) or package_vsize <= 0:
        return False
    floor = flags.get("package_paid_sat_vb")
    if isinstance(floor, bool) or not isinstance(floor, (int, float)) or floor <= 0:
        floor = 1
    if fee_sat / vsize >= float(floor):
        return False
    return package_fee_sat / package_vsize >= float(floor)


def package_clears_fee(flags: dict, package_fee_sat: int | None, package_vsize: int | None) -> bool:
    """The child's package meets the fee line, so this parent's own fee is not the mark."""
    if flags.get("whitelist_package_paid") is not True:
        return False
    if not isinstance(package_fee_sat, int) or not isinstance(package_vsize, int) or package_vsize <= 0:
        return False
    floor = flags.get("package_paid_sat_vb")
    if isinstance(floor, bool) or not isinstance(floor, (int, float)) or floor <= 0:
        floor = 1
    mark = flags.get("minfeerate_sat_vb")
    need = float(floor)
    if isinstance(mark, (int, float)) and not isinstance(mark, bool) and float(mark) > need:
        need = float(mark)
    return package_fee_sat / package_vsize >= need


def whitelist_items(
    raw: bytes, flags: dict, fee: int | None = None, weight: int | None = None,
    sigops: int | None = None, package_fee_sat: int | None = None,
    package_vsize: int | None = None, descendant_count: int = 0,
    prevouts: list[bytes] | None = None,
) -> int:
    """1 for a single whitelist transaction, 2 when its child is in the mempool."""
    if tx_is_ark_whitelist(raw, flags, fee):
        return 2 if descendant_count > 1 else 1
    quiet = dict(flags)
    touched = False
    for key, value in list(quiet.items()):
        if key.startswith("whitelist_") and value is True:
            quiet[key] = False
            touched = True
    if not touched:
        return 0
    before = tx_reject_reason(
        raw, quiet, fee=fee, weight=weight, sigops=sigops,
        package_fee_sat=package_fee_sat, package_vsize=package_vsize, prevouts=prevouts,
    )
    after = tx_reject_reason(
        raw, flags, fee=fee, weight=weight, sigops=sigops,
        package_fee_sat=package_fee_sat, package_vsize=package_vsize, prevouts=prevouts,
    )
    if before and before != after:
        return 1
    return 0


def tx_reject_reason(
    raw: bytes, flags: dict, fee: int | None = None, weight: int | None = None,
    sigops: int | None = None, package_fee_sat: int | None = None, package_vsize: int | None = None,
    prevouts: list[bytes] | None = None,
) -> Optional[str]:
    """Return a short reason to drop this tx, or None to keep it."""
    if not raw or len(raw) < 10:
        return None
    try:
        off = 4
        segwit = off + 2 <= len(raw) and raw[off] == 0x00 and raw[off + 1] == 0x01
        if segwit:
            off += 2
        vin, off = _read_varint(raw, off)
        input_scripts = []
        for _ in range(vin):
            off += 36
            slen, off = _read_varint(raw, off)
            script = raw[off:off + slen]
            input_scripts.append(script)
            off += slen + 4
        vout, off = _read_varint(raw, off)
        outputs = []
        p2wsh_same = 0
        p2wsh_value = None
        for _ in range(vout):
            value = int.from_bytes(raw[off:off + 8], "little")
            off += 8
            slen, off = _read_varint(raw, off)
            script = raw[off:off + slen]
            off += slen
            outputs.append((value, script))
        # Ark package parent: version 3, miner fee exactly 0, one zero
        # pay-to-anchor. The child spends that anchor and pays the small fee.
        # A high-fee transaction is not this shape, even if it has an anchor.
        # The node stays strict. This parent is inserted with sendrawtransaction
        # and ignore_rejects, not by loosening Knots. This flag does not change the node.
        if flags.get("whitelist_ark_zero_anchor") is not False and _ark_zero_fee_parent(raw, outputs, fee):
            return None
        sat_max = flags.get("fakeoutput_sat_max")
        count_min = flags.get("fakeoutput_count_min")
        if not isinstance(sat_max, int) or sat_max <= 0:
            sat_max = 546
        if not isinstance(count_min, int) or count_min <= 0:
            count_min = 3
        for value, script in outputs:
            reason = _script_spam(script, True, flags)
            if reason is None:
                reason = _named_opreturn(script, flags)
            if reason is None and flags.get("rejectbareinscription") and _bare_inscription(script):
                reason = "bareinscription"
            kept = _is_dust_sweep(outputs, flags) or _is_lightning_anchor_sweep(raw, outputs, prevouts, flags) or _is_p2a_sweep(raw, outputs, prevouts, flags)
            if reason in ("datacarrier", "datacarriersize", "opreturntext", "opreturndata") and kept:
                reason = None
            if reason and not _output_whitelisted(script, reason, flags):
                return reason
            if (
                flags.get("rejectfakeoutputs")
                and len(script) == 34
                and script[0] == 0x00
                and script[1] == 0x20
                and value <= sat_max
            ):
                if p2wsh_value is None or value == p2wsh_value:
                    p2wsh_value = value
                    p2wsh_same += 1
        if flags.get("rejectfakeoutputs") and p2wsh_same >= count_min:
            return "fakeoutput"
        dust_rate = flags.get("dust_sat_per_kvb")
        if flags.get("dust_sift") is not False and isinstance(dust_rate, int) and dust_rate > 0:
            for value, script in outputs:
                if flags.get("permitephemeral") is True and value == 0 and script == ANCHOR_SCRIPT:
                    continue
                if value < _dust_threshold(script, dust_rate) and not _is_consolidation(vin, outputs, flags):
                    return "dust"
        witness_scripts = []
        tapscript_len = 0
        lock_off = off
        if segwit:
            for _ in range(vin):
                stack_n, off = _read_varint(raw, off)
                items = []
                for _k in range(stack_n):
                    item_len, off = _read_varint(raw, off)
                    items.append(raw[off:off + item_len])
                    off += item_len
                revealed = _tapscript(items)
                if revealed is not None:
                    tapscript_len = max(tapscript_len, len(revealed))
                script = _witness_script(items)
                if script is not None:
                    witness_scripts.append(script)
                    stack = items
                    if len(stack) >= 2 and stack[-1][:1] == b"\x50" and _is_taproot_control_block(stack[-2]):
                        stack = stack[:-1]
                    tapscript = len(stack) >= 2 and stack[-2] == script and _is_taproot_control_block(stack[-1])
                    satisfaction = stack[:-2] if tapscript else stack[:-1]
                    if flags.get("rejectfakemultisig") and _unverified_key(script, satisfaction, tapscript):
                        return "unverifiedkey"
                    reason = _script_spam(script, False, flags)
                    if reason == "fakemultisig" and _powpeg_excuses(script, flags):
                        reason = None
                    if reason:
                        return reason
            lock_off = off
        for script in input_scripts:
            reason = _script_spam(script, False, flags)
            if reason == "fakemultisig" and _powpeg_excuses(script, flags):
                reason = None
            if reason:
                return reason
        if flags.get("rejectparasites") and lock_off + 4 <= len(raw):
            locktime = int.from_bytes(raw[lock_off:lock_off + 4], "little")
            if locktime == 21:
                return "parasite"
        scripts = [script for _value, script in outputs] + input_scripts + witness_scripts
        limit = flags.get("maxscriptsize")
        if isinstance(limit, int) and limit >= 0:
            for script in scripts:
                if len(script) > limit:
                    return "scriptsize"
        legacy_limit = flags.get("maxtxlegacysigops")
        if isinstance(legacy_limit, int) and legacy_limit >= 0:
            legacy = sum(_legacy_sigops(script) for script in input_scripts)
            legacy += sum(_legacy_sigops(script) for _value, script in outputs)
            if legacy > legacy_limit:
                return "legacysigops"
        if flags.get("permitbaredatacarrier") is False and outputs and all(script[:1] == b"\x6a" for _value, script in outputs):
            if not (_is_lightning_anchor_sweep(raw, outputs, prevouts, flags) or _is_p2a_sweep(raw, outputs, prevouts, flags)):
                return "baredatacarrier"
        if flags.get("permitbareanchor") is False and outputs and all(script == ANCHOR_SCRIPT for _value, script in outputs):
            return "bareanchor"
        per_sigop = flags.get("bytespersigop")
        if isinstance(per_sigop, int) and per_sigop > 0 and isinstance(sigops, int) and sigops > 0:
            vsize = max(1, int(weight) // 4) if isinstance(weight, int) and weight > 0 else len(raw)
            if vsize < sigops * per_sigop:
                return "bytespersigop"
        cost = flags.get("datacarriercost")
        rate = flags.get("minfeerate_sat_vb")
        if isinstance(cost, int) and cost > 0 and isinstance(rate, (int, float)) and isinstance(fee, int) and isinstance(weight, int):
            data_bytes = sum(_datacarrier_bytes(script, bool(flags.get("datacarrierfullcount"))) for _value, script in outputs)
            if data_bytes:
                effective_vsize = (weight + data_bytes * cost) / 4
                if fee < rate * effective_vsize:
                    return "datacarriercost"
        if flags.get("minfee_sift") is not False and isinstance(rate, (int, float)) and rate > 0 and isinstance(fee, int) and isinstance(weight, int) and weight > 0:
            if fee < float(rate) * max(1, weight / 4) and not package_clears_fee(flags, package_fee_sat, package_vsize):
                return "minfeerate"
        # One or two inputs paying many kept outputs. OP_RETURN is not kept.
        # Coinjoins have more inputs than the cap, so they are not this shape.
        if flags.get("rejectfanout"):
            need = flags.get("fanout_outputs_min")
            cap = flags.get("fanout_inputs_max")
            if isinstance(need, int) and need > 0 and isinstance(cap, int) and cap > 0:
                kept = sum(1 for _value, script in outputs if not script or script[:1] != b"\x6a")
                if vin <= cap and kept >= need and not _is_consolidation(vin, outputs, flags):
                    return "fanout"
        # Many outputs under a sat line. A zero output is an anchor, not spray.
        if flags.get("rejectdustspray"):
            need = flags.get("dustspray_count_min")
            ceiling = flags.get("dustspray_sat_max")
            if isinstance(need, int) and need > 0 and isinstance(ceiling, int) and ceiling > 0:
                tiny = sum(1 for value, script in outputs if script[:1] != b"\x6a" and 0 < value < ceiling)
                if tiny >= need and not _is_consolidation(vin, outputs, flags):
                    return "dustspray"
        if flags.get("rejectopreturnstack"):
            need = flags.get("opreturn_count_min")
            if isinstance(need, int) and need > 1:
                count = sum(1 for _value, script in outputs if script[:1] == b"\x6a")
                if count >= need:
                    return "opreturnstack"
        if flags.get("rejectmanysigs") and isinstance(sigops, int):
            need = flags.get("manysigs_min")
            if not isinstance(need, int) or need <= 0:
                need = 100
            if sigops >= need:
                return "manysigs"
        if flags.get("rejectheavytapscript"):
            need = flags.get("tapscript_bytes_min")
            if isinstance(need, int) and need > 0 and tapscript_len >= need:
                return "heavytapscript"
    except (ValueError, IndexError):
        return None
    return None


def witness_commitment_hex(wtxid_hexes: list[str]) -> str:
    """BIP141 commitment for a coinbase whose witness reserved value is 32 zeros.

    wtxid hex strings are the getblocktemplate display order. The merkle uses
    the reversed bytes, then SHA256d(root || 32 zero bytes).
    """
    level = [b"\x00" * 32]
    for hx in wtxid_hexes:
        raw = bytes.fromhex(hx)
        level.append(raw[::-1])
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    commit = _sha256d(level[0] + (b"\x00" * 32))
    return "6a24aa21a9ed" + commit.hex()


# Knots default -blockreservedweight. The coinbase has to fit under weightlimit.
COINBASE_RESERVE_WEIGHT = 8000


def weight_ceiling(weightlimit: int, reserve: int = COINBASE_RESERVE_WEIGHT) -> int:
    if weightlimit <= reserve:
        return 0
    return weightlimit - reserve


def tx_vsize_bytes(tx: dict) -> int:
    data = tx.get("data")
    if isinstance(data, str):
        return len(data) // 2
    return 0


def tx_input_outpoints(raw: bytes) -> list[tuple[bytes, int]] | None:
    """Prevouts this transaction spends. None when the raw tx cannot be read."""
    if not raw or len(raw) < 10:
        return None
    try:
        off = 4
        if off + 2 <= len(raw) and raw[off] == 0x00 and raw[off + 1] == 0x01:
            off += 2
        vin, off = _read_varint(raw, off)
        points = []
        for _ in range(vin):
            if off + 36 > len(raw):
                return None
            prev = raw[off:off + 32]
            vout = int.from_bytes(raw[off + 32:off + 36], "little")
            off += 36
            slen, off = _read_varint(raw, off)
            if off + slen + 4 > len(raw):
                return None
            off += slen + 4
            points.append((prev, vout))
        return points
    except (ValueError, IndexError):
        return None


def _template_outpoints(tx: dict) -> list[tuple[bytes, int]] | None:
    data = tx.get("data")
    if not isinstance(data, str) or not data:
        return None
    try:
        raw = bytes.fromhex(data)
    except ValueError:
        return None
    return tx_input_outpoints(raw)


def _tx_fee(tx: dict) -> int:
    try:
        return int(tx.get("fee") or 0)
    except (TypeError, ValueError):
        return 0


def _spends_removed(tx: dict, removed: set[str]) -> bool:
    """True when this transaction spends one we are taking out of the template."""
    if any(parent in removed for parent in (tx.get("depends_txids") or [])):
        return True
    points = _template_outpoints(tx)
    if not points:
        return False
    hashes: set[bytes] = set()
    for parent in removed:
        try:
            raw = bytes.fromhex(parent)
        except ValueError:
            continue
        if len(raw) == 32:
            hashes.add(raw)
            hashes.add(bytes(reversed(raw)))
    return any(prev in hashes for prev, _vout in points)


def _without(txs: list, gone: set[str]) -> list:
    return [tx for tx in txs if tx["txid"] not in gone]


def _measure(txs: list) -> tuple[set[str], dict[tuple[bytes, int], str], int, int, int]:
    have: set[str] = set()
    owner: dict[tuple[bytes, int], str] = {}
    total = total_size = total_sigops = 0
    for tx in txs:
        have.add(tx["txid"])
        points = _template_outpoints(tx)
        if points:
            for point in points:
                owner[point] = tx["txid"]
        total += int(tx["weight"])
        total_size += tx_vsize_bytes(tx)
        total_sigops += int(tx.get("sigops") or 0)
    return have, owner, total, total_size, total_sigops


def _fits(
    total: int,
    total_size: int,
    total_sigops: int,
    weight: int,
    size: int,
    sigops: int,
    ceiling: int,
    size_ceiling: int | None,
    sigop_ceiling: int | None,
) -> bool:
    if total + weight > ceiling:
        return False
    if size_ceiling is not None and total_size + size > size_ceiling:
        return False
    if sigop_ceiling is not None and total_sigops + sigops > sigop_ceiling:
        return False
    return True


def take_refill(
    kept: list,
    candidates: list,
    ceiling: int,
    banned: set,
    size_ceiling: int | None = None,
    sigop_ceiling: int | None = None,
) -> list:
    """Append candidates that pass the first filter's ban and still fit.

    `candidates` are in the node's order. A candidate is skipped when it was
    filtered, when a parent is missing, or when it would pass a block limit
    even after making room.

    A later snapshot can carry a replace-by-fee of a transaction the first
    snapshot kept. That replacement takes the input. The old transaction and
    anything that spends it leave. Lower-fee transactions are dropped when
    the replacement needs the room. Two newcomers that spend one input keep
    the first, which is the node's order. The caller checks the finished
    list with the node before a gateway receives it.
    """
    original = {tx["txid"] for tx in kept}
    out = list(kept)
    have, owner, total, total_size, total_sigops = _measure(out)

    def _commit(txs: list) -> None:
        nonlocal out, have, owner, total, total_size, total_sigops
        out = txs
        have, owner, total, total_size, total_sigops = _measure(out)

    for tx in candidates:
        txid = tx["txid"]
        if txid in have or txid in banned:
            continue
        parents = tx.get("depends_txids") or []
        if any(parent not in have for parent in parents):
            continue
        points = _template_outpoints(tx)
        if points is None and isinstance(tx.get("data"), str) and tx.get("data"):
            continue
        weight = int(tx["weight"])
        size = tx_vsize_bytes(tx)
        sigops = int(tx.get("sigops") or 0)
        conflicting = {owner[point] for point in points or [] if point in owner}
        newcomers = conflicting - original
        if newcomers:
            print(f"refill skipped {txid} spent input already taken by {','.join(sorted(newcomers))}", flush=True)
            continue
        base = out
        if conflicting:
            gone = set(conflicting)
            changed = True
            while changed:
                changed = False
                for old in base:
                    if old["txid"] in gone:
                        continue
                    if _spends_removed(old, gone):
                        gone.add(old["txid"])
                        changed = True
            base = _without(base, gone)
            if any(parent not in {item["txid"] for item in base} for parent in parents):
                continue
        trial = list(base)
        have_t, owner_t, total_t, size_t, sig_t = _measure(trial)
        kicked: list[set[str]] = []
        if conflicting:
            protected = set(parents)
            stack = list(parents)
            while stack:
                pid = stack.pop()
                if pid in protected and pid not in parents:
                    continue
                protected.add(pid)
                for item in trial:
                    if item["txid"] == pid:
                        stack.extend(item.get("depends_txids") or [])
            while not _fits(total_t, size_t, sig_t, weight, size, sigops, ceiling, size_ceiling, sigop_ceiling):
                victims = [
                    item for item in trial
                    if item["txid"] not in protected and _tx_fee(item) < _tx_fee(tx)
                ]
                if not victims:
                    break
                victim = min(victims, key=_tx_fee)
                drop = {victim["txid"]}
                changed = True
                while changed:
                    changed = False
                    for item in trial:
                        if item["txid"] in drop or item["txid"] in protected:
                            continue
                        if _spends_removed(item, drop):
                            drop.add(item["txid"])
                            changed = True
                trial = _without(trial, drop)
                have_t, owner_t, total_t, size_t, sig_t = _measure(trial)
                kicked.append(drop)
        if not _fits(total_t, size_t, sig_t, weight, size, sigops, ceiling, size_ceiling, sigop_ceiling):
            continue
        if conflicting:
            print(f"refill replaced {','.join(sorted(conflicting))} with {txid}", flush=True)
        for drop in kicked:
            print(f"refill dropped {','.join(sorted(drop))} to fit {txid}", flush=True)
        trial.append(tx)
        _commit(trial)
    return out
