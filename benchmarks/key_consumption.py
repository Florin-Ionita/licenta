"""Key-consumption ratio: key bits per plaintext bit, as a function of payload.

For each payload size we open one QTLS session, send one record, and read
exactly how many bytes of OTP material the record layer consumed. The ratio
(key bits / plaintext bits) approaches 1.0 for large payloads (the WC tag is
amortised) and is dominated by the constant 16-byte tag for tiny ones.

The KME key per *session* isn't counted here -- only per-record consumption.
The session-key cost is a property of the handshake, reported separately.
"""

from __future__ import annotations

from benchmarks.common import BenchConfig, _BenchStack, open_qtls_pair, write_csv


async def run(cfg: BenchConfig) -> dict:
    rows = []
    summary = []
    for payload in cfg.keyconsumption_payloads:
        # Fresh session per payload so the OTP offset is always zero on entry,
        # making the consumption accounting clean. Sized so even the largest
        # payload (extreme profile: 64 KiB) fits in one direction's stream.
        key_size_bits = max(8192, (payload + 64) * 8 * 4)
        async with _BenchStack(prefill_blocks=2,
                                key_size_bits=key_size_bits) as stack:
            c, s, srv = await open_qtls_pair(stack)
            try:
                # Read the per-direction OTP stream's offset before and after
                # one record -- exact accounting, no estimation.
                stream = c._send._cipher._stream  # type: ignore[attr-defined]
                before = stream.consumed
                await c.send(b"x" * payload)
                after = stream.consumed
                bytes_used = after - before
                ratio = bytes_used / payload if payload else float("inf")
                rows.append([payload, bytes_used, ratio])
                summary.append({"payload": payload,
                                "key_bytes": bytes_used,
                                "ratio": ratio})
            finally:
                await c.close(); await s.close()
                srv.close()
                with __import__("contextlib").suppress(Exception):
                    await srv.wait_closed()
    write_csv("key_consumption",
              ["payload_bytes", "key_bytes_consumed", "key_per_plaintext_ratio"],
              rows)
    return {"samples": summary}
