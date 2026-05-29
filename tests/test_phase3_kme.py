"""Phase 3 acceptance tests.

'Done' criterion from the thesis plan:
  * Calling enc_keys on kme_a and dec_keys on kme_b with the returned key_ID
    retrieves *identical* key material on both sides.

Also covered: ETSI-shaped Status, ACL enforcement, no-reuse / wrong-slave
rejection, expiry, malformed input, and a real mTLS certificate round-trip.
"""

from __future__ import annotations

import base64
import time

import pytest
from fastapi.testclient import TestClient

from kme.api import create_kme_app
from kme.network import fan_out_feeder, make_kme_pair
from kme.store import KeyStore
from qkd.keyblock import KeyBlock

MASTER = "SAE-CLIENT"
SLAVE = "SAE-SERVER"


def _seed(store: KeyStore, n: int, material: bytes = b"\xaa" * 32) -> list[str]:
    """Insert ``n`` blocks and return their key_IDs as strings."""
    ids = []
    for _ in range(n):
        b = KeyBlock(material=material, source="abstract-bulk", qber=0.0)
        store.add_block(b)
        ids.append(str(b.key_id))
    return ids


# --------------------------------------------------------------------------
# Status endpoint shape
# --------------------------------------------------------------------------

def test_status_returns_etsi_shape():
    a, b = make_kme_pair()
    a.authorise(MASTER, SLAVE)
    _seed(a, 3)
    client = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))

    r = client.get(f"/api/v1/keys/{SLAVE}/status", headers={"X-SAE-ID": MASTER})
    assert r.status_code == 200
    body = r.json()
    assert body["source_KME_ID"] == "KME-A"
    assert body["target_KME_ID"] == "KME-B"
    assert body["stored_key_count"] == 3
    assert body["master_SAE_ID"] == MASTER
    assert body["slave_SAE_ID"] == SLAVE


def test_missing_sae_identity_is_rejected():
    a, b = make_kme_pair()
    client = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    r = client.get(f"/api/v1/keys/{SLAVE}/status")  # no X-SAE-ID
    assert r.status_code == 401


# --------------------------------------------------------------------------
# THE core criterion: enc on A, dec on B -> identical material
# --------------------------------------------------------------------------

def test_enc_on_a_then_dec_on_b_returns_identical_material():
    a, b = make_kme_pair()
    # Both KMEs share the SAME block (the synchronisation mechanism).
    shared = KeyBlock(material=b"\x13\x37" * 16, source="bb84-visual", qber=0.0)
    a.add_block(shared)
    b.add_block(shared)
    a.authorise(MASTER, SLAVE)
    b.authorise(MASTER, SLAVE)

    client_a = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    client_b = TestClient(create_kme_app(b, peer_kme_id=a.kme_id))

    # Master pulls from KME-A.
    r1 = client_a.post(
        f"/api/v1/keys/{SLAVE}/enc_keys",
        json={"number": 1},
        headers={"X-SAE-ID": MASTER},
    )
    assert r1.status_code == 200, r1.text
    enc = r1.json()["keys"][0]
    key_id = enc["key_ID"]
    master_material = base64.b64decode(enc["key"])

    # Slave fetches the SAME key_ID from KME-B.
    r2 = client_b.post(
        f"/api/v1/keys/{MASTER}/dec_keys",
        json={"key_IDs": [{"key_ID": key_id}]},
        headers={"X-SAE-ID": SLAVE},
    )
    assert r2.status_code == 200, r2.text
    dec = r2.json()["keys"][0]
    slave_material = base64.b64decode(dec["key"])

    assert dec["key_ID"] == key_id
    assert master_material == slave_material  # <-- the whole point of Phase 3


# --------------------------------------------------------------------------
# Security properties
# --------------------------------------------------------------------------

def test_unauthorised_master_is_rejected():
    a, b = make_kme_pair()
    _seed(a, 1)  # no authorise() call
    client = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    r = client.post(
        f"/api/v1/keys/{SLAVE}/enc_keys",
        json={"number": 1},
        headers={"X-SAE-ID": MASTER},
    )
    # ETSI 014 lists only 400/401/503 for enc_keys; ACL refusal -> 401.
    assert r.status_code == 401


def test_slave_cannot_fetch_unactivated_key():
    a, b = make_kme_pair()
    ids = _seed(a, 1)
    client = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    # Slave asks for a key the master never pulled -> 400.
    r = client.post(
        f"/api/v1/keys/{MASTER}/dec_keys",
        json={"key_IDs": [{"key_ID": ids[0]}]},
        headers={"X-SAE-ID": SLAVE},
    )
    assert r.status_code == 400


def test_wrong_slave_cannot_fetch_reserved_key():
    a, b = make_kme_pair()
    shared = KeyBlock(material=b"k" * 32, source="bb84-visual", qber=0.0)
    a.add_block(shared)
    b.add_block(shared)
    a.authorise(MASTER, SLAVE)

    ca = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    cb = TestClient(create_kme_app(b, peer_kme_id=a.kme_id))
    key_id = ca.post(
        f"/api/v1/keys/{SLAVE}/enc_keys",
        json={"number": 1},
        headers={"X-SAE-ID": MASTER},
    ).json()["keys"][0]["key_ID"]

    # A different SAE tries to fetch the key reserved for SLAVE.
    # ETSI 014 §5.4 mandates 401 when the requester is not the SAE the key
    # was reserved for.
    r = cb.post(
        f"/api/v1/keys/{MASTER}/dec_keys",
        json={"key_IDs": [{"key_ID": key_id}]},
        headers={"X-SAE-ID": "SAE-INTRUDER"},
    )
    assert r.status_code == 401


def test_pool_exhaustion_returns_503_backpressure():
    a, b = make_kme_pair()
    a.authorise(MASTER, SLAVE)  # pool empty
    client = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    r = client.post(
        f"/api/v1/keys/{SLAVE}/enc_keys",
        json={"number": 5},
        headers={"X-SAE-ID": MASTER},
    )
    assert r.status_code == 503  # expected QKD back-pressure, not a crash


def test_malformed_key_id_is_400():
    a, b = make_kme_pair()
    client = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    r = client.post(
        f"/api/v1/keys/{MASTER}/dec_keys",
        json={"key_IDs": [{"key_ID": "not-a-uuid"}]},
        headers={"X-SAE-ID": SLAVE},
    )
    assert r.status_code == 400
    body = r.json()
    # ETSI 014 §6.5 wire format.
    assert "message" in body and "detail" not in body
    # ETSI 014 §6.4 mandates this exact message string.
    assert body["message"] == "one or more keys specified are not found on KME"


# --------------------------------------------------------------------------
# ETSI 014 spec-compliance extras (error body format, GET variants, size%8)
# --------------------------------------------------------------------------

def test_error_body_uses_etsi_message_field():
    """ETSI §6.5: error body is `{message, details}`, not FastAPI's `{detail}`."""
    a, b = make_kme_pair()
    client = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    r = client.get(f"/api/v1/keys/{SLAVE}/status")  # no X-SAE-ID -> 401
    assert r.status_code == 401
    body = r.json()
    assert body == {"message": "missing SAE identity", "details": None}


def test_get_enc_keys_simple_request_succeeds():
    """ETSI §6.2: SAE may use GET when only `number` and/or `size` are set."""
    a, b = make_kme_pair()
    a.authorise(MASTER, SLAVE)
    _seed(a, 3)
    client = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    r = client.get(
        f"/api/v1/keys/{SLAVE}/enc_keys",
        params={"number": 2, "size": 256},
        headers={"X-SAE-ID": MASTER},
    )
    assert r.status_code == 200
    assert len(r.json()["keys"]) == 2


def test_get_dec_keys_single_id_succeeds():
    """ETSI §6.4: SAE may use GET when a single key_ID is requested."""
    a, b = make_kme_pair()
    shared = KeyBlock(material=b"k" * 32, source="bb84-visual", qber=0.0)
    a.add_block(shared)
    b.add_block(shared)
    a.authorise(MASTER, SLAVE)

    ca = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    cb = TestClient(create_kme_app(b, peer_kme_id=a.kme_id))
    kid = ca.post(
        f"/api/v1/keys/{SLAVE}/enc_keys",
        json={"number": 1},
        headers={"X-SAE-ID": MASTER},
    ).json()["keys"][0]["key_ID"]

    r = cb.get(
        f"/api/v1/keys/{MASTER}/dec_keys",
        params={"key_ID": kid},
        headers={"X-SAE-ID": SLAVE},
    )
    assert r.status_code == 200
    assert r.json()["keys"][0]["key_ID"] == kid


def test_size_not_multiple_of_8_is_400_with_spec_message():
    """ETSI §6.2: KMEs that only support multiples of 8 must reject with this
    exact error message."""
    a, b = make_kme_pair()
    a.authorise(MASTER, SLAVE)
    _seed(a, 1)
    client = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    r = client.post(
        f"/api/v1/keys/{SLAVE}/enc_keys",
        json={"number": 1, "size": 100},  # 100 % 8 != 0
        headers={"X-SAE-ID": MASTER},
    )
    assert r.status_code == 400
    assert r.json()["message"] == "size shall be a multiple of 8"


def test_key_expiry():
    store = KeyStore(kme_id="KME-A", key_ttl_seconds=0.01)
    _seed(store, 2)
    assert store.fresh_key_count() == 2
    time.sleep(0.05)
    assert store.fresh_key_count() == 0  # expired and purged


# --------------------------------------------------------------------------
# Two KMEs sharing one feed via the fan-out feeder
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fan_out_feeder_synchronises_both_kmes():
    import asyncio

    a, b = make_kme_pair()
    a.authorise(MASTER, SLAVE)
    b.authorise(MASTER, SLAVE)
    q: asyncio.Queue[KeyBlock] = asyncio.Queue()
    stop = asyncio.Event()
    feeder = asyncio.create_task(fan_out_feeder(q, a, b, stop_event=stop))

    block = KeyBlock(material=b"\x99" * 32, source="abstract-bulk", qber=0.01)
    await q.put(block)
    # Give the feeder a moment to drain.
    for _ in range(20):
        if a.fresh_key_count() and b.fresh_key_count():
            break
        await asyncio.sleep(0.05)
    stop.set()
    feeder.cancel()
    await asyncio.gather(feeder, return_exceptions=True)

    # Same key_ID resolvable on both KMEs to identical bytes.
    ca = TestClient(create_kme_app(a, peer_kme_id=b.kme_id))
    cb = TestClient(create_kme_app(b, peer_kme_id=a.kme_id))
    kid = ca.post(
        f"/api/v1/keys/{SLAVE}/enc_keys",
        json={"number": 1},
        headers={"X-SAE-ID": MASTER},
    ).json()["keys"][0]["key_ID"]
    dec = cb.post(
        f"/api/v1/keys/{MASTER}/dec_keys",
        json={"key_IDs": [{"key_ID": kid}]},
        headers={"X-SAE-ID": SLAVE},
    ).json()["keys"][0]
    assert base64.b64decode(dec["key"]) == block.material


# --------------------------------------------------------------------------
# mTLS certificate machinery (real CA -> client cert -> verify)
# --------------------------------------------------------------------------

def test_mtls_cert_chain_round_trip(tmp_path):
    """A client cert issued by the demo CA verifies against that CA, and its
    CN equals the SAE ID -- the identity mechanism ETSI 014 relies on."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import padding

    from kme.certs import create_ca, issue_cert

    ca_crt, ca_key = create_ca(tmp_path)
    sae_crt, sae_key = issue_cert(
        tmp_path, "SAE-CLIENT", ca_crt, ca_key, is_server=False
    )

    ca_cert = x509.load_pem_x509_certificate(ca_crt.read_bytes())
    leaf = x509.load_pem_x509_certificate(sae_crt.read_bytes())

    # CN carries the SAE ID.
    cn = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "SAE-CLIENT"

    # Leaf is genuinely signed by the demo CA (signature verifies).
    ca_cert.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        padding.PKCS1v15(),
        leaf.signature_hash_algorithm,
    )
