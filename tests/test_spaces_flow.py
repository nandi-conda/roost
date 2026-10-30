# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""End to end through the app and the Durable Object RPC boundary: an owner
creates a member-list space, a member writes to it, an app exchanges a
delegation token for a space credential and syncs the member's repo, checking
each commit and record against the MAC its response carries."""

import json

from human import call, human
from roost.cbor import CID
from roost.encoding import b64_decode, b64url_decode
from roost.keys import P256Keypair, Secp256k1Keypair
from roost.spaces import mac
from roost.spaces.httpsig import create_space_sig_headers
from roost.spaces.lthash import LtHash
from roost.spaces.star import read_repo_star

FORUM = "com.example.forum"
POST = "com.example.forum.post"
X = "/xrpc/com.atproto.space."
M = "/xrpc/com.atproto.memberspace."
MEMBERS = {"$type": "com.atproto.memberspace.policy"}
PUBLIC = {"$type": "com.atproto.memberspace.policy", "publicRead": True, "publicWrite": True}


async def credential_for(client, user, space, key, expect=200, **extra):
    token = (await call(client, "GET", f"{X}getDelegationToken?space={space}", user))["token"]
    return await call(client, "POST", X + "getSpaceCredential", expect=expect, space=space,
                      credentialKid=key.did(), delegationToken=token, **extra)


def signed(key, credential, audience):
    return create_space_sig_headers(key, f"Atproto-Space-Credential {credential}", audience)


def kem_key(env, did):
    """The author's #atproto_kem key, as a syncer resolves it from the DID document."""
    methods = env.plc.log[did][-1]["operation"]["verificationMethods"]
    return methods["atproto_kem"]


def want_mac(env, did, mac_type):
    """(Atproto-Space-Want-Mac header, shared secret) for one request."""
    key_share, secret = mac.encapsulate(kem_key(env, did))
    return {mac.WANT_MAC_HEADER: mac.format_want_mac_header(mac_type, key_share)}, secret


def jwt_part(part: str) -> dict:
    return json.loads(b64url_decode(part))


def lex_commit(value: dict) -> dict:
    return {k: (b64_decode(v["$bytes"]) if isinstance(v, dict) else v) for k, v in value.items()}


async def setup(client):
    alice, bob, carol = [await human(client, name) for name in ("alice", "bob", "carol")]
    created = await call(client, "POST", X + "createSpace", alice, spaceType=FORUM, skey="general",
                         policy=MEMBERS)
    space = created["uri"]
    assert space == f"at://{alice['did']}/space/{FORUM}/general"
    await call(client, "POST", M + "putMember", alice, space=space, did=bob["did"], read=True, write=True)
    return alice, bob, carol, space


async def test_member_writes_and_app_syncs_with_credential(client, env):
    alice, bob, carol, space = await setup(client)

    first = await call(client, "POST", X + "createRecord", bob, space=space, repo=bob["did"], collection=POST,
                       rkey="hello", record={"text": "hi from bob"})
    assert first["uri"] == f"{space}/{bob['did']}/{POST}/hello"
    await call(client, "POST", X + "createRecord", bob, expect=400, space=space, repo=bob["did"],
               collection=POST, rkey="hello", record={"text": "again"})
    await call(client, "POST", X + "putRecord", alice, space=space, repo=alice["did"], collection=POST,
               rkey="welcome", record={"text": "welcome"})
    batch = await call(client, "POST", X + "applyWrites", bob, space=space, repo=bob["did"], writes=[
        {"$type": "com.atproto.space.applyWrites#create", "collection": POST, "rkey": "two",
         "value": {"text": "two"}},
        {"$type": "com.atproto.space.applyWrites#update", "collection": POST, "rkey": "hello",
         "value": {"text": "hi, edited"}},
        {"$type": "com.atproto.space.applyWrites#create", "collection": POST, "rkey": "gone",
         "value": {"text": "short-lived"}},
        {"$type": "com.atproto.space.applyWrites#delete", "collection": POST, "rkey": "gone"},
    ])
    assert [r["$type"].rpartition("#")[2] for r in batch["results"]] == [
        "createResult", "updateResult", "createResult", "deleteResult"]
    too_big = await call(client, "POST", X + "createRecord", bob, expect=400, space=space, repo=bob["did"],
                         collection=POST, rkey="big", record={"text": "x" * (1024 * 1024)})
    assert too_big["error"] == "InvalidRecord"

    # The app holds a P-256 key and trades bob's delegation token for a credential.
    key = P256Keypair()
    credential = (await credential_for(client, bob, space, key))["credential"]

    # The space host lists the writer set...
    repos = await call(client, "GET", f"{X}listRepos?space={space}", headers=signed(key, credential, alice["did"]))
    writers = {repo["did"]: repo for repo in repos["repos"]}
    assert set(writers) == {alice["did"], bob["did"]}

    # ...and the repo host serves bob's records and commit, each with a MAC.
    bob_headers = signed(key, credential, bob["did"])
    record_path = f"{X}getRecord?space={space}&repo={bob['did']}&collection={POST}&rkey=hello"
    missing = await call(client, "GET", record_path, headers=bob_headers, expect=400)
    assert missing["error"] == "BadSpaceMac"
    wrong_type, _ = want_mac(env, bob["did"], mac.COMMIT_MAC_TYPE)
    assert (await call(client, "GET", record_path, headers={**bob_headers, **wrong_type}, expect=400))["error"] \
        == "BadSpaceMac"
    want, secret = want_mac(env, bob["did"], mac.RECORD_MAC_TYPE)
    response = await client.get(record_path, headers={**bob_headers, **want})
    record = response.json()
    assert record["value"] == {"$type": POST, "text": "hi, edited"}
    record_mac = mac.parse_mac_header(response.headers["atproto-space-mac"], mac.RECORD_MAC_TYPE)
    assert record_mac == mac.compute_record_mac(secret, record["uri"], CID.parse(record["cid"]).bytes)
    assert response.headers["vary"] == "Atproto-Space-Want-Mac"
    assert "Atproto-Space-Mac" in response.headers["access-control-expose-headers"]
    listed = await call(client, "GET", f"{X}listRecords?space={space}&repo={bob['did']}", headers=bob_headers)
    assert sorted(r["rkey"] for r in listed["records"]) == ["hello", "two"]

    want, secret = want_mac(env, bob["did"], mac.COMMIT_MAC_TYPE)
    response = await client.get(f"{X}getLatestCommit?space={space}&repo={bob['did']}", headers={**bob_headers, **want})
    commit = lex_commit(response.json()["commit"])
    assert set(commit) == {"ver", "repo", "space", "rev", "data"}
    assert (commit["ver"], commit["repo"], commit["space"]) == (1, bob["did"], space)
    assert mac.parse_mac_header(response.headers["atproto-space-mac"], mac.COMMIT_MAC_TYPE) \
        == mac.compute_commit_mac(secret, commit)
    assert b64_decode(writers[bob["did"]]["data"]["$bytes"]) == commit["data"]
    assert writers[bob["did"]]["repoRev"] == commit["rev"]

    want, secret = want_mac(env, bob["did"], mac.COMMIT_MAC_TYPE)
    response = await client.get(f"{X}getRepo?space={space}&repo={bob['did']}", headers={**bob_headers, **want})
    assert response.status == 200 and response.headers["content-type"] == "application/octet-stream"
    meta, pairs = read_repo_star(response.body)
    assert {k: v for k, v in meta.items() if k != "$type"} == commit
    assert mac.parse_mac_header(response.headers["atproto-space-mac"], mac.COMMIT_MAC_TYPE) \
        == mac.compute_commit_mac(secret, commit)
    assert [path for path, _ in pairs] == [f"{POST}/hello", f"{POST}/two"]
    set_hash = LtHash()
    for path, value in pairs:
        set_hash.add(f"{path}/{CID.for_cbor(value)}")
    assert set_hash.digest() == commit["data"]

    ops_path = f"{X}listRepoOps?space={space}&repo={bob['did']}"
    want, _ = want_mac(env, bob["did"], mac.COMMIT_MAC_TYPE)
    page = await client.get(ops_path + "&limit=2", headers={**bob_headers, **want})
    assert "commit" not in page.json() and page.json()["cursor"] and "atproto-space-mac" not in page.headers
    assert (await call(client, "GET", ops_path + "&limit=2", headers=bob_headers, expect=400))["error"] == "BadSpaceMac"
    want, secret = want_mac(env, bob["did"], mac.COMMIT_MAC_TYPE)
    response = await client.get(ops_path, headers={**bob_headers, **want})
    ops = response.json()
    assert [(op["rkey"], op["prev"] is not None) for op in ops["ops"]] == [
        ("hello", False), ("two", False), ("hello", True), ("gone", False), ("gone", True)]
    assert lex_commit(ops["commit"]) == commit
    assert mac.parse_mac_header(response.headers["atproto-space-mac"], mac.COMMIT_MAC_TYPE) \
        == mac.compute_commit_mac(secret, commit)
    replay = LtHash()
    for op in ops["ops"]:
        if op["prev"]:
            replay.remove(f"{op['collection']}/{op['rkey']}/{op['prev']}")
        if op["cid"]:
            replay.add(f"{op['collection']}/{op['rkey']}/{op['cid']}")
    assert replay.digest() == commit["data"]

    # bob reads his own data without a MAC unless he asks for one.
    own = await client.get(f"{X}getLatestCommit?space={space}&repo={bob['did']}", headers=bob["auth"])
    assert own.status == 200 and "atproto-space-mac" not in own.headers
    want, secret = want_mac(env, bob["did"], mac.COMMIT_MAC_TYPE)
    own = await client.get(f"{X}getLatestCommit?space={space}&repo={bob['did']}", headers={**bob["auth"], **want})
    assert mac.parse_mac_header(own.headers["atproto-space-mac"], mac.COMMIT_MAC_TYPE) \
        == mac.compute_commit_mac(secret, commit)

    # The credential is not the owner's: no credential reads another space or audience.
    want, _ = want_mac(env, bob["did"], mac.RECORD_MAC_TYPE)
    await call(client, "GET", record_path, headers={**signed(key, credential, carol["did"]), **want}, expect=401)
    await call(client, "GET", record_path, headers={**signed(P256Keypair(), credential, bob["did"]), **want},
               expect=401)
    # The October 1 scheme is refused outright.
    old = dict(bob_headers, authorization=f"Atproto-Space {credential}")
    assert (await call(client, "GET", record_path, headers={**old, **want}, expect=400))["error"] == "InvalidToken"
    # Without a credential, only bob reads bob's repo.
    await call(client, "GET", record_path, carol, expect=400)
    own = await call(client, "GET", f"{X}listSpaces", bob)
    assert own["spaces"] == [{"uri": space}]


async def test_credential_requests(client, env):
    alice, bob, carol, space = await setup(client)
    key = P256Keypair()
    refused = await credential_for(client, carol, space, key, expect=400)
    assert refused["error"] == "SpaceNotFound"  # not found or not authorized

    token = (await call(client, "GET", f"{X}getDelegationToken?space={space}", bob))["token"]
    request = {"space": space, "credentialKid": key.did(), "delegationToken": token}
    await call(client, "POST", X + "getSpaceCredential", **request)
    replayed = await call(client, "POST", X + "getSpaceCredential", expect=400, **request)
    assert replayed["error"] == "InvalidDelegationToken"
    garbage = await call(client, "POST", X + "getSpaceCredential", expect=400, **dict(request, delegationToken="x.y.z"))
    assert garbage["error"] == "InvalidDelegationToken"
    # A token for another space is refused; so is a key that is not P-256.
    other = f"at://{alice['did']}/space/{FORUM}/other"
    await call(client, "POST", X + "createSpace", alice, spaceType=FORUM, skey="other", policy=MEMBERS)
    token = (await call(client, "GET", f"{X}getDelegationToken?space={other}", alice))["token"]
    mismatched = await call(client, "POST", X + "getSpaceCredential", expect=400,
                            **dict(request, delegationToken=token))
    assert mismatched["error"] == "InvalidDelegationToken"
    token = (await call(client, "GET", f"{X}getDelegationToken?space={space}", bob))["token"]
    await call(client, "POST", X + "getSpaceCredential", expect=400,
               **dict(request, credentialKid=Secp256k1Keypair.create().did(), delegationToken=token))
    # Without a token a member-list space answers as though it does not exist.
    hidden = await call(client, "POST", X + "getSpaceCredential", expect=400, space=space, credentialKid=key.did())
    assert hidden["error"] == "SpaceNotFound"

    # carol's own PDS stores what she writes, but the space host does not sequence her.
    await call(client, "POST", X + "createRecord", carol, space=space, repo=carol["did"], collection=POST,
               rkey="x", record={"text": "not a member"})
    credential = (await credential_for(client, bob, space, key))["credential"]
    repos = await call(client, "GET", f"{X}listRepos?space={space}", headers=signed(key, credential, alice["did"]))
    assert carol["did"] not in {repo["did"] for repo in repos["repos"]}


async def test_delegation_tokens_name_the_authority_pds(client, env):
    alice, bob, carol, space = await setup(client)
    token = (await call(client, "GET", f"{X}getDelegationToken?space={space}", bob))["token"]
    header, payload = (jwt_part(part) for part in token.split(".")[:2])
    assert header["kid"] == "#atproto" and payload["aud"] == f"{alice['did']}#atproto_pds"
    key = P256Keypair()
    credential = (await credential_for(client, bob, space, key))["credential"]
    assert jwt_part(credential.split(".")[0])["kid"] == "#atproto"


async def test_owner_governance_and_delete(client, env):
    alice, bob, carol, space = await setup(client)
    await call(client, "POST", M + "putMember", bob, expect=400, space=space, did=carol["did"], read=True,
               write=False)
    members = await call(client, "GET", f"{M}listMembers?space={space}", alice)
    assert members["members"] == [{"did": bob["did"], "read": True, "write": True}]
    described = await call(client, "GET", f"{X}getSpace?space={space}", alice)
    assert described == {"uri": space, "policy": {"$type": "com.atproto.memberspace.policy", "publicRead": False,
                                                  "publicWrite": False, "publishPolicy": False,
                                                  "publishMembers": False}}
    await call(client, "POST", X + "updateSpace", alice, space=space, policy=dict(MEMBERS, publicRead=True))
    key = P256Keypair()
    await credential_for(client, carol, space, key)  # public read now
    # A public space issues credentials without a delegation token.
    await call(client, "POST", X + "getSpaceCredential", space=space, credentialKid=key.did())

    await call(client, "POST", X + "createRecord", alice, space=space, repo=alice["did"], collection=POST,
               rkey="a", record={"text": "a"})
    await call(client, "POST", X + "deleteSpace", alice, space=space)
    await call(client, "POST", X + "deleteSpace", alice, space=space)  # already gone: nothing to do
    gone = await credential_for(client, bob, space, key, expect=400)
    assert gone["error"] == "SpaceDeleted"
    tokenless = await call(client, "POST", X + "getSpaceCredential", expect=400, space=space, credentialKid=key.did())
    assert tokenless["error"] == "SpaceDeleted"
    write = await call(client, "POST", X + "createRecord", alice, expect=400, space=space, repo=alice["did"],
                       collection=POST, rkey="b", record={"text": "b"})
    assert write["error"] == "SpaceNotFound"
    assert (await call(client, "GET", f"{X}listSpaces", alice))["spaces"] == []

    # The authority may recreate it; it is a new, empty space.
    await call(client, "POST", X + "createSpace", alice, spaceType=FORUM, skey="general", policy=PUBLIC)
    await call(client, "POST", X + "getSpaceCredential", space=space, credentialKid=key.did())
    gone = await call(client, "GET", f"{X}getLatestCommit?space={space}&repo={alice['did']}", alice, expect=400)
    assert gone["error"] == "RepoNotFound"


async def test_space_blob_is_served_only_through_its_space(client, env):
    alice, bob, carol, space = await setup(client)
    uploaded = await client.post("/xrpc/com.atproto.repo.uploadBlob",
                               headers=dict(bob["auth"], **{"content-type": "image/png"}), body=b"\x89PNG...")
    blob = uploaded.json()["blob"]
    await call(client, "POST", X + "createRecord", bob, space=space, repo=bob["did"], collection=POST, rkey="pic",
               record={"text": "pic", "image": blob})
    key = P256Keypair()
    credential = (await credential_for(client, bob, space, key))["credential"]
    headers = signed(key, credential, bob["did"])
    cid = blob["ref"]["$link"]
    listed = await call(client, "GET", f"{X}listBlobs?space={space}&repo={bob['did']}", headers=headers)
    assert listed["cids"] == [cid]
    got = await call(client, "GET", f"{X}getBlob?space={space}&repo={bob['did']}&cid={cid}", headers=headers)
    assert got.body == b"\x89PNG..." and got.headers["content-security-policy"]
    other = await call(client, "POST", X + "createRecord", bob, expect=400, space=space, repo=bob["did"],
                       collection=POST, rkey="nope",
                       record={"image": dict(blob, ref={"$link": "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"})})
    assert other["error"] == "BlobNotFound"


async def test_service_describe_advertises_spaces(client):
    response = await client.get("/xrpc/community.lexicon.service.describe")
    assert response.status == 200
    body = response.json()
    assert body["roles"] == ["pds"]
    methods = {entry["value"] for entry in body["methods"]}
    assert {"com.atproto.space.getDelegationToken", "com.atproto.space.createSpace",
            "com.atproto.memberspace.putMember",
            "com.atproto.server.describeServer", "community.lexicon.service.describe"} <= methods
    assert all(entry["$type"] == "community.lexicon.service.describe#nsid" for entry in body["methods"])
    assert not any("(" in value for value in methods)


async def test_delegation_for_a_missing_own_space_says_so(client):
    """Colibri creates its preferences space when getDelegationToken answers SpaceNotFound."""
    dana = await human(client, "dana")
    space = f"at://{dana['did']}/space/{FORUM}/self"
    missing = await call(client, "GET", f"{X}getDelegationToken?space={space}", dana, expect=400)
    assert missing["error"] == "SpaceNotFound"
    await call(client, "POST", X + "createSpace", dana, spaceType=FORUM, skey="self",
               policy={"$type": "com.atproto.personalspace.policy"})
    assert (await call(client, "GET", f"{X}getDelegationToken?space={space}", dana))["token"]
