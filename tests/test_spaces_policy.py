# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The October 29 spaces alpha: space policies (personalspace, memberspace,
managedspace) in place of simplespace, published policy and member records,
removeWriter, clearRecords, and migrating a space with its authority's account
(exportSpaceMeta, importSpaceMeta, importRepo)."""

import json
from urllib.parse import parse_qs, urlsplit

from fakes import Sql
from human import call, human
from test_spaces_flow import FORUM, MEMBERS, POST, M, X, credential_for, setup, signed

from roost import cbor
from roost.encoding import b64_decode, b64url_decode
from roost.keys import P256Keypair
from roost.net import HttpResponse
from roost.spaces.meta import serialize_space_meta
from roost.spaces.star import read_repo_star, write_star
from roost.spaces.store import SpaceStore

PERSONAL = {"$type": "com.atproto.personalspace.policy"}
EMPTY_DIGEST = "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad"


def do_for(env, did):
    row = env.db.connection.execute("SELECT do_id FROM accounts WHERE did = ?", (did,)).fetchone()
    return env.account_do(row["do_id"]).account


async def own_records(client, who, space, collection=None):
    query = f"{X}listRecords?space={space}&repo={who['did']}" + (f"&collection={collection}" if collection else "")
    return {r["rkey"]: r["value"] for r in (await call(client, "GET", query, who))["records"]}


async def writers(client, env, space, reader):
    key = P256Keypair()
    credential = (await credential_for(client, reader, space, key))["credential"]
    authority = space.split("/")[2]
    listed = await call(client, "GET", f"{X}listRepos?space={space}", headers=signed(key, credential, authority))
    return {repo["did"] for repo in listed["repos"]}


async def test_policies_are_normalized_and_replaced_wholesale(client, env):
    alice, bob, carol, space = await setup(client)
    unknown = await call(client, "POST", X + "createSpace", alice, expect=400, spaceType=FORUM, skey="x",
                         policy={"$type": "com.example.policy"})
    assert unknown["error"] == "UnsupportedPolicy"
    await call(client, "POST", X + "createSpace", alice, expect=400, spaceType=FORUM, skey="x",
               policy={"$type": "com.atproto.managedspace.policy", "managingApp": "https://app.test"})
    again = await call(client, "POST", X + "createSpace", alice, expect=400, spaceType=FORUM, skey="general",
                       policy=MEMBERS)
    assert again["error"] == "SpaceAlreadyExists"
    await call(client, "POST", X + "createSpace", alice, spaceType=FORUM, skey="mine", policy=dict(PERSONAL, x=1))
    mine = f"at://{alice['did']}/space/{FORUM}/mine"
    assert (await call(client, "GET", f"{X}getSpace?space={mine}", alice))["policy"] == PERSONAL

    # Fields left out of an update go back to their defaults.
    await call(client, "POST", X + "updateSpace", alice, space=space,
               policy=dict(MEMBERS, publicRead=True, allowedApps=["https://app.test/client.json"]))
    await call(client, "POST", X + "updateSpace", alice, space=space, policy=MEMBERS)
    assert "allowedApps" not in (await call(client, "GET", f"{X}getSpace?space={space}", alice))["policy"]
    # A different $type discards the member list; migrating back does not restore it.
    await call(client, "POST", X + "updateSpace", alice, space=space, policy=PERSONAL)
    mismatch = await call(client, "GET", f"{M}listMembers?space={space}", alice, expect=400)
    assert mismatch["error"] == "PolicyMismatch"
    put = await call(client, "POST", M + "putMember", alice, expect=400, space=space, did=carol["did"],
                     read=True, write=True)
    assert put["error"] == "PolicyMismatch"
    await call(client, "POST", X + "updateSpace", alice, space=space, policy=MEMBERS)
    assert (await call(client, "GET", f"{M}listMembers?space={space}", alice))["members"] == []
    # updateSpace needs the whole policy; getSpace is the owner's alone.
    await call(client, "POST", X + "updateSpace", alice, expect=400, space=space)
    assert (await call(client, "GET", f"{X}getSpace?space={space}", bob, expect=400))["error"] == "NotSpaceOwner"


async def test_personalspace_admits_only_its_authority(client, env):
    alice, bob = await human(client, "alice"), await human(client, "bob")
    created = await call(client, "POST", X + "createSpace", alice, spaceType=FORUM, skey="drafts", policy=PERSONAL)
    space = created["uri"]
    key = P256Keypair()
    assert (await credential_for(client, bob, space, key, expect=400))["error"] == "SpaceNotFound"
    credential = (await credential_for(client, alice, space, key))["credential"]
    # A space credential no longer reaches getSpace.
    await call(client, "GET", f"{X}getSpace?space={space}", headers=signed(key, credential, alice["did"]),
               expect=401)
    await call(client, "POST", X + "createRecord", bob, space=space, repo=bob["did"], collection=POST,
               rkey="x", record={"text": "not tracked"})
    await call(client, "POST", X + "createRecord", alice, space=space, repo=alice["did"], collection=POST,
               rkey="x", record={"text": "mine"})
    assert await writers(client, env, space, alice) == {alice["did"]}


async def test_published_policy_and_member_records(client, env):
    alice, bob, carol, space = await setup(client)
    assert await own_records(client, alice, space) == {}
    published = dict(MEMBERS, publishPolicy=True, publishMembers=True)
    await call(client, "POST", X + "updateSpace", alice, space=space, policy=published)
    records = await own_records(client, alice, space)
    assert records["self"]["policy"]["publishMembers"] is True
    assert records[bob["did"]] == {"$type": "com.atproto.memberspace.member", "read": True, "write": True}

    await call(client, "POST", M + "putMember", alice, space=space, did=carol["did"], read=True, write=False)
    assert (await own_records(client, alice, space))[carol["did"]]["write"] is False
    await call(client, "POST", M + "removeMember", alice, space=space, did=carol["did"])
    assert carol["did"] not in await own_records(client, alice, space)
    # Clearing a flag withdraws what it published.
    await call(client, "POST", X + "updateSpace", alice, space=space, policy=dict(MEMBERS, publishPolicy=True))
    assert set(await own_records(client, alice, space)) == {"self"}
    await call(client, "POST", X + "updateSpace", alice, space=space, policy=MEMBERS)
    assert await own_records(client, alice, space) == {}

    # Nobody writes these collections directly, in any repo.
    for who in (alice, bob):
        for collection in ("com.atproto.space.policy", "com.atproto.memberspace.member"):
            await call(client, "POST", X + "putRecord", who, expect=400, space=space, repo=who["did"],
                       collection=collection, rkey="self", record={"policy": MEMBERS})
            await call(client, "POST", X + "applyWrites", who, expect=400, space=space, repo=who["did"], writes=[
                {"$type": "com.atproto.space.applyWrites#create", "collection": collection, "value": {}}])
        await call(client, "POST", X + "deleteRecord", who, expect=400, space=space, repo=who["did"],
                   collection="com.atproto.space.policy", rkey="self")


async def test_did_web_ports_are_unencoded_in_member_record_keys(client, env):
    alice, bob, carol, space = await setup(client)
    await call(client, "POST", X + "updateSpace", alice, space=space, policy=dict(MEMBERS, publishMembers=True))
    await call(client, "POST", M + "putMember", alice, space=space, did="did:web:localhost%3A2583", read=True,
               write=False)
    assert "did:web:localhost:2583" in await own_records(client, alice, space)


async def test_managing_app_decides_reads_and_writes(client, env):
    alice, bob = await human(client, "alice"), await human(client, "bob")
    asked = []

    async def app(method, url, headers, body):
        if url.endswith("/.well-known/did.json"):
            doc = {"id": "did:web:forum.test",
                   "service": [{"id": "#forum", "type": "X", "serviceEndpoint": "https://forum.test"}]}
            return HttpResponse(200, json.dumps(doc).encode())
        parts = urlsplit(url)
        asked.append((parts.path, {k: v[0] for k, v in parse_qs(parts.query).items()}, headers["Authorization"]))
        return HttpResponse(200, json.dumps({"authorized": True}).encode(), {"content-type": "application/json"})
    env.http.routes["https://forum.test/"] = app

    created = await call(client, "POST", X + "createSpace", alice, spaceType=FORUM, skey="managed",
                         policy={"$type": "com.atproto.managedspace.policy", "managingApp": "did:web:forum.test#forum"})
    space = created["uri"]
    # No delegation token, no credential.
    tokenless = await call(client, "POST", X + "getSpaceCredential", expect=400, space=space,
                           credentialKid=P256Keypair().did())
    assert tokenless["error"] == "SpaceNotFound"
    await credential_for(client, bob, space, P256Keypair())
    await call(client, "POST", X + "createRecord", bob, space=space, repo=bob["did"], collection=POST, rkey="1",
               record={"text": "hi"})
    paths = {path for path, _, _ in asked}
    assert paths == {"/xrpc/com.atproto.managedspace.checkUserAccess"}
    assert [params["access"] for _, params, _ in asked] == ["read", "write"]
    assert all("clientId" not in params for _, params, _ in asked)
    payload = json.loads(b64url_decode(asked[0][2].split(" ", 1)[1].split(".")[1]))
    assert payload["lxm"] == "com.atproto.managedspace.checkUserAccess"

    # An app that errors denies.
    env.http.routes["https://forum.test/"] = lambda *args: _fail(args)
    assert (await credential_for(client, bob, space, P256Keypair(), expect=400))["error"] == "SpaceNotFound"


async def _fail(args):
    url = args[1]
    if url.endswith("/.well-known/did.json"):
        doc = {"id": "did:web:forum.test",
               "service": [{"id": "#forum", "type": "X", "serviceEndpoint": "https://forum.test"}]}
        return HttpResponse(200, json.dumps(doc).encode())
    return HttpResponse(500, b"")


async def test_the_user_is_checked_before_the_app(client, env):
    alice, bob, carol, space = await setup(client)
    await call(client, "POST", X + "updateSpace", alice, space=space,
               policy=dict(MEMBERS, allowedApps=["https://app.test/client-metadata.json"]))
    # carol is no member: she learns nothing, not even that her app is refused.
    assert (await credential_for(client, carol, space, P256Keypair(), expect=400))["error"] == "SpaceNotFound"
    assert (await credential_for(client, bob, space, P256Keypair(), expect=400))["error"] == "AppNotAuthorized"
    await call(client, "POST", X + "updateSpace", alice, space=space,
               policy=dict(MEMBERS, publicRead=True, allowedApps=["https://app.test/client-metadata.json"]))
    tokenless = await call(client, "POST", X + "getSpaceCredential", expect=400, space=space,
                           credentialKid=P256Keypair().did())
    assert tokenless["error"] == "AppNotAuthorized"


async def test_writer_set_removal(client, env):
    alice, bob, carol, space = await setup(client)
    await call(client, "POST", M + "putMember", alice, space=space, did=carol["did"], read=True, write=True)
    for who in (bob, carol):
        await call(client, "POST", X + "createRecord", who, space=space, repo=who["did"], collection=POST,
                   rkey="1", record={"text": "hi"})
    assert await writers(client, env, space, alice) == {bob["did"], carol["did"]}

    refused = await call(client, "POST", X + "removeWriter", bob, expect=400, space=space, did=carol["did"])
    assert refused["error"] == "NotSpaceOwner"
    await call(client, "POST", X + "removeWriter", alice, space=space, did=carol["did"])
    await call(client, "POST", X + "removeWriter", alice, space=space, did=carol["did"])  # idempotent
    assert await writers(client, env, space, alice) == {bob["did"]}
    # An authorized write tracks carol again.
    await call(client, "POST", X + "createRecord", carol, space=space, repo=carol["did"], collection=POST,
               rkey="2", record={"text": "back"})
    assert await writers(client, env, space, alice) == {bob["did"], carol["did"]}

    await call(client, "POST", M + "putMember", alice, space=space, did=carol["did"], read=True, write=False)
    await call(client, "POST", M + "removeMember", alice, space=space, did=bob["did"])
    assert await writers(client, env, space, alice) == set()


async def test_clear_records(client, env):
    alice, bob, carol, space = await setup(client)
    await call(client, "POST", X + "updateSpace", alice, space=space, policy=dict(MEMBERS, publishPolicy=True))
    for who in (alice, bob):
        await call(client, "POST", X + "createRecord", who, space=space, repo=who["did"], collection=POST,
                   rkey="1", record={"text": "hi"})
    await call(client, "POST", X + "clearRecords", bob, expect=403, space=space, repo=alice["did"])
    before = (await call(client, "GET", f"{X}getLatestCommit?space={space}&repo={bob['did']}", bob))["commit"]
    assert await call(client, "POST", X + "clearRecords", bob, space=space, repo=bob["did"]) == {}
    after = (await call(client, "GET", f"{X}getLatestCommit?space={space}&repo={bob['did']}", bob))["commit"]
    assert after["rev"] > before["rev"]
    assert b64_decode(after["data"]["$bytes"]).hex() == EMPTY_DIGEST
    assert await own_records(client, bob, space) == {}
    ops = await call(client, "GET", f"{X}listRepoOps?space={space}&repo={bob['did']}&since={before['rev']}", bob)
    assert ops["ops"] == [] and ops["commit"]["rev"] == after["rev"]
    # Still a writer, at the empty digest; clearing again is a no-op.
    assert bob["did"] in await writers(client, env, space, alice)
    await call(client, "POST", X + "clearRecords", bob, space=space, repo=bob["did"])
    again = (await call(client, "GET", f"{X}getLatestCommit?space={space}&repo={bob['did']}", bob))["commit"]
    assert again["rev"] == after["rev"]
    # The authority keeps its published policy record.
    await call(client, "POST", X + "clearRecords", alice, space=space, repo=alice["did"])
    assert set(await own_records(client, alice, space)) == {"self"}


async def test_space_migrates_with_its_authority(client, env):
    alice, bob, carol, space = await setup(client)
    await call(client, "POST", X + "updateSpace", alice, space=space, policy=dict(MEMBERS, publishMembers=True))
    await call(client, "POST", X + "createRecord", bob, space=space, repo=bob["did"], collection=POST, rkey="1",
               record={"text": "hi"})
    await call(client, "POST", X + "createRecord", alice, space=space, repo=alice["did"], collection=POST,
               rkey="1", record={"text": "welcome"})
    meta = (await call(client, "GET", f"{X}exportSpaceMeta?space={space}", alice)).body
    repo = (await call(client, "GET", f"{X}getRepo?space={space}&repo={alice['did']}", alice)).body
    head = (await call(client, "GET", f"{X}getLatestCommit?space={space}&repo={alice['did']}", alice))["commit"]
    assert (await call(client, "GET", f"{X}exportSpaceMeta?space={space}", bob, expect=400))["error"] == \
        "NotSpaceOwner"

    # The new host starts empty: the repo can't arrive before its space.
    do = do_for(env, alice["did"])
    for table in ("space", "space_policy", "memberspace_member", "space_writer", "space_record", "space_repo",
                  "space_record_oplog"):
        do.spaces.sql.exec(f"DELETE FROM {table}")
    early = await client.post(X + "importRepo", headers=dict(alice["auth"]), body=repo)
    assert early.status == 400 and early.json()["error"] == "SpaceNotFound"
    refused = await client.post(X + "importSpaceMeta", headers=dict(bob["auth"]), body=meta)
    assert refused.json()["error"] == "NotSpaceOwner"

    for _ in range(2):  # imports replace, so a step can be retried
        assert (await client.post(X + "importSpaceMeta", headers=dict(alice["auth"]), body=meta)).status == 200
        assert (await client.post(X + "importRepo", headers=dict(alice["auth"]), body=repo)).status == 200
    assert (await call(client, "GET", f"{M}listMembers?space={space}", alice))["members"] == \
        [{"did": bob["did"], "read": True, "write": True}]
    assert await writers(client, env, space, bob) == {alice["did"], bob["did"]}
    moved = (await call(client, "GET", f"{X}getLatestCommit?space={space}&repo={alice['did']}", alice))["commit"]
    assert moved["data"] == head["data"] and moved["rev"] > head["rev"]
    assert set(await own_records(client, alice, space)) == {"1", bob["did"]}

    # A repo that is not the caller's, or whose records don't fold to its data, is refused.
    other = await client.post(X + "importRepo", headers=dict(bob["auth"]), body=repo)
    assert other.status == 400
    commit, pairs = read_repo_star(repo)
    tampered = write_star(commit, [(pairs[0][0], cbor.encode({"$type": POST, "text": "forged"})), *pairs[1:]])
    assert (await client.post(X + "importRepo", headers=dict(alice["auth"]), body=tampered)).status == 400


async def test_space_meta_imports_reject_what_they_cannot_carry(client, env):
    alice = await human(client, "alice")
    space = f"at://{alice['did']}/space/{FORUM}/moved"
    writer = {"did": alice["did"], "repoRev": "3m2xyzabcde22", "data": bytes(32), "spaceRev": "3m2xyzabcde22"}

    async def importing(archive):
        return await client.post(X + "importSpaceMeta", headers=dict(alice["auth"]), body=archive)

    unknown = await importing(serialize_space_meta(space, {"$type": "com.example.policy"}, [], [writer]))
    assert unknown.json()["error"] == "UnsupportedPolicy"
    member = {"did": "did:plc:bob", "read": True, "write": False}
    state = await importing(serialize_space_meta(space, PERSONAL, [member], []))
    assert state.status == 400 and "Unrecognized policy state" in state.json()["message"]
    meta = {"$type": "atproto-space-meta", "ver": 1, "space": space}
    out_of_order = write_star(meta, [("writer/did:plc:a", cbor.encode({})), ("policy", cbor.encode(MEMBERS))])
    assert (await importing(out_of_order)).status == 400
    missing = write_star(meta, [])
    assert "missing policy" in (await importing(missing)).json()["message"]
    assert (await importing(serialize_space_meta(space, MEMBERS, [member], [writer]))).status == 200
    assert (await call(client, "GET", f"{M}listMembers?space={space}", alice))["members"] == [member]


def test_simplespace_configs_migrate_to_policies():
    sql = Sql()
    sql.exec("""CREATE TABLE simplespace_config (uri TEXT PRIMARY KEY, read_policy TEXT NOT NULL,
                read_managing_app TEXT, write_policy TEXT NOT NULL, write_managing_app TEXT,
                app_access_type TEXT NOT NULL, app_allowed TEXT NOT NULL)""")
    sql.exec("""CREATE TABLE simplespace_member (space TEXT NOT NULL, did TEXT NOT NULL, can_read INTEGER NOT NULL,
                can_write INTEGER NOT NULL, PRIMARY KEY (space, did))""")
    rows = [("at://did:plc:a/space/x.y.z/1", "public", None, "member-list", None, "open", "[]"),
            ("at://did:plc:a/space/x.y.z/2", "member-list", None, "public", None, "allowList", '["https://c"]'),
            ("at://did:plc:a/space/x.y.z/3", "public", None, "managing-app", "did:web:app#m", "allowList", '["x"]')]
    for row in rows:
        sql.exec("INSERT INTO simplespace_config VALUES (?, ?, ?, ?, ?, ?, ?)", *row)
        sql.exec("INSERT INTO simplespace_member VALUES (?, 'did:plc:m', 1, 0)", row[0])
    store = SpaceStore(sql)
    store.init_schema()
    store.init_schema()  # once only
    base = {"$type": "com.atproto.memberspace.policy", "publishPolicy": False, "publishMembers": False}
    assert store.get_policy(rows[0][0]) == dict(base, publicRead=True, publicWrite=False)
    assert store.get_policy(rows[1][0]) == dict(base, publicRead=False, publicWrite=True, allowedApps=["https://c"])
    assert store.get_policy(rows[2][0]) == {"$type": "com.atproto.managedspace.policy",
                                           "managingApp": "did:web:app#m", "publishPolicy": False}
    assert [store.list_members(row[0]) for row in rows] == [[{"did": "did:plc:m", "read": True, "write": False}]] * 2 + [[]]
    assert not sql.exec("SELECT name FROM sqlite_master WHERE name LIKE 'simplespace%'")
