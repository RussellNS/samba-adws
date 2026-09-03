# Test harness

Two modes. The default runs anywhere; the `live` mode runs in the container.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest              # stubbed, ~0.2s, no Samba needed
```

```bash
# inside the samba-ad-dc container
pytest -m live                # real python3-samba
```

## Why two modes

`adws/sambautils.py` does `import ldb` at module scope and subclasses
`samba.samdb.SamDB`, so importing it normally requires python3-samba —
which means every iteration would need a container rebuild.

`tests/conftest.py` puts `tests/stubs/` at the front of `sys.path` before
anything imports `sambautils`, so `import ldb` and `import samba` resolve
to fakes. The render methods then run against replayed directory data.

The stubs are only worth as much as their fidelity to the real modules,
so `tests/test_stub_fidelity.py` (marked `live`) asserts the assumptions
hold against real Samba. **If a fidelity test fails, fix the stub — never
weaken the assertion.** A stub that disagrees with reality turns every
other passing test into a false negative.

That is not hypothetical: the stub initially returned plain `bytes` for
attribute values, which broke eleven `render_pull` tests against code that
works fine in production. Samba actually returns a `bytes` subclass whose
`__str__` decodes UTF-8.

## Layout

| Path | Purpose |
|---|---|
| `conftest.py` | Selects stubbed vs live; installs stubs; shared fixtures |
| `stubs/ldb.py` | Fake `ldb` — constants, `Message`, `Dn`, `Result`, `ldb.bytes` |
| `stubs/samba/` | Fake `samba` — `SamDB` routing to a pluggable backend |
| `replay.py` | Turns recorded or hand-built LDB traffic into that backend |
| `fixtures/` | Captured recordings, one directory per cmdlet |
| `test_stub_fidelity.py` | `live` — asserts the stubs still match reality |

## Writing a test

Hand-build the directory data inline:

```python
def test_something(sambautils, recording):
    from tests import replay
    import ldb

    rec = recording().add_syntax({'cn': ldb.SYNTAX_DIRECTORY_STRING})
    rec.add_search(
        [('CN=alice,DC=vlab,DC=test', {'cn': [b'alice']})],
        base='DC=vlab,DC=test', scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)', attrs=['cn'],
    )

    with replay.using(rec):
        helper = sambautils.SamDBHelper()
        xml = helper.render_pull(**context)

    assert rec.searches()[0]['attrs'] == ['cn']
```

Searches are matched on `(base, scope, expression, attrs)` — **not** on
controls, since the paging cookie changes between pages. Repeated
identical searches are served in the order they were added, which is what
makes multi-page paging replayable.

## Capturing a fixture from a real DC

```bash
# in the container
supervisorctl stop adws
ADWS_RECORD_DIR=/tmp/rec python3 /opt/samba-adws/main.py -b 0.0.0.0 -p 9389
```

Run the cmdlet from the Windows client, then copy `/tmp/rec` out to
`tests/fixtures/<name>/` and load it with `replay.load('<name>')`.

Each capture directory holds `calls.jsonl` (every LDB call with its
arguments and results) and `<n>.xml` (the SOAP request and response for
exchange *n*). Recording is inert unless `ADWS_RECORD_DIR` is set.

## Known defects are `xfail(strict=True)`

Bugs found but not yet fixed are encoded as strict xfails, so the suite
stays green *and* tells you the moment one gets fixed — a strict xfail
that starts passing is reported as a failure, prompting you to drop the
marker. `pytest -rx` lists them with their reasons.
