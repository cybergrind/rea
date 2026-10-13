# Binary Ninja provider

REA adapts the MCP server of an already running Binary Ninja into its native analysis tools. The adapter was written against Binary Ninja's built-in UI MCP server (`serverInfo` `binaryninja_ui_mcp` 0.1.0, Streamable HTTP, `bn_*` tools). Install, license, and start Binary Ninja yourself; REA does not install, upgrade, or launch it.

The adapter is **attached and read-only**. It answers from the view that is active in Binary Ninja's MCP server. It never opens, closes, or saves an item, never changes the active view, and never edits the database. Opening and saving databases is separate [operator tooling](#operator-tooling).

## Point REA at Binary Ninja

Set the endpoint, then select `binja` once through `REA_ANALYSIS_PROVIDER`, the CLI's `--provider binja`, or MCP's `open_binary.provider_id`.

```bash
export REA_BINJA_MCP_URL=http://127.0.0.1:24642/mcp
export REA_ANALYSIS_PROVIDER=binja
rea decompile /absolute/path/to/program 0x401000 --json
rea function /absolute/path/to/program main --json
```

| Variable                   | Meaning                                                                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `REA_BINJA_MCP_URL`        | MCP endpoint. Required: the provider is not configured without it. It must be `http` or `https` on `127.0.0.1` or `[::1]`, without credentials, query, or fragment. |
| `REA_BINJA_MCP_TIMEOUT_MS` | Deadline of one MCP request. Default `900000`.                                                                                                                      |

There is no default endpoint. A default would make Binary Ninja a second usable candidate on every host that also has Ghidra or Hopper, and automatic provider selection refuses to choose between two.

`rea doctor --provider binja --json` checks the setting without connecting. For guided registration, set `REA_BINJA_MCP_URL` before `rea setup --client <client>`; setup shows the variable in its plan and keeps it after approval.

## Which target is analyzed

Open the **original input binary** in REA, not a `.bndb` database. In Binary Ninja the item may be either that binary or its saved database.

Binary Ninja's MCP server reports no input hash, so REA binds the target with the facts the server does report. At the first request of a session REA:

1. digests the target file again and compares it with the SHA-256 recorded when the target was opened;
2. requires exactly one active view and reads its open item;
3. compares the size of that item's raw view with the size of the target file;
4. reads up to 256 bytes that Binary Ninja maps at file offset zero and compares them with the start of the target file.

A size or header mismatch fails. The open item's path is expected to be the target, `<target>.bndb`, or `<name>.bndb` beside it; an unrelated path is accepted only when the content checks pass, and the result says so. When Binary Ninja exposes no raw view or maps nothing at file offset zero, the result carries a limitation that fewer checks were possible. Bytes beyond the compared header are not checked.

Before and after every request REA re-reads the active view. A changed view handle, open item, view type, image base, or end address fails the request, as does a target file whose size or modification time changed. Analysis that is not `IdleState` also fails: partial analysis is not served. These checks do not lock the GUI. Another MCP client can still change the active view between two checks.

REA's close operation releases its MCP connection only.

## One caller at a time

Binary Ninja's MCP handler answers one request at a time. Parallel requests queue behind each other and can stall the server for minutes. One REA session serializes its own requests, including those of composed tools such as `binary_overview`. It does not coordinate with other processes. When several agents share one Binary Ninja, let one process own the calls; the [fetch lane](#fetch-lane) exists for that.

## Coverage

| Operation                                          | Binary Ninja MCP tools                                                                         |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `list_procedures`, `search_procedures`             | `bn_function_list`                                                                             |
| `list_strings`, `search_strings`                   | `bn_string_list`, `bn_memory_read`                                                             |
| `list_names`, `address_name`                       | `bn_symbol_list`, `bn_symbol_list_at`                                                          |
| `list_segments`                                    | `bn_segment_list`, `bn_section_list`                                                           |
| `list_documents`                                   | none: the bound target path                                                                    |
| `comment`                                          | `bn_comment_get`                                                                               |
| `read_bytes`                                       | `bn_memory_read`                                                                               |
| `address_to_file_offset`                           | `bn_segment_list`                                                                              |
| `resolve_containing_procedure`                     | `bn_data_at`, `bn_function_info`, `bn_segment_list`                                            |
| `procedure_address`, `procedure_info`              | `bn_function_info`, `bn_function_list`, `bn_function_stack_layout`                             |
| `procedure_pseudo_code`                            | `bn_function_decompile`                                                                        |
| `procedure_assembly`, `read_function_instructions` | `bn_function_disassembly`                                                                      |
| `procedure_callers`, `procedure_callees`           | `bn_function_callers`, `bn_function_callees`                                                   |
| `procedure_references`                             | `bn_function_callers`, `bn_function_callees`, `bn_function_xrefs_to`, `bn_function_xrefs_from` |
| `xrefs`                                            | `bn_function_info`, `bn_function_callers`, `bn_data_xrefs_to`                                  |
| `analyze_function`                                 | the function tools above, `bn_function_basic_blocks`, `bn_comment_get`                         |

Every session also calls `bn_binary_view_list`, `bn_open_item_list`, and `bn_analysis_status` for target binding. Composed tools such as `binary_overview`, `get_call_graph`, `batch_decompile`, `trace_feature`, and `find_xrefs_to_name` work through these operations.

Session availability reports these operations as unavailable, each with its reason:

| Operation                                                                                                                                    | Reason                                                                      |
| -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `annotate_native_function`, `set_address_name`, `set_addresses_names`, `set_comment`, `set_inline_comment`, `set_bookmark`, `unset_bookmark` | The adapter is read-only.                                                   |
| `current_address`, `current_procedure`, `current_document`, `goto_address`                                                                   | The MCP server exposes no GUI cursor.                                       |
| `next_address`, `prev_address`, `list_bookmarks`                                                                                             | The MCP server has no such query.                                           |
| `inline_comment`                                                                                                                             | Binary Ninja keeps one comment per address; `comment` serves it.            |
| `inspect_native_instruction`, `inspect_native_load_image`                                                                                    | The MCP server does not report the required facts.                          |
| `resolve_native_call_targets`, `inspect_native_data_type`                                                                                    | Not mapped yet. `bn_function_callees` and `bn_type_info` could supply them. |

### What the results do and do not establish

- **Procedures** are resolved by entry address or by name. A name must match one rendered function name exactly, or one name without its parameter list. Interior addresses are rejected; use `resolve_containing_procedure`.
- **Function bodies** are complete: `procedure_info` and dossiers carry the inclusive ranges Binary Ninja reports.
- **References** have endpoints but no type flags. Incoming non-call references name the function they enter, not the exact target address, so the entry address stands in. Outgoing non-call references carry the start of the source range. A call site without an analyzed callee is listed under unresolved calls.
- **`xrefs`** on a function entry returns its call sites and data references. On any other address it returns data references only. The MCP server has no query for code that references a data address, so an empty list there does not mean the address is unreferenced.
- **Strings** are Binary Ninja string objects, decoded from their bytes. A listing previews at most 256 bytes per object; longer values are cut and counted in the result limitations. With an explicit address, or for search hits found through Binary Ninja's own filter, REA reads the whole object, up to 65536 bytes.
- **Search** of a literal made of printable ASCII, without `\` or `|`, is preselected by Binary Ninja's case-insensitive substring filter and rechecked locally. Every other pattern, including regex mode, walks the whole inventory.
- **Dossiers** leave referenced strings, referenced names, and comments other than the entry comment empty. Empty there means unknown.
- `provider.version` identifies the REA adapter. The Binary Ninja version is not reported; MCP `serverInfo` is preserved in raw observations.
- Results are live and reflect analyst names, types, and patches in the database. They are never replayed from analysis snapshots.

### Large binaries

Whole-database inventories are complete by contract and therefore large. A browser core has hundreds of thousands of functions and millions of string objects; `list_strings`, `list_names`, `binary_overview`, and regex searches walk all of them at 1000 rows per request. Prefer function-scoped operations and ASCII literal searches there, and set your MCP client's response budget (`REA_MCP_MAX_RESPONSE_BYTES`) and request deadline accordingly.

## Operator tooling

Two scripts in a source checkout support long analyses of large binaries. They are not part of the `rea` CLI, the MCP catalog, or the published package, because they do what the analysis surface must never do: one can change GUI state, and both coordinate callers. Each needs the compiled runtime (`npm run build:cached`).

Both honor one lock, taken without waiting: a SQLite exclusive transaction on the lock file, which the operating system releases if the holder dies. Whoever holds the lock owns Binary Ninja. Plain `rea` commands do not take it.

### Database tool

```bash
export REA_BINJA_MCP_URL=http://127.0.0.1:24642/mcp
export REA_BINJA_LOCK=/absolute/path/to/fetch.lock
node scripts/binja-database.mjs list --root /path/to/binaries
node scripts/binja-database.mjs open /absolute/path/to/program
node scripts/binja-database.mjs wait --limit 900
node scripts/binja-database.mjs status
node scripts/binja-database.mjs save item_2
node scripts/binja-database.mjs call bn_function_info '{"function":"0x401000"}'
```

- `list` prints saved `*.bndb` files under `--root` and the open items with their unsaved-change flag.
- `open` avoids repeating an analysis. An item that is already open is only activated. Otherwise the saved database beside the binary (`<name>.bndb` or `<stem>.bndb`, the newer one) is opened, and only without one the binary itself. A second item is refused unless `--allow-second` is given. The recommended view of the item is then made active.
- `status` and `wait` report the analysis state; `wait` polls until idle or until the next poll would pass `--limit`. Exit code 3 means not idle.
- `save` saves one named open item of an idle view. It is never retried: a save that timed out is still running.
- `call` forwards one raw tool call. It accepts read-only tools; any other tool needs `--mutating`. `bn_open_item_close` is never called.

Only `open`, `save`, and `call --mutating` change Binary Ninja state, and only when invoked. Exit code 2 means refused.

### Fetch lane

```bash
export REA_BINJA_MCP_URL=http://127.0.0.1:24642/mcp
node scripts/binja-fetch-lane.mjs --target /absolute/path/to/program \
  --queue work/queue.txt --requests work/requests \
  --json-dir evidence/json --code-dir evidence/code --watch 1800
```

The lane drains queued function addresses through the public `rea decompile` and `rea function` commands with `--provider binja`, strictly one call at a time, and saves the results for offline readers.

- A queue file has one hexadecimal address per line; `0x` is optional and text after the address or after `#` is a comment. `full <addr>` asks for the dossier instead of pseudocode alone. Readers add work by dropping `*.txt` files into the requests directory. The queue is re-read before every call, and plain requests run before `full` ones.
- Each result is saved as the unmodified Evidence envelope (`<json-dir>/decompile-<addr>.json` or `function-<addr>.json`) and as text (`<code-dir>/0x<addr>-REA.c`; for `full` also `.asm` and `.calls.txt`). The call file lists callers and callees by address and name; a call whose target is not an analyzed function is listed by its target address.
- Saved files are never overwritten. An address whose text file exists is skipped. A repeated read gets a new envelope name (`decompile-<addr>.2.json`).
- A failure writes `<command>-<addr>.err` and the address is not retried in that run. Three consecutive failures (`--max-failures`) stop the lane, so a wrong active view or a stalled Binary Ninja is not hammered.
- Waiting is bounded: `--watch` is the idle time after which the lane exits, `--timeout` the deadline of one call.
- The lock is `--lock`, else `REA_BINJA_LOCK`, else `<json-dir>/fetch.lock`. A second lane on the same lock is refused.

Exit code 0 means idle without failures, 1 failures or stopped, 2 refused.

## Connect an agent

```json
{
  "mcpServers": {
    "rea": {
      "command": "npx",
      "args": ["-y", "rea-agents@<version-with-binja>", "mcp"],
      "env": {
        "REA_ANALYSIS_PROVIDER": "binja",
        "REA_BINJA_MCP_URL": "http://127.0.0.1:24642/mcp"
      }
    }
  }
}
```

```json
{"name":"open_binary","arguments":{"path":"/absolute/path/to/program","provider_id":"binja"}}
{"name":"analyze_function","arguments":{"procedure":"0x401000"}}
{"name":"close_binary","arguments":{}}
```

Opening a target does not contact Binary Ninja; the first analysis request binds the active view. `binary_session` reports actual tool availability.

## Verification

Run `npm run verify:binja -- --target /absolute/path/to/program --procedure 0x401000` with Binary Ninja running and the target's view active. It exercises the production CLI and MCP server, validates output contracts and Evidence, checks that a mutation is refused, and confirms that the open items, their unsaved-change flags, and the active view are unchanged afterwards. Whole-database inventories are skipped unless `--inventories` is given. See [testing](testing.md#binary-ninja-mcp-adapter) for what the adapter tests do and do not establish.
