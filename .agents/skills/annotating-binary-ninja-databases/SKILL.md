---
name: annotating-binary-ninja-databases
description: Use when an analysis with REA's Binary Ninja provider must also leave names, comments, user types, prototypes or variable types in the open Binary Ninja database, or when REA reports annotate_native_function, set_address_name or set_comment unavailable for binja.
---

# Annotating Binary Ninja databases

REA's `binja` provider is read-only by design: it gives evidence, not edits.
Annotations go through Binary Ninja's own MCP server, using `scripts/bn.sh`.
That script queues calls one at a time, refuses database lifecycle tools, and
writes only to the open item you name. It journals every write with the state
before and after, read back from Binary Ninja.

**Required background:** the `reverse-engineer-anything` skill, and its
`references/annotation-practices.md` for naming tiers, comment content, types
and verification. This skill covers only the Binary Ninja route.

## Start

`bn.sh` needs a built REA source checkout (`npm run build:cached`). It finds
the checkout this skill lives in, following symlinks. For a copied install,
set `REA_CHECKOUT`.

1. Read: `bash scripts/bn.sh bn_open_item_list` and `bash scripts/bn.sh bn_binary_view_get_active`.
   Confirm the active item is the user's target. Never switch it yourself.
2. `export BN_EXPECT_ITEM=<item_N> BN_JOURNAL=<report dir>/bn-journal.jsonl REA_BINJA_MCP_URL=http://127.0.0.1:24642/mcp`.
   Writes fail closed until `BN_EXPECT_ITEM` is set and that item is active.
   REA's CLI needs `REA_BINJA_MCP_URL` too; `bn.sh` has its own default, REA does not.
3. Use `bn.sh` for reads REA doesn't map (IL, types, variables, data
   variables) and for every write. Cite REA Evidence as described next.

Binary Ninja handles one request at a time. Only the lead agent calls it.
Sub-agents work from saved files (see Workers below). REA refuses requests while
analysis isn't idle, so finish a write batch with `bn_analysis_update_and_wait`
before going back to REA.

## Evidence for names

- **Confirmed function name:** one REA `analyze_function` record for that
  function. Cite its Evidence ID in the function's comment and in the report.
- **Inferred names, tables, constants, IL, types:** cite the `bn.sh`
  observation by tool and address, or the upstream source and version.

The complete record is about 190 KB, more than several clients accept as one
tool result. Produce it with the CLI into a file and never print it:

```bash
node "$REA_CHECKOUT/scripts/rea.mjs" function <original binary> 0xENTRY --provider binja --json > rea/fn-0xENTRY.json
jq -r .evidence_id rea/fn-0xENTRY.json
```

Read parts of it without re-running the analysis; facets include `procedure`,
`pseudocode`, `assembly`, `callers`, `callees` and `references`:

```bash
jq -c '{source:{kind:"inline",evidence:.},view:{kind:"native",facet:"pseudocode",offset:0,limit:4000}}' rea/fn-0xENTRY.json > rea/view.json
node "$REA_CHECKOUT/scripts/rea.mjs" inspect-analysis-view rea/view.json --json
```

These pages make good worker packets: they keep the parent Evidence ID. With
REA's MCP tools, a client that saves an oversized `analyze_function` result to a
file still gives you the Evidence ID; page `inspect_analysis_view` from there.

## Write recipes (arguments verified against the server)

| Goal                                    | Call                                                                                                                                                                                                  |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Name an auto-named function (`sub_*`)   | `bn_symbol_define {"symbol":"0xADDR","name":"N","type":"FunctionSymbol"}`; an inferred name is stored with its prefix: `"name":"maybe_N"`                                                             |
| Rename an existing user/imported symbol | `bn_symbol_rename {"symbol":"0xADDR","newName":"N"}` (fails with `symbol_not_found` on auto names)                                                                                                    |
| Name a global                           | `bn_symbol_define {"symbol":"0xADDR","name":"N","type":"DataSymbol"}`                                                                                                                                 |
| Undo a name                             | `bn_symbol_undefine {"symbol":"0xADDR","name":"N","type":"FunctionSymbol"}`                                                                                                                           |
| Comment (one per address)               | `bn_comment_set {"comment":"0xADDR","text":"…"}`; clear with `bn_comment_delete {"comment":"0xADDR"}`                                                                                                 |
| Create a struct / enum                  | `bn_type_struct_create {"source":"struct S { … };"}`, `bn_type_enum_create {"source":"enum E { … };"}`; several at once: `bn_type_define {"source":"…"}`. Create a type before any definition uses it |
| Function prototype                      | `bn_function_prototype_set {"function":"0xENTRY","prototype":"void f(struct S* s, int n)"}`                                                                                                           |
| Variable name / type                    | `bn_variable_rename {"function":"0xENTRY","variable":"<current name from bn_variable_list>","newName":"N","skipAnalysisUpdate":true}`; `bn_variable_set_type {…,"definition":"struct S*"}`            |
| Global's type                           | `bn_data_variable_define {"datavar":"0xADDR","definition":"int16_t[8]"}`                                                                                                                              |
| After a batch                           | `bn_analysis_update_and_wait {}`                                                                                                                                                                      |

Each write response carries `mutation.before`/`after` and `changed`. The journal
also stores an independent readback (`before`, `after`) for comments, symbols,
prototypes, variables, data variables and named types, and records `changed`, so
re-running a batch leaves no-op entries marked `changed: false`.

## Read notes

- Containing function of an interior address: `bn_data_at {"address":…}`.
  `bn_function_*` tools take entry addresses only.
- Callers/callees include jump and fallthrough edges, not just calls.
- Disassembly and IL are paged: pass `offset`/`limit` (≤1000). Never pull a whole large function into context.
- Search strings and functions with `query` (case-insensitive substring) on `bn_string_list` and `bn_function_list`. Don't page whole inventories.
- List tools return markdown tables; most other tools return JSON.

## Workers (small-model sub-agents)

1. Lead saves the input packet: REA `analyze_function` Evidence, or `bn.sh`
   disassembly/HLIL pages, plus the relevant constants and reference source,
   all as files. Size it to the worker model's context: one function's pages,
   the constants it uses and the matching upstream excerpt. Give line or
   address ranges for anything larger, and tell the worker to read in ranges
   (`sed -n`, offset/limit). A worker that reads whole assembly or source
   files overflows a small model.
2. One worker per function or branch, on a small model (Claude Code: `model: "haiku"`).
   Workers get file paths only: no Binary Ninja access, no writes. If the
   requested model isn't available, say so and name the substitute.
3. Each worker returns proposals: `target | kind (name/comment/type/prototype) | value | evidence addresses | tier (confirmed/inferred) | UNVERIFIED parts`.
4. Lead checks every proposal against raw evidence, then writes. Record rejections and corrections in the findings report.

## Write log

The journal is the write log; don't write it from memory. Render it with:

```bash
jq -r 'select(.changed != false)|[.ts,.tool,(.args|tostring),.rc,(.before|gsub("\n";" ")|.[0:160]),(.after|gsub("\n";" ")|.[0:160])]|@tsv' "$BN_JOURNAL"
```

Before finishing, read back every table-like batch (e.g. named constants
against their bytes via `bn_memory_read`). Report any mismatch.

## Common mistakes

| Mistake                                                  | Fix                                                                                                      |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `bn_symbol_rename` on `sub_*` → `symbol_not_found`       | `bn_symbol_define` with `type: "FunctionSymbol"`                                                         |
| Paging all strings to find one                           | `bn_string_list` with `query`                                                                            |
| `bn_function_info` on an interior address                | `bn_data_at` first                                                                                       |
| Hand-written write log drifting from the database        | Render the journal; read back batches                                                                    |
| Inferred names indistinguishable from confirmed ones     | Store the `maybe_` prefix in the name; a tier noted only in a comment or report doesn't show in listings |
| Applying a type before creating it → `Type parse failed` | Create the struct/enum first, then apply it                                                              |
| Building on earlier annotations without checking them    | Treat them as claims; read back the ones you rely on                                                     |
| Several agents calling Binary Ninja                      | Workers read saved files; only the lead calls `bn.sh`                                                    |
| Saving, closing or switching the database                | Never; `bn.sh` refuses, and the user saves when satisfied                                                |
