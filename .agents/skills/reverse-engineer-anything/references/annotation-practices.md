# Annotating an analysis database

Read this when the user asks for names, comments or types to be left in an
analysis database. REA writes only where a provider advertises it: with Ghidra,
`annotate_native_function` and `set_address_name` / `set_addresses_names` edit
the session database until close. The IDA and Binary Ninja adapters are
read-only. Annotate those only through a route the user selected outside REA,
and apply the same practices below.

## Names carry their evidence level

Give each name one tier, visible in the database itself:

| Tier      | Requires                                                                                                                                                                    | Form                                                                        |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Confirmed | A naming fact (export, debug symbol, RTTI, a string that names the function) or two independent structural facts (e.g. a registration slot and matching upstream constants) | The plain name                                                              |
| Inferred  | One supporting fact, or structure alone (a sole caller, a call pattern, string use)                                                                                         | The user's marker, else the prefix `maybe_`                                 |
| Unknown   | No defensible meaning                                                                                                                                                       | Keep the provider's default name; add a comment if the role is partly known |

The prefix is part of the stored name. A tier noted only in a comment or a
report doesn't show in listings, cross-references or pseudocode.

Promote a name only when new evidence meets the confirmed row. A plausible
name with weak evidence misleads the next analyst more than `sub_` does.
For code matched to an upstream project, use its symbol names and record the
project and version in the comment (see
[native and artifacts](native-and-artifacts.md#identify-embedded-open-source-code)).

## Comments state the claim and its evidence

Write each comment as: claim, evidence, tier. Evidence means addresses, REA
Evidence IDs, or a named external source with its version. Example:
`Loop-filter entry, luma, horizontal edges. Registered in slot [0][0] by 0x17ff394;
control flow matches upstream lpf_h_sb_y (dav1d, version unknown). Confirmed.`

## Types come from observed layout

Create a struct, enum or typedef only from observed facts: field offsets in
accesses, allocation or frame sizes, constant tables, or a matched upstream
definition whose offsets agree with the code. Then apply it to prototypes,
variables and globals, and re-read the pseudocode: field accesses should replace
raw offsets. A type that is defined but never applied adds nothing.

## Existing annotations are claims

Names, types and comments already in the database, from an earlier pass or
another analyst, carry unknown evidence. Before building on one, check it as
you would a new write: read the code or bytes it describes (for named tables,
compare each name with its values). Record any correction with its evidence.

## Leave a starting point for the next session

A saved database is the next session's input. Keep a ledger file with the
goal, each question and its status, the annotations with their evidence, and
the next steps, and point to it from a comment at a fixed address, such as the
image start. A later session reads that comment and the ledger, lists the
user-defined names and types, and continues from the open questions. Writes
listed in the ledger but missing from the database were never saved.

## Verify writes and keep the log from tool results

- Batch related writes, then read the changed state back: name, comment,
  prototype or type at each target. For named tables or constants, compare each
  name with the bytes it labels.
- Build the write log from the tool results or a call journal: target, old
  value, new value, evidence. Writing it from memory drifts from the database.
- Report any write that failed or read back differently. Leave saving the
  database to the user unless they asked otherwise.
