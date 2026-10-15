#!/usr/bin/env bash
# One raw call to Binary Ninja's built-in MCP server, serialized and journaled.
#
#   bash bn.sh TOOL ['{"json":"args"}']
#
# - Calls hold an exclusive flock, so concurrent callers queue instead of
#   hitting Binary Ninja's one-request-at-a-time handler in parallel.
#   (REA's own MCP calls do not take this lock.)
# - Database lifecycle, view switching, section edits and analysis abort are refused.
# - Writes require BN_EXPECT_ITEM and run only while that open item is active.
# - Every write is appended to $BN_JOURNAL with the value before and after,
#   both read back from Binary Ninja, so the write log never depends on memory.
#
# Environment:
#   REA_CHECKOUT       REA source checkout with built dist/ (provides the MCP client);
#                      defaults to the checkout containing this script, followed
#                      through symlinks
#   REA_BINJA_MCP_URL  default http://127.0.0.1:24642/mcp
#   BN_EXPECT_ITEM     open item handle that writes may target, e.g. item_1
#   BN_JOURNAL         default ./bn-journal.jsonl
#   BN_AGENT           label recorded in the journal (default: lead)
#   BN_LOCK            default ${XDG_RUNTIME_DIR:-/tmp}/bn-mcp.lock
set -uo pipefail

self="$(readlink -f "${BASH_SOURCE[0]}")"
# scripts/ -> skill -> .agents/skills -> .agents -> checkout root
REA_CHECKOUT="${REA_CHECKOUT:-$(cd "$(dirname "$self")/../../../.." 2>/dev/null && pwd)}"
export REA_BINJA_MCP_URL="${REA_BINJA_MCP_URL:-http://127.0.0.1:24642/mcp}"
JOURNAL="${BN_JOURNAL:-$PWD/bn-journal.jsonl}"
LOCK="${BN_LOCK:-${XDG_RUNTIME_DIR:-/tmp}/bn-mcp.lock}"
AGENT="${BN_AGENT:-lead}"
CLIENT="$REA_CHECKOUT/scripts/binja-database.mjs"

tool="${1:-}"
args="${2:-}"
[ -n "$args" ] || args='{}'
SKILL_MD="$(readlink -f "$(dirname "$self")/../SKILL.md")"
case "$tool" in
  ""|-h|--help|help)
    echo "usage: bash bn.sh TOOL [JSON]"
    echo "Tool names and exact arguments: 'Write recipes' and 'Read notes' in $SKILL_MD"
    [ -n "$tool" ] && exit 0; exit 2 ;;
esac
[ -f "$CLIENT" ] && [ -d "$REA_CHECKOUT/dist" ] || {
  echo "bn.sh: no built REA checkout at '$REA_CHECKOUT'; set REA_CHECKOUT, or run npm run build:cached there" >&2
  exit 2
}
jq -e 'type == "object"' >/dev/null 2>&1 <<<"$args" || { echo "bn.sh: arguments must be one JSON object" >&2; exit 2; }

case "$tool" in
  bn_open_item_save|bn_open_item_open|bn_open_item_close|bn_binary_view_set_active|\
  bn_project_file_open|bn_section_create|bn_section_delete|bn_section_modify|bn_analysis_abort)
    echo "bn.sh: $tool is refused: database lifecycle, view switching and section edits belong to the user" >&2
    exit 2 ;;
esac

write=1
case "$tool" in
  *_list|*_list_at|*_get|*_get_active|*_info|*_triage|*_decompile|*_disassembly|*_il|\
  *_callers|*_callees|*_xrefs_to|*_xrefs_from|*_search|*_complexity|*_stack_layout|\
  *_basic_blocks|bn_memory_read|bn_data_at|bn_analysis_status|bn_type_parse)
    write=0 ;;
esac

call() { node "$CLIENT" call "$1" "$2" --mutating 2>&1 | grep -v '^binja-database: no --lock'; return "${PIPESTATUS[0]}"; }
arg() { jq -r --arg k "$1" '.[$k] // empty' <<<"$args"; }

# The read that shows the state a write changes, or nothing when there is none.
probe() {
  case "$tool" in
    bn_comment_set|bn_comment_delete)
      jq -cn --arg a "$(arg comment)" '["bn_comment_get", {comment: $a}]' ;;
    bn_symbol_define|bn_symbol_rename|bn_symbol_undefine)
      jq -cn --arg a "$(arg symbol)" '["bn_symbol_list_at", {address: $a}]' ;;
    bn_function_prototype_set|bn_calling_convention_set)
      jq -cn --arg f "$(arg function)" '["bn_function_prototype_get", {function: $f}]' ;;
    bn_variable_rename|bn_variable_set_type)
      jq -cn --arg f "$(arg function)" '["bn_variable_list", {function: $f, limit: 1000}]' ;;
    bn_data_variable_define|bn_data_variable_undefine)
      jq -cn --arg a "$(arg datavar)" '["bn_data_at", {address: $a}]' ;;
    bn_type_*)
      t="$(arg type)"; [ -n "$t" ] && jq -cn --arg t "$t" '["bn_type_info", {type: $t}]' ;;
  esac
}
snapshot() {
  local p="$1"; [ -n "$p" ] || return 0
  local out; out=$(call "$(jq -r '.[0]' <<<"$p")" "$(jq -c '.[1]' <<<"$p")")
  if [ "$tool" = bn_variable_rename ] || [ "$tool" = bn_variable_set_type ]; then
    # Keep only the rows for the variable being changed (old or new name).
    grep -F -e "$(arg variable)" -e "$(arg newName)" <<<"$out" | grep -v '^---' || true
  else
    printf '%s' "$out"
  fi
}

exec 9>"$LOCK"
flock -w 900 9 || { echo "bn.sh: waited 900 s for the Binary Ninja lane; another caller holds $LOCK" >&2; exit 3; }

if [ "$write" = 1 ]; then
  [ -n "${BN_EXPECT_ITEM:-}" ] || { echo "bn.sh: set BN_EXPECT_ITEM (from bn_open_item_list) before writing" >&2; exit 2; }
  active=$(call bn_binary_view_get_active '{}')
  item=$(jq -r '.binaryView.openItem // empty' <<<"$active" 2>/dev/null)
  if [ "$item" != "$BN_EXPECT_ITEM" ]; then
    echo "bn.sh: refused $tool: active item is '${item:-unknown}', expected $BN_EXPECT_ITEM" >&2
    exit 2
  fi
  p=$(probe)
  before=$(snapshot "$p")
fi

out=$(call "$tool" "$args"); rc=$?
[ "$rc" = 0 ] || echo "bn.sh: $tool failed; check its name and arguments in 'Write recipes' or 'Read notes': $SKILL_MD" >&2

if [ "$write" = 1 ]; then
  after=$(snapshot "$p")
  # Binary Ninja reports whether the write changed anything; null when it doesn't say.
  changed=$(jq -c 'if type == "object" and has("changed") then .changed else null end' <<<"$out" 2>/dev/null) || changed=null
  [ -n "$changed" ] || changed=null
  jq -cn --arg ts "$(date -Is)" --arg agent "$AGENT" --arg item "$BN_EXPECT_ITEM" --arg tool "$tool" \
     --argjson args "$args" --argjson rc "$rc" --argjson changed "$changed" \
     --arg before "$before" --arg after "$after" --arg result "$(head -c 2000 <<<"$out")" \
     '{ts:$ts, agent:$agent, item:$item, tool:$tool, args:$args, rc:$rc, changed:$changed, before:$before, after:$after, result:$result}' \
     >>"$JOURNAL"
fi
printf '%s\n' "$out"
exit "$rc"
