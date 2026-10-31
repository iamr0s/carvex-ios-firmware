export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"

_setup_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
_repo_root=$(cd -- "$_setup_dir/../.." && pwd)

# Resolve Ghidra relative to this repository so moving the workspace does not
# require editing this file. An inherited variable from an old workspace is
# ignored when it no longer points at a usable Ghidra installation.
if [ -n "${GHIDRA_HOME:-}" ] && [ ! -x "$GHIDRA_HOME/support/analyzeHeadless" ]; then
  unset GHIDRA_HOME
fi
if [ -z "${GHIDRA_HOME:-}" ]; then
  _d="$_repo_root/firmware/tools/ghidra"
  if [ -x "$_d/support/analyzeHeadless" ]; then
    export GHIDRA_HOME="$_d"
  fi
fi
unset _d _setup_dir _repo_root

: "${GHIDRA_HOME:?set GHIDRA_HOME to a Ghidra 12.x installation}"
export GHIDRA_ANALYZE_HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"
