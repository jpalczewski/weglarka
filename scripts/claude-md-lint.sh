#!/usr/bin/env bash
# Lint the agent instructions: the root CLAUDE.md and the path-scoped rules in .claude/rules/.
#
#   scripts/claude-md-lint.sh              size limits, `paths:` globs, relative Markdown links
#   scripts/claude-md-lint.sh --coverage REF
#       compare a previous CLAUDE.md (`git show REF:CLAUDE.md`) with the current tree: every backticked token,
#       `ADR 00NN`, `#NN` and docs/crates path must still appear in CLAUDE.md or .claude/rules/*.md
#
# Limits: root CLAUDE.md <= 120 lines; a rule <= 40,000 characters (Claude Code truncates on-demand files past ~40k).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

max_root_lines=120
max_rule_chars=40000
problems=0

fail() {
  printf 'claude-md lint: %s\n' "$*" >&2
  problems=$((problems + 1))
}

check_sizes() {
  local lines
  lines=$(wc -l <CLAUDE.md)
  if ((lines > max_root_lines)); then
    fail "CLAUDE.md has $lines lines (limit $max_root_lines)"
  fi
  local f chars
  for f in .claude/rules/*.md; do
    chars=$(wc -m <"$f")
    if ((chars > max_rule_chars)); then
      fail "$f has $chars characters (limit $max_rule_chars)"
    fi
  done
}

# Prints the quoted globs of the `paths:` list in a rule's frontmatter, one per line.
rule_globs() {
  awk '
    NR == 1 && $0 == "---" { fm = 1; next }
    fm && $0 == "---" { exit }
    fm && /^paths:/ { inpaths = 1; next }
    fm && inpaths && /^  - / { sub(/^  - /, ""); gsub(/^"|"$/, ""); print; next }
    fm && inpaths && !/^  - / { inpaths = 0 }
  ' "$1"
}

# Expands one level of {a,b,c} brace alternatives (nested/multiple groups are expanded recursively).
expand_braces() {
  local glob=$1
  if [[ $glob =~ ^(.*)\{([^{}]*)\}(.*)$ ]]; then
    local pre=${BASH_REMATCH[1]} alts=${BASH_REMATCH[2]} post=${BASH_REMATCH[3]} alt
    local IFS=,
    for alt in $alts; do
      expand_braces "$pre$alt$post"
    done
  else
    printf '%s\n' "$glob"
  fi
}

check_globs() {
  local tracked
  tracked=$(git ls-files)
  local f glob variant regex found
  for f in .claude/rules/*.md; do
    if [[ $(head -n 1 "$f") == "---" ]] && [[ -z $(rule_globs "$f") ]]; then
      fail "$f: frontmatter without a quoted \`paths:\` list"
    fi
    while IFS= read -r glob; do
      [[ -z $glob ]] && continue
      found=0
      while IFS= read -r variant; do
        # glob -> regex: `**/` any directories, `**` anything, `*` within a segment, `.` literal
        regex=$(printf '%s' "$variant" | sed -e 's/[.]/\\./g' -e 's#\*\*/#\x01#g' -e 's#\*\*#\x02#g' -e 's#\*#[^/]*#g' \
          -e 's#\x01#(.*/)?#g' -e 's#\x02#.*#g')
        if grep -Eq "^${regex}\$" <<<"$tracked"; then
          found=1
        else
          fail "$f: brace alternative '$variant' of glob '$glob' matches no tracked file"
        fi
      done < <(expand_braces "$glob")
      ((found)) || true
    done < <(rule_globs "$f")
  done
}

# Relative Markdown links `](target)` must resolve to a tracked path (anchors and URLs are skipped).
check_links() {
  local f dir target path
  for f in CLAUDE.md .claude/rules/*.md; do
    dir=$(dirname "$f")
    while IFS= read -r target; do
      case $target in
        http://* | https://* | mailto:* | '#'*) continue ;;
      esac
      path=${target%%#*}
      [[ -z $path ]] && continue
      if [[ ! -e "$dir/$path" ]]; then
        fail "$f: broken link '$target'"
      fi
    done < <(grep -oE '\]\([^)]+\)' "$f" | sed -e 's/^](//' -e 's/)$//')
  done
}

# Everything an old CLAUDE.md mentioned must still be somewhere in the new tree.
check_coverage() {
  local ref=$1 old new missing=0
  old=$(mktemp)
  new=$(mktemp)
  trap 'rm -f "$old" "$new"' RETURN
  git show "$ref:CLAUDE.md" | tr '\n' ' ' | tr -s ' ' >"$old"
  # collapse whitespace so a token wrapped across lines still matches
  cat CLAUDE.md .claude/rules/*.md | tr '\n' ' ' | tr -s ' ' >"$new"

  local token base
  {
    # shellcheck disable=SC2016
    grep -oE '`[^`]+`' "$old" | sed -e 's/^`//' -e 's/`$//'
    grep -oE 'ADR [0-9]{4}' "$old"
    grep -oE '#[0-9]+' "$old"
    grep -oE '(docs|crates)/[A-Za-z0-9_./-]+' "$old"
  } | sort -u | while IFS= read -r token; do
    [[ -z $token ]] && continue
    if grep -qF -- "$token" "$new"; then continue; fi
    # Polish placeholders and words that were translated on purpose (see the PR that split CLAUDE.md)
    case $token in
      '#kotwicy' | '<apka>.'* | '<katalog stanu>/'* | '<nginx_conf_dir>/tls/<domena>'* | '[shared_volumes.<nazwa>]') continue ;;
      'daemon → wszystko' | 'docs/guides/<temat>.md' | '* → (nic z Węglarki)' | 'scripts/worktree.sh sweep [dni]') continue ;;
      'http → (nic z Węglarki)' | 'unix-http → (nic z Węglarki)' | 'wg-shared-<nazwa>') continue ;;
    esac
    # old file used crate-relative paths (`daemon/src/x.rs`); accept the same file under crates/weglarka-*/
    if [[ $token == */* && $token != *' '* ]]; then
      base=${token##*/}
      if grep -qF -- "${token#*/}" "$new" || { [[ -n $base ]] && grep -qF -- "$base" "$new"; }; then continue; fi
    fi
    printf 'MISSING: %s\n' "$token"
  done >"$old.missing"
  missing=$(wc -l <"$old.missing")
  cat "$old.missing"
  rm -f "$old.missing"
  if ((missing > 0)); then
    fail "$missing token(s) from $ref:CLAUDE.md are missing from the new tree"
  fi
}

if [[ ${1:-} == --coverage ]]; then
  check_coverage "${2:?usage: claude-md-lint.sh --coverage REF}"
else
  check_sizes
  check_globs
  check_links
fi

if ((problems > 0)); then
  exit 1
fi
printf 'claude-md lint: OK\n'
