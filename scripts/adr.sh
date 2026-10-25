#!/usr/bin/env bash
# ADR tooling: the generated decisions index, numbering/link lint, and renumbering after a collision.
#
#   scripts/adr.sh index [--check]   rewrite docs/decisions/README.md from the ADR titles
#                                    (--check: only verify it is current, for CI)
#   scripts/adr.sh lint              numbering, index freshness, cross-references, Markdown links and anchors, guide index
#   scripts/adr.sh renumber OLD NEW  rename an ADR and update every reference to it
#
# `lint` runs in CI (job `docs-lint`) for every PR, docs-only ones included: a rebase that left two
# PRs with the same ADR number, or a section renumber that broke a link, fails there in seconds
# instead of surfacing at merge time.
#
# Numbering is a shared resource across branches, so a collision is normal, not a mistake: reserve the
# number early (push the branch with the ADR stub and open a draft PR) and renumber in one command.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

adr_dir=docs/decisions
index=$adr_dir/README.md

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# The ADR files that are decisions (0000-template.md is the skeleton).
adr_files() {
  find "$adr_dir" -maxdepth 1 -name '[0-9][0-9][0-9][0-9]-*.md' ! -name '0000-*' -print | LC_ALL=C sort
}

# First line "# NNNN — Topic" → "NNNN<TAB>Topic"; fails on a malformed title.
adr_title() {
  head -n 1 "$1" | perl -CSD -ne '
    if (/^# (\d{4}) \x{2014} (.+?)\s*$/) { print "$1\t$2\n" } else { exit 1 }
  '
}

# GitHub's heading anchor: lowercase, punctuation dropped, spaces → hyphens (Unicode letters kept).
slugify() {
  perl -CSD -ne 's/^#+[ \t]+//; chomp; $_ = lc; s/[^\p{L}\p{N} _-]//g; s/ /-/g; print "$_\n"'
}

generate_index() {
  cat <<'EOF'
# Implementation decisions (ADR)

Each decision describes the problem, the choice, the consequences and the rejected alternatives. New
entries are numbered consecutively (`0001`, `0002`, …) and the skeleton is
[`0000-template.md`](0000-template.md). The table below is generated from the ADR titles by
`scripts/adr.sh index`, and CI (`scripts/adr.sh lint`) verifies it is current — do not edit it by hand.

| # | Topic |
|---|---|
EOF
  local file line
  while IFS= read -r file; do
    line=$(adr_title "$file") || die "$file: first line must be '# NNNN — <topic>'"
    printf '| [%s](%s) | %s |\n' "${line%%$'\t'*}" "${file##*/}" "${line#*$'\t'}"
  done < <(adr_files)
}

write_index() {
  local tmp
  tmp=$(mktemp)
  generate_index >"$tmp"
  mv "$tmp" "$index"
}

check_index() {
  local tmp
  tmp=$(mktemp)
  generate_index >"$tmp"
  if ! diff -q "$index" "$tmp" >/dev/null; then
    printf 'error: %s is stale — run scripts/adr.sh index\n' "$index" >&2
    diff -u "$index" "$tmp" >&2 || true
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
}

lint_adr_titles() {
  local problems=0 file line num number_file
  number_file=$(mktemp)
  while IFS= read -r file; do
    if ! line=$(adr_title "$file" 2>/dev/null); then
      printf 'error: %s: first line must be "# NNNN — <topic>"\n' "$file" >&2
      problems=$((problems + 1))
      continue
    fi
    num=${line%%$'\t'*}
    if [[ ${file##*/} != "$num"-* ]]; then
      printf 'error: %s: title says %s but the file name says otherwise\n' "$file" "$num" >&2
      problems=$((problems + 1))
    fi
    printf '%s\n' "$num" >>"$number_file"
  done < <(adr_files)
  while IFS= read -r num; do
    printf 'error: ADR number %s is used by more than one file — renumber one:\n' "$num" >&2
    printf '       scripts/adr.sh renumber %s <free number>\n' "$num" >&2
    problems=$((problems + 1))
  done < <(sort "$number_file" | uniq -d)
  rm -f "$number_file"
  return $((problems > 0))
}

lint_cross_references() {
  local problems=0 ref number matches
  # Links written as `docs/decisions/NNNN-file.md` or `decisions/NNNN-file.md` (both resolve under docs/).
  while IFS= read -r ref; do
    [ -f "docs/${ref#docs/}" ] || {
      printf 'error: link to a missing ADR: %s\n' "$ref" >&2
      problems=$((problems + 1))
    }
  done < <(git grep -hoE '(docs/)?decisions/[0-9]{4}-[a-z0-9-]+\.md' -- '*.md' '*.rs' | LC_ALL=C sort -u)
  # ADR-to-ADR links written as `NNNN-file.md` (relative to docs/decisions/).
  while IFS= read -r ref; do
    [ -f "$adr_dir/$ref" ] || {
      printf 'error: link to a missing ADR: %s/%s\n' "$adr_dir" "$ref" >&2
      problems=$((problems + 1))
    }
  done < <(git grep -hoE '\([0-9]{4}-[a-z0-9-]+\.md\)' -- '*.md' | tr -d '()' | LC_ALL=C sort -u)
  # Plain "ADR NNNN" mentions in prose.
  while IFS= read -r number; do
    matches=$(find "$adr_dir" -maxdepth 1 -name "$number-*.md" -print -quit)
    [ -n "$matches" ] || {
      printf 'error: "ADR %s" is mentioned but no such ADR exists\n' "$number" >&2
      problems=$((problems + 1))
    }
  done < <(git grep -hoE 'ADR [0-9]{4}' -- '*.md' '*.rs' | awk '{print $2}' | LC_ALL=C sort -u)
  return $((problems > 0))
}

# Every relative link in a Markdown file must resolve: the target file exists and, for `file.md#anchor`
# or `#anchor`, the anchor matches a heading of that file. Duplicate "##"/"###" headings in one file are
# rejected because they make anchors ambiguous. Every guide must be listed in docs/guides/README.md.
lint_doc_links() {
  local problems=0
  git ls-files -z --cached --others --exclude-standard -- '*.md' | perl -0 -CSD -e '
    use strict; use File::Basename qw(dirname); use File::Spec;
    my (%slugs, %dups, $bad);
    sub slug { my $t = shift; $t =~ s/^#+[ \t]+//; $t =~ s/[ \t]+$//; $t = lc $t; $t =~ s/[^\p{L}\p{N} _-]//g; $t =~ s/ /-/g; $t }
    sub headings {
      my $f = shift; return $slugs{$f} if $slugs{$f};
      my %h; my $fence = 0;
      open my $fh, "<:utf8", $f or return {}; local $/ = "\n";
      while (<$fh>) {
        $fence = !$fence if /^```/;
        next if $fence;
        if (/^(#{1,6}) /) { chomp; my $s = slug($_); $h{$s}++; $dups{$f}{$s} = 1 if /^#{2,3} / && $h{$s} > 1 }
      }
      return $slugs{$f} = \%h;
    }
    for my $f (split /\0/, do { local $/; <STDIN> }) {
      next unless -f $f;
      headings($f);
      open my $fh, "<:utf8", $f or next;
      my ($fence, $n) = (0, 0); local $/ = "\n";
      while (<$fh>) {
        $n++;
        $fence = !$fence if /^```/;
        next if $fence;
        s/`[^`]*`//g;
        while (/\]\(([^)\s]+)\)/g) {
          my $t = $1;
          next if $t =~ m{^(https?:|mailto:)};
          my ($path, $anchor) = split /#/, $t, 2;
          my $target = $path eq "" ? $f : File::Spec->catfile(dirname($f), $path);
          $target =~ s{^\./}{};
          unless (-e $target) { print STDERR "error: $f:$n: link to a missing file: $t\n"; $bad++; next }
          if (defined $anchor && $anchor ne "" && $target =~ /\.md$/) {
            unless (headings($target)->{$anchor}) { print STDERR "error: $f:$n: link \"$t\" matches no heading\n"; $bad++ }
          }
        }
      }
    }
    for my $f (sort keys %dups) { for my $s (sort keys %{$dups{$f}}) { print STDERR "error: $f: several headings share the anchor \"#$s\"\n"; $bad++ } }
    exit($bad ? 1 : 0);
  ' || problems=1
  # every guide is listed in the guide index
  local guide
  for guide in docs/guides/*.md; do
    [ "${guide##*/}" = README.md ] && continue
    grep -qF "(${guide##*/})" docs/guides/README.md || {
      printf 'error: %s is not listed in docs/guides/README.md\n' "$guide" >&2
      problems=1
    }
  done
  return $problems
}

lint_no_section_signs() {
  local problems=0 hit
  while IFS= read -r hit; do
    printf 'error: %s\n       use a link ("guide.md") instead of a bare "§" reference\n' "$hit" >&2
    problems=$((problems + 1))
  done < <(git grep -n '§' -- '*.md' || true)
  return $((problems > 0))
}

cmd_lint() {
  local problems=0
  lint_adr_titles || problems=$((problems + 1))
  lint_cross_references || problems=$((problems + 1))
  lint_doc_links || problems=$((problems + 1))
  lint_no_section_signs || problems=$((problems + 1))
  check_index || problems=$((problems + 1))
  if [ "$problems" -gt 0 ]; then
    printf '\n%d problem group(s); see above.\n' "$problems" >&2
    return 1
  fi
  printf 'adr lint: OK\n'
}

cmd_renumber() {
  local old=${1:-} new=${2:-}
  if [ -z "$old" ] || [ -z "$new" ]; then
    die 'usage: scripts/adr.sh renumber OLD NEW'
  fi
  if ! [[ $old =~ ^[0-9]{4}$ && $new =~ ^[0-9]{4}$ ]]; then
    die 'OLD and NEW must be four digits'
  fi
  local src
  src=$(find "$adr_dir" -maxdepth 1 -name "$old-*.md" ! -name '0000-*' -print -quit)
  [ -n "$src" ] || die "no ADR $old in $adr_dir"
  local dst=$adr_dir/$new-${src#"$adr_dir/$old-"}
  [ -e "$dst" ] && die "$dst already exists"
  git mv "$src" "$dst"
  perl -CSD -i -pe "s/^# $old \x{2014} /# $new \x{2014} /" "$dst"
  # File links and "ADR NNNN" mentions in every tracked document/source file.
  git ls-files -z -- '*.md' '*.rs' | xargs -0 perl -CSD -i -pe \
    "s{decisions/$old-}{decisions/$new-}g; s/\\bADR $old\\b/ADR $new/g"
  write_index
  printf 'renumbered %s -> %s; review with: git diff --stat && git diff\n' "$old" "$new"
}

case "${1:-}" in
  index)
    if [ "${2:-}" = "--check" ]; then check_index; else write_index; fi
    ;;
  lint) cmd_lint ;;
  renumber) shift; cmd_renumber "$@" ;;
  *)
    printf 'usage: scripts/adr.sh index [--check] | lint | renumber OLD NEW\n' >&2
    exit 64
    ;;
esac
