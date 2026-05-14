#!/usr/bin/env python3
# build_man_md.py — render groff/troff man pages into GitHub-flavoured
# Markdown so the same content can be browsed both with `man wireguardrtc`
# and from the GitHub UI.
#
# Why a custom converter: pandoc/mandoc aren't always installed on the
# build host, and adding a pypi dep just for doc generation is heavier
# than the macros we actually use.  The daemon's man page sticks to a
# small subset (TH, SH/SS, TP, IP, PP, B/I/BR/IR/EX/EE, RS/RE,
# SY/YS/OP) and a few inline escapes; this script covers exactly that
# set.  Unknown directives are echoed as comments so the diff makes
# the omission obvious.
#
# Usage:
#   python3 build_man_md.py <input.[1-8]> <output.md>
#   python3 build_man_md.py --all          # regenerate every shipped page

import argparse
import os
import re
import sys
from pathlib import Path

INLINE_RX = re.compile(r"\\f[BIRP]|\\\(bu|\\-|\\&|\\\\")


def _strip_quotes(s):
    """A troff macro argument can be a quoted string or a bare token.
    `.B "two words"` keeps the two words bold."""
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def _split_args(line):
    """Split a macro argument line on whitespace, respecting "quoted"
    runs.  Mirrors what troff itself does."""
    out, cur, in_q = [], [], False
    for ch in line:
        if ch == '"':
            in_q = not in_q
            continue
        if ch.isspace() and not in_q:
            if cur:
                out.append("".join(cur))
                cur = []
            continue
        cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def _inline_escapes_only(s):
    """Translate character escapes only — `\\-` → `-`, `\\&` → empty,
    `\\(em` → `—`, etc.  Drops font-change sequences (`\\fB`, `\\fI`,
    `\\fR`, `\\fP`) entirely rather than emitting HTML tags, since
    this helper is used for preformatted blocks where HTML doesn't
    render."""
    if not s:
        return s
    out = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            c = s[i + 1]
            if c == "f" and i + 2 < n:
                # font change — drop the 3-char sequence
                i += 3
                continue
            if c == "(":
                if s[i:i+4] == "\\(bu":
                    out.append("*"); i += 4; continue
                if s[i:i+4] == "\\(em":
                    out.append("--"); i += 4; continue
                if s[i:i+4] == "\\(en":
                    out.append("-"); i += 4; continue
                # unknown special — drop the 4-char sequence
                i += 4
                continue
            if c == "-":
                out.append("-"); i += 2; continue
            if c == "&":
                i += 2; continue
            if c == "\\":
                out.append("\\"); i += 2; continue
            # unknown backslash — keep next char, drop backslash
            out.append(c); i += 2; continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _inline(s):
    """Translate inline troff escapes into Markdown.  Bold/italic
    runs (\\fB ... \\fR) are converted to **bold** / *italic*.
    The result is conservative: when in doubt we drop the escape
    rather than emit broken Markdown."""
    if not s:
        return s
    out = []
    i = 0
    cur_font = "R"  # roman (plain)
    open_marker = ""
    n = len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            c = s[i + 1]
            if c == "f" and i + 2 < n:
                new_font = s[i + 2]
                if new_font == "P":
                    # restore previous; treat as roman for simplicity
                    new_font = "R"
                # close previous run
                if open_marker:
                    out.append(open_marker)
                    open_marker = ""
                # open new
                if new_font == "B":
                    out.append("**"); open_marker = "**"
                elif new_font == "I":
                    out.append("*"); open_marker = "*"
                elif new_font == "BI":
                    out.append("***"); open_marker = "***"
                cur_font = new_font
                i += 3
                continue
            if c == "(":
                # special character: \(bu, \(em, etc.  We only care
                # about a handful that show up in real man pages.
                if s[i:i+4] == "\\(bu":
                    out.append("•")
                    i += 4
                    continue
                if s[i:i+4] == "\\(em":
                    out.append("—")
                    i += 4
                    continue
                if s[i:i+4] == "\\(en":
                    out.append("–")
                    i += 4
                    continue
                # unknown special — drop the 4-char sequence so
                # output is at least readable.
                i += 4
                continue
            if c == "-":
                out.append("-")
                i += 2
                continue
            if c == "&":
                # zero-width separator — drop.
                i += 2
                continue
            if c == "\\":
                out.append("\\")
                i += 2
                continue
            # unknown backslash escape — drop the backslash, keep the
            # next char.
            out.append(c)
            i += 2
            continue
        out.append(s[i])
        i += 1
    if open_marker:
        out.append(open_marker)
    return "".join(out)


def _alt_font(args, fonts):
    """Helper for .BR/.IR/.RB/.RI/.BI/.IB style alternation: each
    argument toggles between two fonts.  `fonts` is the pair, e.g.
    ('B', 'R') for .BR — first arg bold, second roman, third bold, …

    Uses HTML tags (<b>, <i>) rather than Markdown asterisks because
    troff alternation routinely produces adjacent emphasis runs
    (.BI --foo VAL → bold "--foo" abutting italic "VAL"), and
    Markdown rules around `**foo***bar*` are ambiguous and
    renderer-dependent.  HTML tags parse unambiguously in every
    Markdown engine that accepts inline HTML — and GitHub does."""
    out = []
    for i, a in enumerate(args):
        a = _inline(a)
        f = fonts[i % 2]
        if f == "B":
            out.append(f"<b>{a}</b>")
        elif f == "I":
            out.append(f"<i>{a}</i>")
        else:
            out.append(a)
    return "".join(out)


def convert(text, source_name="man"):
    """Render the troff source `text` into Markdown.  `source_name` is
    used in the synthetic header comment so the reader can trace the
    .md back to its source."""
    lines = text.splitlines()
    out = []
    out.append(f"<!-- generated from {source_name} by build_man_md.py "
                "— do not edit by hand -->")
    # Accumulator for normal paragraph text; flushed on macro boundaries.
    para = []
    # When set, the next chunk of output (whether from a macro or
    # from plain text) becomes the TP tag instead of paragraph
    # content.  The next paragraph after the tag is the body, indented
    # under the tag bullet.
    tp_capture = None  # None or a list to accumulate the tag

    def flush_para():
        nonlocal tp_capture
        if not para:
            return
        text_out = _inline(" ".join(para).strip())
        if tp_capture is not None:
            # We're collecting the TP tag.
            tp_capture.append(text_out)
            para.clear()
            return
        # Normal paragraph; indent according to depth.
        prefix = indent_stack[-1]
        if prefix:
            # Continuation lines under a bullet take the same indent.
            text_out = prefix + text_out
        out.append(text_out)
        para.clear()

    def emit_tp_tag(tag_md):
        """Emit `- **tag**` at the current indent, then push a deeper
        indent so the body lines fall under the bullet."""
        out.append("")
        out.append(f"{indent_stack[-1]}- {tag_md}")
        indent_stack.append(indent_stack[-1] + "  ")

    def maybe_emit_tp():
        """Called after every line that might contribute to a TP tag.
        If we now have at least one piece of tag content, emit the
        tag and transition to body mode (push indent)."""
        nonlocal tp_capture
        if tp_capture is not None and tp_capture:
            tag_md = "".join(tp_capture).strip() or "*(no tag)*"
            tp_capture = None
            emit_tp_tag(tag_md)
            tp_depth_marks.append(True)

    def close_tp_if_open():
        """If we're currently inside a TP body (indented), pop the
        indent.  Called on .SH, .SS, .PP and friends."""
        # We mark TP-body depth by anything pushed beyond the initial
        # "" entry due to a TP (RS/RE push their own, marked
        # separately).  Simpler: pop one level if depth > 1 AND the
        # immediately preceding line was a TP body.  Cleanest: maintain
        # an explicit flag.
        pass

    # State stack for indent (RS/RE) AND TP body.  Each entry is an
    # indent prefix.
    indent_stack = [""]
    # Track which entries on the indent stack came from a TP body
    # (so .PP / .SH can pop them).  A simple parallel-list flag.
    tp_depth_marks = []
    # Are we inside a synopsis block (.SY/.YS)?
    in_synopsis = False
    synopsis_buf = []
    # Are we inside an example/preformatted block (.EX/.EE or .nf/.fi)?
    in_pre = False

    def pop_tp_levels():
        """Pop every TP-introduced indent level on top of the stack."""
        while indent_stack and tp_depth_marks and tp_depth_marks[-1]:
            indent_stack.pop()
            tp_depth_marks.pop()

    title_set = False

    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        # Comments .\" — drop.
        if raw.startswith(".\\\""):
            continue
        if raw.startswith("'\\\""):
            continue
        # Empty lines preserve paragraph breaks.
        if raw == "":
            flush_para()
            if tp_capture is not None and tp_capture:
                # End of TP tag collection — emit and start the body.
                tag_md = "".join(tp_capture).strip() or "*(no tag)*"
                tp_capture = None
                emit_tp_tag(tag_md)
                tp_depth_marks.append(True)
            if not in_pre:
                out.append("")
            else:
                out.append("")
            continue
        # Non-macro line.
        if not raw.startswith(".") and not raw.startswith("'"):
            if in_pre:
                # Code-block content still needs troff character
                # escapes processed (\-, \&, \(em, …) so users don't
                # see literal backslashes in the rendered fence.  We
                # use the "escapes only" helper because HTML emphasis
                # tags wouldn't render inside ``` anyway.
                out.append(_inline_escapes_only(raw))
            elif tp_capture is not None:
                # The .TP's tag line is plain text — capture it and
                # immediately emit (a tag is one source line).
                tp_capture.append(_inline(raw.strip()))
                maybe_emit_tp()
            else:
                para.append(raw.strip())
            continue
        # Strip the leading "." or "'".
        macro_line = raw[1:].strip()
        if not macro_line:
            continue
        # Split macro name + args.
        parts = macro_line.split(None, 1)
        macro = parts[0]
        rest = parts[1] if len(parts) > 1 else ""

        if macro == "TH" and not title_set:
            # .TH NAME SECTION [DATE] [SOURCE] [MANUAL]
            args = _split_args(rest)
            name = args[0] if args else ""
            section = args[1] if len(args) > 1 else ""
            manual = args[4] if len(args) > 4 else ""
            title = f"{name}({section})"
            if manual:
                title += f" — {manual}"
            out.append(f"# {title}")
            out.append("")
            title_set = True
            continue

        if macro in ("SH",):
            flush_para()
            pop_tp_levels()
            args = _split_args(rest)
            heading = " ".join(_inline(a) for a in args) if args else ""
            out.append("")
            out.append(f"## {heading}")
            out.append("")
            indent_stack[:] = [""]
            tp_depth_marks[:] = []
            continue

        if macro == "SS":
            flush_para()
            pop_tp_levels()
            args = _split_args(rest)
            heading = " ".join(_inline(a) for a in args) if args else ""
            out.append("")
            out.append(f"### {heading}")
            out.append("")
            indent_stack[:] = [""]
            tp_depth_marks[:] = []
            continue

        if macro in ("PP", "LP", "P"):
            flush_para()
            pop_tp_levels()
            out.append("")
            continue

        if macro == "br":
            flush_para()
            continue

        if macro == "TP":
            # .TP [INDENT-WIDTH] — the next line (macro or text)
            # becomes the tag.  If we're already inside a TP body,
            # close it first so each TP is at the same outer indent.
            flush_para()
            pop_tp_levels()
            tp_capture = []
            continue

        if macro == "TQ":
            # Continuation tag for the previous .TP — append to the
            # tag of the same bullet.  Simplest correct behaviour:
            # emit the previous tag, then start a fresh sibling
            # bullet for this one.
            flush_para()
            pop_tp_levels()
            tp_capture = []
            continue

        if macro == "IP":
            # .IP [TAG] [INDENT-WIDTH] — works like a flat .TP whose
            # tag is on the same line.  Push the body indent so the
            # paragraph text following lands inside the bullet
            # instead of resetting to the section margin.
            flush_para()
            pop_tp_levels()
            args = _split_args(rest)
            tag = args[0] if args else ""
            if tag in ("\\(bu", "•", "*", "o"):
                bullet_line = f"{indent_stack[-1]}- "
            elif tag:
                bullet_line = f"{indent_stack[-1]}- **{_inline(tag)}**"
            else:
                # No tag — emit an anonymous list item header so the
                # body still indents.
                bullet_line = f"{indent_stack[-1]}- "
            out.append(bullet_line)
            indent_stack.append(indent_stack[-1] + "  ")
            tp_depth_marks.append(True)
            continue

        if macro == "RS":
            indent_stack.append(indent_stack[-1] + "  ")
            tp_depth_marks.append(False)
            continue
        if macro == "RE":
            if len(indent_stack) > 1:
                indent_stack.pop()
                if tp_depth_marks:
                    tp_depth_marks.pop()
            continue

        if macro == "EX":
            flush_para()
            out.append("")
            out.append("```")
            in_pre = True
            continue
        if macro == "EE":
            out.append("```")
            out.append("")
            in_pre = False
            continue
        if macro == "nf":
            flush_para()
            out.append("")
            out.append("```")
            in_pre = True
            continue
        if macro == "fi":
            if in_pre:
                out.append("```")
                out.append("")
                in_pre = False
            continue

        if macro == "SY":
            # Synopsis opener.  Buffer the command line into
            # `synopsis_buf` until .YS so all the in-line .B / .OP
            # macros that follow contribute to the same logical
            # synopsis paragraph instead of escaping into the
            # surrounding flow.
            flush_para()
            in_synopsis = True
            synopsis_buf[:] = [f"<b>{_inline(rest.strip())}</b>"]
            continue
        if macro == "YS":
            if synopsis_buf:
                out.append("")
                out.append(" ".join(synopsis_buf))
                out.append("")
            in_synopsis = False
            synopsis_buf[:] = []
            continue
        if macro == "OP":
            # Synopsis option marker → [arg arg …]
            args = _split_args(rest)
            arg_text = " ".join(_inline(a) for a in args)
            piece = f"\\[{arg_text}\\]"
            if in_synopsis:
                synopsis_buf.append(piece)
            else:
                out.append(piece)
            continue

        # Inline-emphasis macros — produce a fragment that goes to
        # the active sink: synopsis buffer > TP-tag accumulator >
        # current paragraph.
        def _append_inline(fragment):
            if in_synopsis:
                synopsis_buf.append(fragment)
            elif tp_capture is not None:
                tp_capture.append(fragment)
            else:
                para.append(fragment)

        if macro == "B":
            text = _inline(_strip_quotes(rest))
            _append_inline(f"<b>{text}</b>" if text else "")
            maybe_emit_tp()
            continue
        if macro == "I":
            text = _inline(_strip_quotes(rest))
            _append_inline(f"<i>{text}</i>" if text else "")
            maybe_emit_tp()
            continue
        if macro in ("BR", "IB"):
            args = _split_args(rest)
            _append_inline(_alt_font(args, ("B", "R")))
            maybe_emit_tp()
            continue
        if macro in ("RB",):
            args = _split_args(rest)
            _append_inline(_alt_font(args, ("R", "B")))
            maybe_emit_tp()
            continue
        if macro in ("IR",):
            args = _split_args(rest)
            _append_inline(_alt_font(args, ("I", "R")))
            maybe_emit_tp()
            continue
        if macro in ("RI",):
            args = _split_args(rest)
            _append_inline(_alt_font(args, ("R", "I")))
            maybe_emit_tp()
            continue
        if macro in ("BI",):
            args = _split_args(rest)
            _append_inline(_alt_font(args, ("B", "I")))
            maybe_emit_tp()
            continue

        if macro in ("TS", "TE"):
            # Tables — emit as a preformatted block; rendering as MD
            # tables would need full layout parsing.
            if macro == "TS":
                flush_para()
                out.append("")
                out.append("```")
                in_pre = True
            else:
                out.append("```")
                out.append("")
                in_pre = False
            continue

        # Unknown macro — preserve as HTML comment so the omission is
        # visible in the rendered output.
        out.append(f"<!-- TROFF {macro} {rest} -->")

    flush_para()
    # Collapse runs of >2 blank lines.
    result = []
    blanks = 0
    for line in out:
        if line == "":
            blanks += 1
            if blanks <= 1:
                result.append(line)
        else:
            blanks = 0
            result.append(line)
    return "\n".join(result).rstrip() + "\n"


def _convert_file(src, dst):
    text = Path(src).read_text(encoding="utf-8")
    md = convert(text, source_name=os.path.basename(src))
    Path(dst).write_text(md, encoding="utf-8")
    sys.stderr.write(f"[INFO] {src} -> {dst} "
                      f"({len(md)} bytes)\n")


# Pairs of (man-source, generated-md) that ship in the github tree.
# Add more entries here as new man pages land.
DEFAULT_PAIRS = [
    ("daemon/wireguardrtc.8", "docs/wireguardrtc.8.md"),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", nargs="?", help="man-page source")
    ap.add_argument("output", nargs="?", help="markdown destination")
    ap.add_argument("--all", action="store_true",
                    help="regenerate every shipped page from "
                         "DEFAULT_PAIRS")
    args = ap.parse_args()

    if args.all:
        # Assume cwd is the repo root (or daemon/, since the daemon's
        # Debian build runs the script from daemon/).
        here = Path.cwd()
        if (here / "daemon").is_dir():
            root = here
        elif (here.name == "daemon" and (here.parent / "daemon").is_dir()):
            root = here.parent
        elif (here.name == "daemon" and (here.parent / "github").is_dir()):
            root = here.parent
        else:
            # Best effort: treat cwd as the github root.
            root = here
        for src, dst in DEFAULT_PAIRS:
            src_path = root / src
            dst_path = root / dst
            if not src_path.is_file():
                sys.stderr.write(f"[WARN] missing {src_path}\n")
                continue
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            _convert_file(str(src_path), str(dst_path))
        return

    if not args.input or not args.output:
        ap.error("specify <input> <output> or --all")
    _convert_file(args.input, args.output)


if __name__ == "__main__":
    main()
