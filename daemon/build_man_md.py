#!/usr/bin/env python3
# build_man_md.py — render groff/troff man pages into GitHub-flavored
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
                if s[i:i+4] == "\\(+-":
                    out.append("+/-"); i += 4; continue
                if s[i:i+4] == "\\(co":
                    out.append("(c)"); i += 4; continue
                if s[i:i+4] == "\\(rg":
                    out.append("(R)"); i += 4; continue
                if s[i:i+4] == "\\(de":
                    out.append("deg"); i += 4; continue
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
                if s[i:i+4] == "\\(+-":
                    out.append("±")
                    i += 4
                    continue
                if s[i:i+4] == "\\(co":
                    out.append("©")
                    i += 4
                    continue
                if s[i:i+4] == "\\(rg":
                    out.append("®")
                    i += 4
                    continue
                if s[i:i+4] == "\\(de":
                    out.append("°")
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


def _render_tbl(buf):
    """Render a tbl(1) table body (the lines between .TS and .TE) into
    a GitHub-flavored Markdown table.  The subset of tbl(1) we handle
    matches what wireguardrtc(8) uses: a single format-spec line
    (`l l lx.`), an optional `_` divider acting as a header separator,
    and rows whose cells are tab-separated.  A trailing column whose
    content opens with `T{` and closes with `T}` on a later line gets
    its body lines joined with a single space."""
    # Step 1: locate the format spec.  It's the first non-empty line
    # whose stripped text ends with `.`.  Everything before it is
    # global-options (tab(;), allbox, …) which we ignore for now.
    spec = None
    body_start = 0
    for idx, line in enumerate(buf):
        s = line.strip()
        if not s:
            continue
        if s.endswith("."):
            spec = s[:-1].strip()
            body_start = idx + 1
            break
    cols = max(1, len(spec.split())) if spec else 1

    # Step 2: walk the body, collecting rows.  A row is a list of
    # cell strings; the special row `["_"]` marks a horizontal
    # divider (typically the header separator).
    rows = []
    multi = None  # accumulator for a T{ … T} multi-line cell
    cur = []     # cells of the current row being built
    for line in buf[body_start:]:
        if multi is not None:
            if line.strip() == "T}":
                cur.append(" ".join(multi).strip())
                multi = None
                rows.append(cur)
                cur = []
            else:
                multi.append(_inline(line.strip()))
            continue
        s = line.rstrip()
        if not s.strip():
            continue
        if s.strip() == "_":
            # Horizontal divider — header separator.
            rows.append(["_"])
            continue
        cells = s.split("\t")
        if cells and cells[-1].strip() == "T{":
            for c in cells[:-1]:
                cur.append(_inline(c.strip()))
            multi = []
            continue
        for c in cells:
            cur.append(_inline(c.strip()))
        rows.append(cur)
        cur = []
    if cur:
        rows.append(cur)

    # Step 3: locate the header.  If we saw a `_` divider, the row
    # immediately before it is the header; otherwise the first row.
    header = None
    body = []
    sep_idx = next((i for i, r in enumerate(rows) if r == ["_"]), None)
    if sep_idx is not None and sep_idx > 0:
        header = rows[sep_idx - 1]
        body = [r for r in rows[sep_idx + 1:] if r != ["_"]]
    elif rows:
        header = rows[0]
        body = [r for r in rows[1:] if r != ["_"]]
    else:
        header = [""] * cols

    def _pad(row):
        row = [c.replace("|", "\\|") for c in row]
        return (row + [""] * cols)[:cols]

    out = []
    out.append("| " + " | ".join(_pad(header)) + " |")
    out.append("|" + "|".join(["---"] * cols) + "|")
    for r in body:
        out.append("| " + " | ".join(_pad(r)) + " |")
    return out


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
    # from plain text) becomes the TP tag (or the IP bullet content)
    # instead of paragraph content.  After the capture flushes, body
    # paragraphs are indented under the bullet.
    tp_capture = None  # None or a list to accumulate the tag
    # If set, the captured content is emitted on the SAME line as
    # this prefix (used for .IP bullets where the prefix is `- ` and
    # the content has to share the line so deeper nesting doesn't
    # cross the 4-space code-block threshold).  When None, the
    # default `- **tag**` form is used.
    tp_capture_bullet_prefix = None

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

    def emit_tp_tag(tag_md, bullet_prefix=None):
        """Emit a bullet line and push a body indent so the next
        paragraphs fall under it.  When `bullet_prefix` is None
        (default), use `<current_indent>- {tag_md}` — the .TP case.
        When set, use the explicit prefix and inline the tag content
        on the same line — the .IP-with-tag case."""
        out.append("")
        if bullet_prefix is None:
            out.append(f"{indent_stack[-1]}- {tag_md}")
        else:
            out.append(f"{bullet_prefix}{tag_md}")
        indent_stack.append(indent_stack[-1] + "  ")

    def maybe_emit_tp():
        """Called after every line that might contribute to a TP tag.
        If we now have at least one piece of tag content, emit the
        tag and transition to body mode (push indent)."""
        nonlocal tp_capture, tp_capture_bullet_prefix
        if tp_capture is not None and tp_capture:
            tag_md = "".join(tp_capture).strip() or "*(no tag)*"
            prefix = tp_capture_bullet_prefix
            tp_capture = None
            tp_capture_bullet_prefix = None
            emit_tp_tag(tag_md, bullet_prefix=prefix)
            block_kinds.append("tp")

    def close_tp_if_open():
        """If we're currently inside a TP body (indented), pop the
        indent.  Called on .SH, .SS, .PP and friends."""
        # We mark TP-body depth by anything pushed beyond the initial
        # "" entry due to a TP (RS/RE push their own, marked
        # separately).  Simpler: pop one level if depth > 1 AND the
        # immediately preceding line was a TP body.  Cleanest: maintain
        # an explicit flag.
        pass

    # Indent prefix for the current block.  Indent_stack[0] = "" is
    # the section margin.  Each .TP / .IP-with-tag pushes a deeper
    # prefix; .RS pushes a marker without changing the indent (it
    # acts as a barrier so .IP's pop-walk stops there).
    indent_stack = [""]
    # Parallel to indent_stack but one shorter (no entry for the
    # bottom "" element).  Each entry tags how its corresponding
    # indent_stack level got pushed:
    #   "tp" — by .TP or .IP-with-tag (poppable by .PP / next .TP/.IP
    #          / .SH / .SS / .RE-of-containing-RS)
    #   "rs" — by .RS (poppable only by the matching .RE; acts as a
    #          floor for pop_tp_levels so an .IP inside .RS doesn't
    #          tear down the surrounding .TP body).
    # When the kind is "rs", the corresponding indent_stack entry is
    # the SAME prefix as the previous level (no indent change).
    block_kinds = []
    # Are we inside a synopsis block (.SY/.YS)?
    in_synopsis = False
    synopsis_buf = []
    # Are we inside an example/preformatted block (.EX/.EE or .nf/.fi)?
    in_pre = False
    # Are we inside a tbl(1) table (.TS/.TE)?  All lines between go
    # to tbl_buf and get parsed in one shot when .TE arrives.
    in_tbl = False
    tbl_buf = []

    def pop_tp_levels():
        """Pop TP/IP indent levels back down to the nearest .RS
        barrier (or the section margin if no .RS is active).  Called
        on .PP / .SH / .SS / next .TP / next .IP-with-tag — anything
        that says "we're done with the current bullet's body"."""
        while block_kinds and block_kinds[-1] == "tp":
            indent_stack.pop()
            block_kinds.pop()

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
        # Inside a tbl(1) table everything goes verbatim into the
        # buffer except the closing .TE, which falls through to the
        # macro dispatcher below.
        if in_tbl and not raw.startswith(".TE"):
            tbl_buf.append(raw)
            continue
        # Empty lines preserve paragraph breaks.
        if raw == "":
            flush_para()
            if tp_capture is not None and tp_capture:
                # End of TP tag collection — emit and start the body.
                tag_md = "".join(tp_capture).strip() or "*(no tag)*"
                tp_capture = None
                emit_tp_tag(tag_md)
                block_kinds.append("tp")
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
            block_kinds[:] = []
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
            block_kinds[:] = []
            continue

        if macro in ("PP", "LP", "P"):
            flush_para()
            pop_tp_levels()
            out.append("")
            continue

        if macro == "br":
            flush_para()
            continue

        if macro == "sp":
            # Vertical space — render as a paragraph break.  The
            # optional numeric arg (number of blank lines) is ignored;
            # Markdown collapses runs of blanks anyway.
            flush_para()
            out.append("")
            continue

        if macro in ("ne", "in", "ti", "ad", "na", "hy", "nh", "ll",
                     "pl", "vs", "ps", "ft"):
            # Layout directives without a Markdown analogue — drop
            # silently rather than leak as an HTML comment.
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
            # tag of the same bullet.  Simplest correct behavior:
            # emit the previous tag, then start a fresh sibling
            # bullet for this one.
            flush_para()
            pop_tp_levels()
            tp_capture = []
            continue

        if macro == "IP":
            # .IP [TAG] [INDENT-WIDTH] semantics:
            #   - With a bullet tag (\\(bu): start a new bullet.  The
            #     CONTENT (next non-macro line, or the next inline-
            #     emphasis macro's output) gets put on the SAME line
            #     as `- ` — putting it on a separate indented line
            #     would let Markdown's 4-space-indent rule treat the
            #     content as a code block, especially at deeper nest
            #     levels (e.g. inside a .TP body inside an .RS).
            #   - With a label tag: bold the label on the bullet line,
            #     content follows the same rule.
            #   - With no tag: just a paragraph break at the current
            #     indent (idiomatic troff way to start a new para
            #     inside a TP body or RS block).
            args = _split_args(rest)
            tag = args[0] if args else ""
            if not tag:
                # Naked .IP — paragraph break WITHIN the current
                # body (TP body, RS block, …).  Do NOT pop tp levels:
                # the source uses this idiom specifically to start
                # another paragraph under the same bullet.
                flush_para()
                out.append("")
                continue
            # Bullet-with-tag: this DOES end the previous IP's body
            # (a new bullet at the same level), so pop those.
            flush_para()
            pop_tp_levels()
            if tag in ("\\(bu", "•", "*", "o"):
                ip_bullet_prefix = f"{indent_stack[-1]}- "
            else:
                ip_bullet_prefix = (
                    f"{indent_stack[-1]}- **{_inline(tag)}** ")
            # Capture the next text/macro line as the bullet content,
            # to be emitted on the SAME line as the prefix.
            tp_capture = []
            tp_capture_bullet_prefix = ip_bullet_prefix
            continue

        if macro == "RS":
            # Push an "rs" barrier onto block_kinds.  The indent
            # itself doesn't change (re-use the current prefix) —
            # Markdown's nested list takes care of visual nesting
            # via the bullet hierarchy and adding an extra `  `
            # here would push bullets past the 4-space code-block
            # threshold.  The barrier exists so that an .IP inside
            # this .RS doesn't tear down the surrounding .TP body
            # via pop_tp_levels().
            flush_para()
            indent_stack.append(indent_stack[-1])
            block_kinds.append("rs")
            continue
        if macro == "RE":
            # Pop everything down to and including the topmost "rs".
            flush_para()
            while block_kinds and block_kinds[-1] != "rs":
                indent_stack.pop()
                block_kinds.pop()
            if block_kinds and block_kinds[-1] == "rs":
                indent_stack.pop()
                block_kinds.pop()
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

        if macro == "TS":
            # Start of a troff tbl(1) table.  Collect every following
            # line up to .TE, then parse into a Markdown table.  The
            # subset of tbl we handle covers what wireguardrtc.8 uses:
            # a single format-spec line (`l l lx.`), an optional `_`
            # divider acting as the header separator, and rows whose
            # cells are tab-separated.  Multi-line cell bodies wrapped
            # in `T{` … `T}` get joined with `<br>`.
            flush_para()
            in_tbl = True
            tbl_buf = []
            continue
        if macro == "TE":
            if in_tbl:
                out.append("")
                out.extend(_render_tbl(tbl_buf))
                out.append("")
                in_tbl = False
                tbl_buf = []
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
