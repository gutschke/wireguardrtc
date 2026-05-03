#!/usr/bin/env python3
import sys
import markdown
from weasyprint import HTML, CSS

def generate_pdf(html_str, font_size_pt, margin_in):
    """Renders the HTML to PDF with specific typographic settings."""
    css = f"""
    @page {{
        size: letter;
        margin: {margin_in}in;
    }}
    body {{
        font-family: system-ui, -apple-system, sans-serif;
        font-size: {font_size_pt}pt;
        line-height: 1.45;
        color: #111;
    }}
    h1, h2, h3, h4 {{
        break-after: avoid;
        break-inside: avoid;
        margin-top: 1.2em;
        margin-bottom: 0.5em;
    }}
    pre, code {{
        font-family: monospace;
        font-size: {font_size_pt * 0.88}pt;
        background: #f4f4f4;
        padding: 6px;
        border-radius: 4px;
        white-space: pre-wrap;
        word-break: break-all;
    }}
    pre {{ border-left: 3px solid #666; break-inside: avoid; }}
    .two-column {{
        column-count: 2;
        column-gap: 0.4in;
    }}
    """
    return HTML(string=html_str).render(stylesheets=[CSS(string=css)])

def build():
    sys.stderr.write("[INFO] Reading wg-holepunch-guide.md...\n")
    try:
        with open('wg-holepunch-guide.md', 'r') as f:
            md_text = f.read()
    except FileNotFoundError:
        sys.stderr.write("[ERROR] Markdown file not found.\n")
        sys.exit(1)

    html_content = markdown.markdown(md_text, extensions=['fenced_code', 'codehilite'])
    
    # Save standalone HTML
    full_html = f"""<!DOCTYPE html><html>
    <head><style>body{{font-family: sans-serif; max-width: 900px; margin: 2em auto; line-height: 1.6;}}</style></head>
    <body>{html_content}</body></html>"""
    with open('wg-holepunch-guide.html', 'w') as f:
        f.write(full_html)
    sys.stderr.write("[INFO] wg-holepunch-guide.html generated successfully.\n")

    sys.stderr.write("[INFO] Optimizing PDF layout iteratively for Print (US Letter, 2-Column)...\n")
    
    # Base configuration for two-column letter format
    pdf_html = f"""<!DOCTYPE html><html><body class="two-column">{html_content}</body></html>"""
    
    best_doc = None
    best_pages = float('inf')
    
    # Try iterations from 10.5pt down to 9.0pt to find the tightest, cleanest fit
    for pt in [10.5, 10.0, 9.5, 9.0]:
        sys.stderr.write(f"[DEBUG] Attempting layout with {pt}pt font...\n")
        doc = generate_pdf(pdf_html, pt, 0.6)
        pages = len(doc.pages)
        
        if best_doc is None:
            best_doc = doc
            best_pages = pages
        elif pages < best_pages:
            sys.stderr.write(f"[DEBUG] Font size {pt}pt successfully reduced document to {pages} pages.\n")
            best_doc = doc
            best_pages = pages
            
    # Final diagnostic output regarding filled pages
    sys.stderr.write(f"[INFO] Optimal layout selected: spans {best_pages} page(s).\n")
    
    try:
        best_doc.write_pdf('wg-holepunch-guide.pdf')
        sys.stderr.write("[SUCCESS] wg-holepunch-guide.pdf generated successfully.\n")
    except Exception as e:
        sys.stderr.write(f"[ERROR] PDF generation failed: {e}\n")

if __name__ == "__main__":
    build()
