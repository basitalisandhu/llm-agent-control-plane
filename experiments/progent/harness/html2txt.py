import sys, re, html
from html.parser import HTMLParser

class P(HTMLParser):
    """HTML -> text; each table row is emitted on ONE line with ' | ' between cells."""
    def __init__(self):
        super().__init__()
        self.out = []
        self.skip = 0
        self.table = 0
    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "annotation", "annotation-xml"):
            self.skip += 1
        if tag == "table":
            self.table += 1
            self.out.append("\n[TABLE]\n")
        if self.table:
            if tag == "tr":
                self.out.append("\n")
            if tag in ("td", "th"):
                self.out.append(" | ")
            return
        if tag in ("p", "div", "br", "li", "h1", "h2", "h3", "h4", "h5", "figcaption", "caption", "section"):
            self.out.append("\n")
    def handle_endtag(self, tag):
        if tag in ("script", "style", "annotation", "annotation-xml"):
            self.skip = max(0, self.skip - 1)
        if tag == "table":
            self.table = max(0, self.table - 1)
            self.out.append("\n[/TABLE]\n")
    def handle_data(self, data):
        if not self.skip:
            if self.table:
                data = data.replace("\n", " ")
            self.out.append(data)

raw = sys.stdin.read()
p = P()
p.feed(raw)
txt = "".join(p.out)
txt = html.unescape(txt)
txt = re.sub(r"[ \t\r\f\v]+", " ", txt)
txt = re.sub(r"\n\s*\n+", "\n", txt)
sys.stdout.write(txt)
