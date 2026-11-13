"""PDF export of a signed message. The signed data travels inside the PDF
metadata (Keywords) as base64 JSON, so `/verify` can check it without parsing pages."""

import base64
import io
import json
import re
import textwrap
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

FONT_NAME = "DejaVuSans"
FONT_PATH = Path(__file__).with_name("fonts") / "DejaVuSans.ttf"
MARKER = "ib-signed-message:"
MARKER_PATTERN = re.compile(rb"ib-signed-message:([A-Za-z0-9+/=]+)")
LINE_HEIGHT = 12
MARGIN = 50

pdfmetrics.registerFont(TTFont(FONT_NAME, str(FONT_PATH)))


def message_pdf(title: str, lines: list[str], signed_data: dict) -> bytes:
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.setTitle(title)
    embedded = base64.b64encode(json.dumps(signed_data, sort_keys=True).encode())
    pdf.setKeywords(MARKER + embedded.decode())
    y = A4[1] - MARGIN
    pdf.setFont(FONT_NAME, 14)
    pdf.drawString(MARGIN, y, title)
    y -= 2 * LINE_HEIGHT
    pdf.setFont(FONT_NAME, 8)
    for line in lines:
        for chunk in textwrap.wrap(line, 100) or [""]:
            if y < MARGIN:
                pdf.showPage()
                pdf.setFont(FONT_NAME, 8)
                y = A4[1] - MARGIN
            pdf.drawString(MARGIN, y, chunk)
            y -= LINE_HEIGHT
    pdf.save()
    return buffer.getvalue()


def extract_signed_data(pdf_bytes: bytes):
    match = MARKER_PATTERN.search(pdf_bytes)
    if match is None:
        raise ValueError("no signed message data in this file")
    return json.loads(base64.b64decode(match.group(1), validate=True))
