import io
import os
import tempfile

import pygal
from fpdf import FPDF

from tp1.utils.capture import Capture
from tp1.utils.config import logger


#####################################################################################################
# CONSTANTS
#####################################################################################################

PAGE_W = 210  # A4 width  (mm)
MARGIN = 15
CONTENT_W = PAGE_W - 2 * MARGIN


#####################################################################################################
# CLASS
#####################################################################################################


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Network Capture Analysis Report"
        self.summary = summary
        self.array = ""
        self.graph = ""
        self._graph_path = ""  # temp PNG path for the chart

    def concat_report(self) -> str:
        """
        Concat all data in report (used for plain-text fallback).
        """
        content = ""
        content += self.title + "\n"
        content += self.summary
        content += self.array
        content += self.graph
        return content

    def save(self, filename: str) -> None:
        """
        Build and save the PDF report.

        :param filename: output PDF path
        """
        logger.info(f"Generating PDF report: {filename}")
        pdf = self._build_pdf()
        pdf.output(filename)
        logger.info(f"PDF saved: {filename}")

        # Cleanup temp chart file
        if self._graph_path and os.path.exists(self._graph_path):
            os.remove(self._graph_path)

    def generate(self, param: str) -> None:
        """
        Pre-generate content sections.

        :param param: "graph" | "array"
        """
        if param == "graph":
            self.graph = self._gen_graph()
        elif param == "array":
            self.array = self._gen_array()

    # -----------------------------------------------------------------------------------------
    # PRIVATE
    # -----------------------------------------------------------------------------------------

    def _gen_array(self) -> str:
        """
        Build a text representation of the protocol table.

        :return: formatted table string
        """
        protocols = self.capture.sort_network_protocols()
        if not protocols:
            return "No data captured.\n"

        header = f"{'Protocol':<25} {'Packets':>10}\n"
        separator = "-" * 37 + "\n"
        rows = "".join(f"{proto:<25} {count:>10}\n" for proto, count in protocols.items())

        return header + separator + rows

    def _gen_graph(self) -> str:
        """
        Render a bar chart of protocol distribution with pygal, save as PNG,
        and return the file path for PDF embedding.

        :return: path to the generated PNG file
        """
        protocols = self.capture.sort_network_protocols()
        if not protocols:
            return ""

        # Keep top 10 protocols for readability
        top = dict(list(protocols.items())[:10])

        chart = pygal.Bar(
            title="Protocol distribution (top 10)",
            x_label_rotation=35,
            style=pygal.style.CleanStyle,
            width=800,
            height=400,
        )
        chart.x_labels = list(top.keys())
        chart.add("Packets", list(top.values()))

        # pygal renders to SVG natively; convert to PNG via cairosvg if available,
        # otherwise fall back to saving the SVG path and embedding it as text note.
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        tmp.close()

        try:
            import cairosvg

            svg_data = chart.render()
            cairosvg.svg2png(bytestring=svg_data, write_to=tmp.name)
            self._graph_path = tmp.name
        except ImportError:
            # cairosvg unavailable — save SVG instead and skip image embedding
            svg_tmp = tmp.name.replace(".png", ".svg")
            chart.render_to_file(svg_tmp)
            self._graph_path = ""
            logger.warning("cairosvg not found — chart saved as SVG only, not embedded in PDF.")
            return svg_tmp

        return tmp.name

    def _build_pdf(self) -> FPDF:
        """
        Assemble the full PDF document.

        :return: FPDF instance ready to be saved
        """
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=MARGIN)
        pdf.add_page()

        # ---- Title ----
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_fill_color(30, 30, 80)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(CONTENT_W, 14, self.title, new_x="LMARGIN", new_y="NEXT", align="C", fill=True)
        pdf.ln(6)

        # ---- Summary ----
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(CONTENT_W, 8, "Analysis Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Courier", size=9)
        pdf.multi_cell(CONTENT_W, 5, self.summary)
        pdf.ln(4)

        # ---- Protocol table ----
        if self.array:
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(CONTENT_W, 8, "Protocol Statistics", new_x="LMARGIN", new_y="NEXT")
            self._draw_table(pdf)
            pdf.ln(4)

        # ---- Chart ----
        if self._graph_path and os.path.exists(self._graph_path):
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(CONTENT_W, 8, "Protocol Distribution Chart", new_x="LMARGIN", new_y="NEXT")
            pdf.image(self._graph_path, x=MARGIN, w=CONTENT_W)
            pdf.ln(4)

        # ---- Attacks ----
        attacks = self.capture.attacks
        pdf.set_font("Helvetica", "B", 13)
        if attacks:
            pdf.set_text_color(180, 0, 0)
            pdf.cell(CONTENT_W, 8, f"Detected Attacks ({len(attacks)})", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            self._draw_attacks(pdf, attacks)
        else:
            pdf.set_text_color(0, 140, 0)
            pdf.cell(CONTENT_W, 8, "No attacks detected — traffic is clean.", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)

        return pdf

    def _draw_table(self, pdf: FPDF) -> None:
        """
        Draw the protocol statistics table in the PDF.
        """
        protocols = self.capture.sort_network_protocols()
        if not protocols:
            return

        col_proto = CONTENT_W * 0.70
        col_count = CONTENT_W * 0.30

        # Header row
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(220, 220, 240)
        pdf.cell(col_proto, 7, "Protocol", border=1, fill=True)
        pdf.cell(col_count, 7, "Packets", border=1, fill=True, align="R", new_x="LMARGIN", new_y="NEXT")

        # Data rows
        pdf.set_font("Helvetica", size=9)
        fill = False
        for proto, count in protocols.items():
            pdf.set_fill_color(245, 245, 255) if fill else pdf.set_fill_color(255, 255, 255)
            pdf.cell(col_proto, 6, proto, border=1, fill=True)
            pdf.cell(col_count, 6, str(count), border=1, fill=True, align="R", new_x="LMARGIN", new_y="NEXT")
            fill = not fill

    def _draw_attacks(self, pdf: FPDF, attacks: list) -> None:
        """
        Draw detected attacks section in the PDF.
        """
        pdf.set_font("Helvetica", size=10)

        for i, atk in enumerate(attacks, start=1):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_fill_color(255, 230, 230)
            pdf.cell(CONTENT_W, 7, f"[{i}] {atk['type']}", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Helvetica", size=9)
            pdf.set_fill_color(255, 245, 245)
            rows = [
                ("Protocol", atk.get("protocol", "N/A")),
                ("Attacker IP", atk.get("attacker_ip", "N/A")),
                ("Attacker MAC", atk.get("attacker_mac", "N/A")),
                ("Detail", atk.get("detail", "N/A")),
            ]
            for label, value in rows:
                pdf.cell(50, 6, f"  {label}:", border="LR", fill=True)
                pdf.cell(CONTENT_W - 50, 6, value, border="LR", fill=True, new_x="LMARGIN", new_y="NEXT")

            pdf.cell(CONTENT_W, 0, "", border="T", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
