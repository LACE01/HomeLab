"""Chart flowables for PDF reports, built on reportlab.graphics (already a hard
dependency via reportlab -- no extra package needed, which matters since this app's
pip index has been flaky about newer pins in some environments).

Each function returns a reportlab Drawing, which is itself a flowable and can be
appended directly into a SimpleDocTemplate's elements list right alongside
Paragraphs and Tables.
"""
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.charts.legends import Legend
from reportlab.lib import colors

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#ef4444"),
    "High": colors.HexColor("#f97316"),
    "Medium": colors.HexColor("#f59e0b"),
    "Low": colors.HexColor("#3b82f6"),
    "Info": colors.HexColor("#64748b"),
}


def severity_pie_chart(counts: dict, width=280, height=180) -> Drawing:
    """counts: {"Critical": n, "High": n, ...}"""
    order = [s for s in ["Critical", "High", "Medium", "Low", "Info"] if counts.get(s, 0) > 0]
    if not order:
        order = ["Critical", "High", "Medium", "Low", "Info"]
    values = [counts.get(s, 0) for s in order]
    total = sum(values) or 1

    d = Drawing(width, height)
    pie = Pie()
    pie.x = 15
    pie.y = 15
    pie.width = 130
    pie.height = 130
    pie.data = values
    pie.labels = [f"{s} ({counts.get(s, 0)})" for s in order]
    pie.simpleLabels = 0
    pie.sideLabels = 1
    pie.slices.strokeWidth = 0.75
    pie.slices.strokeColor = colors.HexColor("#0D1117")
    for i, s in enumerate(order):
        pie.slices[i].fillColor = SEVERITY_COLORS.get(s, colors.grey)
    d.add(pie)
    return d


def trend_line_chart(rows: list, series: list, width=460, height=190) -> Drawing:
    """rows: list of dicts with a 'date' key plus one key per series.
    series: [{"key": "org_score", "label": "Score", "color": "#2F81F7"}, ...]
    Draws a multi-line trend chart with a date axis -- used for score/SLA history
    and opened-vs-closed throughput, mirroring what's already on the Executive tab."""
    d = Drawing(width, height)
    if not rows:
        d.add(String(10, height / 2, "No historical data yet.", fontSize=9, fillColor=colors.grey))
        return d

    plot = LinePlot()
    plot.x = 45
    plot.y = 30
    plot.width = width - 90
    plot.height = height - 60

    data = []
    for s in series:
        line = [(i, (r.get(s["key"]) if r.get(s["key"]) is not None else 0)) for i, r in enumerate(rows)]
        data.append(line)
    plot.data = data

    for i, s in enumerate(series):
        plot.lines[i].strokeColor = colors.HexColor(s["color"])
        plot.lines[i].strokeWidth = 1.75

    plot.xValueAxis.valueMin = 0
    plot.xValueAxis.valueMax = max(1, len(rows) - 1)
    n = len(rows)
    step = max(1, n // 6)
    plot.xValueAxis.valueSteps = list(range(0, n, step))
    plot.xValueAxis.labelTextFormat = lambda v: rows[int(v)]["date"][5:10] if 0 <= int(v) < n else ""
    plot.xValueAxis.labels.fontSize = 6.5
    plot.xValueAxis.labels.angle = 30
    plot.xValueAxis.labels.dy = -8

    all_vals = [v for s in series for r in rows for v in [r.get(s["key"]) or 0]]
    plot.yValueAxis.valueMin = 0
    plot.yValueAxis.valueMax = max(10, (max(all_vals) if all_vals else 100) * 1.15)
    plot.yValueAxis.labels.fontSize = 7

    d.add(plot)

    legend = Legend()
    legend.x = width - 10
    legend.y = height - 10
    legend.alignment = "right"
    legend.fontSize = 7
    legend.dxTextSpace = 6
    legend.columnMaximum = len(series)
    legend.colorNamePairs = [(colors.HexColor(s["color"]), s["label"]) for s in series]
    d.add(legend)
    return d


def bar_chart(labels: list, values: list, width=460, height=200, bar_color="#ef4444", value_label="Count") -> Drawing:
    """Simple vertical bar chart -- used for aging buckets, business-unit exposure, etc."""
    d = Drawing(width, height)
    if not labels or not values:
        d.add(String(10, height / 2, "No data.", fontSize=9, fillColor=colors.grey))
        return d

    chart = VerticalBarChart()
    chart.x = 45
    chart.y = 40
    chart.width = width - 70
    chart.height = height - 70
    chart.data = [values]
    chart.categoryAxis.categoryNames = [str(l)[:14] for l in labels]
    chart.categoryAxis.labels.fontSize = 6.5
    chart.categoryAxis.labels.angle = 25
    chart.categoryAxis.labels.dy = -8
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(1, max(values) * 1.2)
    chart.valueAxis.labels.fontSize = 7
    chart.bars[0].fillColor = colors.HexColor(bar_color)
    chart.barWidth = 10
    d.add(chart)
    return d


def multi_series_bar_chart(labels: list, series: list, width=460, height=210) -> Drawing:
    """series: [{"label": "Critical", "color": "#ef4444", "values": [..]}, {"label": "High", ...}]
    Grouped bars -- used for e.g. aging report (severity split per age bucket)."""
    d = Drawing(width, height)
    if not labels or not series:
        d.add(String(10, height / 2, "No data.", fontSize=9, fillColor=colors.grey))
        return d

    chart = VerticalBarChart()
    chart.x = 45
    chart.y = 40
    chart.width = width - 70
    chart.height = height - 70
    chart.data = [s["values"] for s in series]
    chart.categoryAxis.categoryNames = [str(l)[:14] for l in labels]
    chart.categoryAxis.labels.fontSize = 6.5
    all_vals = [v for s in series for v in s["values"]]
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(1, (max(all_vals) if all_vals else 1) * 1.2)
    chart.valueAxis.labels.fontSize = 7
    chart.barWidth = 6
    chart.groupSpacing = 8
    for i, s in enumerate(series):
        chart.bars[i].fillColor = colors.HexColor(s["color"])
    d.add(chart)

    legend = Legend()
    legend.x = width - 10
    legend.y = height - 8
    legend.alignment = "right"
    legend.fontSize = 7
    legend.columnMaximum = len(series)
    legend.colorNamePairs = [(colors.HexColor(s["color"]), s["label"]) for s in series]
    d.add(legend)
    return d
