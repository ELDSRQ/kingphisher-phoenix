// Accessible monthly bar chart for the five-year ledger trend. Rendered as
// SVG with per-bar <title> and a legend; the adjacent report table remains the
// primary accessible data surface (this is a visual summary, not extra data).
// CSP-clean by construction: only presentation attributes, never inline style.

import { el, svg } from "./dom.js";

export function ledgerTrendChart(report) {
  const buckets = report.buckets || [];
  if (!buckets.length) {
    return el("p", { class: "field-help", text: "No monthly buckets to chart." });
  }
  const series = [
    { key: "confirmed_interaction", label: "Confirmed", color: "#174a7e", title: "Confirmed human interaction" },
    { key: "clicked", label: "Clicked", color: "#2e7d32", title: "Ledger exposure with an observed click" },
    { key: "no_click", label: "No click", color: "#9aa4b2", title: "Delivered exposure with no observed click" },
  ];
  const countsOf = (bucket) => new Map((bucket.counts || []).map((metric) => [metric.name, metric.value]));
  const rows = buckets.map((bucket) => ({ month: bucket.month, counts: countsOf(bucket) }));
  const maxValue = Math.max(1, ...rows.flatMap((row) => series.map((s) => row.counts.get(s.key) || 0)));

  const width = 720;
  const height = 240;
  const padLeft = 46;
  const padRight = 8;
  const padTop = 10;
  const padBottom = 28;
  const plotWidth = width - padLeft - padRight;
  const plotHeight = height - padTop - padBottom;
  const groupWidth = plotWidth / rows.length;
  const barWidth = Math.min(20, Math.max(2, (groupWidth * 0.8) / series.length));
  const scaleY = (value) => padTop + plotHeight - (plotHeight * Math.max(0, value)) / maxValue;

  const yTicks = 4;
  const yAxisTicks = [];
  for (let i = 0; i <= yTicks; i += 1) {
    const value = Math.round((maxValue * i) / yTicks);
    yAxisTicks.push(svg("text", {
      x: padLeft - 6, y: scaleY(value) + 4, "text-anchor": "end", "font-size": "10", class: "chart-axis",
    }, [String(value)]));
  }

  const labelStep = Math.max(1, Math.ceil(rows.length / 12));
  const bars = rows.map((row, groupIndex) => {
    const groupCenter = padLeft + groupWidth * groupIndex + groupWidth / 2;
    const groupBars = series.map((s, seriesIndex) => {
      const value = row.counts.get(s.key) || 0;
      const x = groupCenter - (series.length * barWidth) / 2 + seriesIndex * barWidth;
      const y = scaleY(value);
      const bar = svg("rect", {
        x, y, width: barWidth, height: Math.max(0, padTop + plotHeight - y),
        fill: s.color, role: "img",
      }, [svg("title", {}, [`${row.month} — ${s.label}: ${value}`])]);
      return bar;
    });
    const label = groupIndex % labelStep === 0
      ? svg("text", { x: groupCenter, y: height - 8, "text-anchor": "middle", "font-size": "9", class: "chart-axis" }, [row.month])
      : null;
    return svg("g", {}, [...groupBars, label].filter(Boolean));
  });

  const legend = el("div", { class: "chart-legend" }, series.map((s, index) => (
    el("span", { class: "chart-legend-item" }, [
      el("span", { class: `chart-legend-swatch swatch-${index}`, "aria-hidden": "true" }),
      el("span", { text: `${s.label} (${s.title})` }),
    ])
  )));

  const chart = svg("svg", {
    width, height, viewBox: `0 0 ${width} ${height}`, role: "img",
    "aria-label": "Monthly pseudonymous ledger exposures: confirmed interaction, clicked, and no-click counts by month. Exact figures are in the table below.",
    class: "report-chart-svg",
  }, [
    svg("title", {}, ["Five-year awareness ledger exposure trend by month"]),
    svg("g", { "aria-hidden": "true" }, yAxisTicks),
    ...bars,
  ]);

  return el("figure", { class: "report-chart" }, [legend, chart]);
}
