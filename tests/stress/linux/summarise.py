#!/usr/bin/env python3
"""Turn a run's CSVs into a GitHub job summary.

Reads throughput.csv (elapsed,rx_mbit,tx_mbit,cpu_pct) and, when the ETW capture
produced one, peer-rates.csv (elapsed,added,deleted). Writes Markdown: a table, a
Mermaid chart per series, and a sparkline under each one so the numbers are legible
even where Mermaid is not rendered.

Usage: summarise.py <results-dir> [> $GITHUB_STEP_SUMMARY]
"""
import sys
import os
import csv

BARS = ' .:-=+*#%@'


def read_csv(path, cols):
    """Return column-wise lists of floats, or None if the file is unusable."""
    if not os.path.exists(path):
        return None
    rows = []
    with open(path, newline='') as fh:
        for row in csv.DictReader(fh):
            try:
                rows.append([float(row[c]) for c in cols])
            except (TypeError, ValueError, KeyError):
                continue          # a partial last line, or a sampler error message
    if not rows:
        return None
    return [[r[i] for r in rows] for i in range(len(cols))]


def bucket_max(values, width):
    """Downsample by the max of each bucket, never by sampling every nth value: the
    bursts are the point, and a flood wave expiring takes three seconds out of nine
    hundred."""
    step = max(1, len(values) // width)
    return [max(values[i:i + step]) for i in range(0, len(values), step)]


def sparkline(values, width=60):
    """One line of text, so the shape survives where Mermaid is not rendered."""
    if not values:
        return ''
    buckets = bucket_max(values, width)
    top = max(buckets) or 1
    return ''.join(BARS[min(len(BARS) - 1, int(v / top * (len(BARS) - 1)))] for v in buckets)


def mermaid(title, unit, x, series, width=40):
    """An xychart-beta block. Downsampled, because the renderer crowds past ~40 points."""
    lines = ['```mermaid', 'xychart-beta', '    title "%s"' % title,
             '    x-axis "seconds" %d --> %d' % (int(min(x)), int(max(x)))]
    hi = max((max(v) for _, v in series if v), default=0) or 1
    lines.append('    y-axis "%s" 0 --> %d' % (unit, int(hi * 1.1) + 1))
    for _, values in series:
        lines.append('    line [%s]' % ', '.join('%.1f' % v for v in bucket_max(values, width)))
    lines.append('```')
    return chr(10).join(lines)


def section(out, title, path, cols, labels, unit):
    data = read_csv(path, cols)
    if not data:
        out.append('_no %s collected_' % os.path.basename(path))
        out.append('')
        return
    x = data[0]
    series = list(zip(labels, data[1:]))
    out.append('### %s' % title)
    out.append('')
    out.append('| series | mean | peak |')
    out.append('| --- | --- | --- |')
    for name, values in series:
        out.append('| %s | %.1f | %.1f |' % (name, sum(values) / len(values), max(values)))
    out.append('')
    out.append(mermaid('%s: %s' % (title, ', '.join(n for n, _ in series)), unit, x, series))
    out.append('')
    for name, values in series:
        out.append('`%-8s %s`  peak %.0f' % (name, sparkline(values), max(values)))
    out.append('')


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    throughput = os.path.join(root, 'throughput.csv')
    out = ['## Stress run', '']
    # One unit per chart: xychart-beta has no legend and one y-axis, so mixing Mbit/s with
    # a percentage hides the percentage along the floor and leaves the lines unnamed. The
    # series are named in each title instead, in the order they are drawn.
    section(out, 'Throughput', throughput,
            ['elapsed', 'rx_mbit', 'tx_mbit'], ['rx_mbit', 'tx_mbit'], 'Mbit/s')
    section(out, 'Server CPU', throughput,
            ['elapsed', 'cpu_pct'], ['cpu_pct'], '%')
    section(out, 'Peers added and deleted', os.path.join(root, 'peer-rates.csv'),
            ['elapsed', 'added', 'deleted'], ['added', 'deleted'], 'per second')
    print(chr(10).join(out))


if __name__ == '__main__':
    main()
