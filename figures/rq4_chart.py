"""Generate the paper's RQ4 WAL-vs-DELETE latency figure.

Run from anywhere; writes ``rq4_chart.pdf`` next to this script. Both
journal-mode series below come from the same matched 500,000-call,
20-configuration sweep. This script plots that preserved summary; it does
not rerun the benchmark.
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.family"] = "DejaVu Serif"
plt.rcParams["font.size"] = 9
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42

# "Both" phase, matched storage/synchronization settings from one sweep.
configs = ["tmpfs\nFULL", "tmpfs\nNORMAL", "tmpfs\nOFF", "NFS\nFULL", "NFS\nNORMAL", "NFS\nOFF"]
wal_median = [1.1534665, 1.1485085, 1.144393, 19.1459685, 17.808912, 17.7920735]
delete_median = [1.6685445, 1.659228, 1.596192, 21.4688695, 20.596620, 19.680626]
wal_p99 = [1.607601, 1.601215, 1.592974, 27.698705, 63.184215, 27.159032]
delete_p99 = [1.748420, 1.735073, 1.670293, 24.681349, 23.517951, 22.316034]

fig, axes = plt.subplots(1, 2, figsize=(6.9, 2.6))

x = np.arange(len(configs))
width = 0.35

ax = axes[0]
ax.bar(x - width/2, wal_median, width, label="WAL", color="0.85", edgecolor="black", hatch="")
ax.bar(x + width/2, delete_median, width, label="DELETE (production default)", color="0.5", edgecolor="black", hatch="///")
ax.set_ylabel("Median latency (ms)")
ax.set_xticks(x)
ax.set_xticklabels(configs, fontsize=7.5)
ax.set_title("(a) Median", fontsize=9)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)

ax = axes[1]
ax.bar(x - width/2, wal_p99, width, label="WAL", color="0.85", edgecolor="black", hatch="")
ax.bar(x + width/2, delete_p99, width, label="DELETE (production default)", color="0.5", edgecolor="black", hatch="///")
ax.set_ylabel("p99 latency (ms)")
ax.set_xticks(x)
ax.set_xticklabels(configs, fontsize=7.5)
ax.set_title("(b) p99", fontsize=9)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)

handles, labels = axes[0].get_legend_handles_labels()
fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 1.08), ncol=2, frameon=False, fontsize=8.5)

plt.tight_layout(rect=[0, 0, 1, 0.94])
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rq4_chart.pdf")
plt.savefig(out, bbox_inches="tight")
print("saved", out)
