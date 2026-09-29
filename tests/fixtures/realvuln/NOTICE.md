# RealVuln fixture

`vulpy.ground-truth.json` and `vulpy.semgrep.json` are copied unchanged from the RealVuln benchmark
(https://github.com/kolega-ai/Real-Vuln-Benchmark, commit 7a710251f55c17d32d3adcb13d37468e2e3b9e4a,
benchmark 3.1.0): `ground-truth/realvuln-vulpy/ground-truth.json` and
`scan-results/realvuln-vulpy/semgrep/results.json`. Licensed under the Apache License 2.0 by Kolega.ai.

They pin vulnscan's scorer to RealVuln's: RealVuln's own scorer (scorer/matcher.py + metrics.py) gives
TP 16, FP 29, FN 41, TN 6, F3 0.2867, CVSS-weighted F3 0.3028 on these two files.
