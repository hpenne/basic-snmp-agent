# Fuzz testing

## Coverage report

The daily fuzz workflow generates an HTML coverage report after each batch run.

To find it:

1. Go to the **Actions** tab in the GitHub repository.
2. Select the **Fuzz** workflow.
3. Open the latest successful run.
4. Scroll to the **Artifacts** section at the bottom of the run page.
5. Download `fuzz-coverage-report`.

To view the report locally:

```sh
unzip fuzz-coverage-report.zip -d fuzz-coverage-report
open fuzz-coverage-report/index.html   # macOS
xdg-open fuzz-coverage-report/index.html  # Linux
```

## Corpus pruning

The corpus is pruned automatically on the first day of each month at 03:00 UTC.

To trigger pruning manually:

1. Go to the **Actions** tab in the GitHub repository.
2. Select the **Fuzz corpus prune** workflow.
3. Click **Run workflow**.

Pruning operates on the corpus stored by ClusterFuzzLite (configured via `storage-repo` or a GCS bucket).
If no external corpus storage is configured, pruning has no effect.
