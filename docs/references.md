# Fact references

## Configuration options

### Environment variables

* `FACT_PATHS`: List of file paths to monitor.

* `FACT_LOGLEVEL`: At which level produce log messages.

### Commandline options

* `--skip-pre-flight`: Do not perform pre-flight checks. Before starting up
  Fact tries to verify if needed LSM hooks are available, but in some
  environments this might not be robust enough. In such cases one can disable
  those checks.

* `-p, --paths`: List of file paths to monitor. This option could be used
  multiple times, instructing Fact to monitor multiple files.
