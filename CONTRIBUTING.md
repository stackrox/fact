# Contributing guidelines

Welcome to the project! Here are a few tips to guide you through your
contribution.

## Standalone first

We try to keep project developer friendly and make it easy to run independently
in any environment. That means that any new functionality needs to be mindful
about external dependencies and keep them optional as much as possible.

## Extensible architecture

The project is under active development, and we encourage new contributors
bringing new ideas and features. To keep this under control make sure adding
your feature does not require significant changes in existing code. If possible
design new functionality in a "pluggable" way, so that it only has to be
registered somewhere to kick in -- think event processing pipelines, channels,
Multiple Producers Single Consumer approaches (MPSC), etc.

## Minimal state

When developing a new functionality try to keep the state minimal, where under
"state" we understand:

* A working set of the feature that lives in memory. Due to the monitoring
  nature of the project it's more than easy to end up in a situation when Fact
  has to handle lots of data. At the same time we have to be a good citizen and
  keep memory footprint as low as possible. Hence, think about what really
  needs to be stored in memory, and what could be sampled or aggregated.

* Execution state of the program. In the spirit of extensible architecture, try
  to make new functionality as isolated as possible and require only minimal
  input from the rest of the program to do what it is supposed to do.
