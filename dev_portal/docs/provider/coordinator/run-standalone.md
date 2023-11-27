---
sidebar_position: 2
title: Run Standalone
---

The Coordinator can be served as a standalone binary by following the steps below:

1.  Download the lastest [release](https://github.com/ark-network/ark-coordinator/releases) of the service and the CLI for Linux or MacOS.
2.  Rename the binaries `coordinatord` and `coordinator` , move them to your _PATH_ (eg. `/usr/local/bin`), and grant them exec permissions with `chmod +x /usr/local/bin/coordinatord` and `chmod +x /usr/local/bin/coordinator`.
3.  Start the service with

```bash
ARK_COORDINATOR_LOG_LEVEL=5
coordinatord & > ~/ark-logs/coordinator.logs.txt &
```

The command above redirects all the logs to the file `~/ark-logs/coordinator.logs.txt`. Therefore you can check the logs of the service at anytime by consulting that file.

The Coordinator service makes use of a datadir - defaults to `~/.coordinatord` on Linux, `~/Library/Application\ Support/Coordinatord` on MacOS - that can be customized by exporting the environment variable `export ARK_COORDINATOR_DATADIR=path/to/datadir` at its startup.

You can configure the Coordinator by the means of environment variables or by adding a `config.json` file to the service's datadir. Learn more about this by visiting [this section](configure-service.md).

Once the service is started you can [configure the CLI](configure-cli.md) and start interacting with it.
