---
sidebar_position: 5
title: Configure the CLI
---

Now that your service is up and running you can configure the `coordinator` CLI to interact with it.

The CLI makes use of a configuration file stored in its datadir - defaults to `~/.coordinator-cli` on Linux, `~/Library/Application\ Support/Coordinator-cli` on MacOS.

You can customize the datadir path of your coordinator cli by exporting the environment variable `export ARK_COORDINATOR_CLI_DATADIR=path/to/datadir`.

:::tip
Add this env var to your bash profile otherwise you'll need to always export it when running `coordinator` commands.
:::

You can manage the configuration of your CLI with the features of the `coordinator config` command. Following, you can learn all what you can do with this command.

### Initialize CLI config

You can initialize the configuration of your CLI by the means of flags

```bash
$ coordinator config init
```

This command brings the configuration of your CLI to its default status unless you don't specify a flag for those params you want to tweak.

Run `coordinator config init --help` to see all available configuration flags.

### Customize CLI config

You can change granular params of the CLI's configuration by using the `set` subcommand as shown below:

```bash
$ coordinator config set no-tls true
```

### Show CLI config

You can take a look at the configuration of your CLI with:

```bash
$ coordinator config
```

You've learned everything about configuring the CLI, let's see how it does let you interact with the Coordinator.