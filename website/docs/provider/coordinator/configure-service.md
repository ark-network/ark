---
sidebar_position: 4
title: Configure the Coordinator
---

The Coordinator can be configured by exporting environment variables at startup, or by adding a configuration file to its datadir.

### Configure with environment variables

The following table lists all the environment variables available, along with a brief description and their default values:

| Name | Description | Default Value |
|---|---|---|
| ARK_COORDINATOR_DATADIR | Let's you change the service's datadir path | `~/.coordinatord` (Linux).<br/><br/>`~/Library/Application\ Support/Coordinatord` (MacOS). |

### Configure with file

You can configure the Coordinator by adding a `config.json` file to its datadir.

Below, you can see all the props you can add to the config file:

```json
{
  //TBD
}
```