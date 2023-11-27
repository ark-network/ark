---
sidebar_position: 3
title: Run with Docker
---

The Coordinator can be served as a dockerized application by following the steps below:

1. Install [Docker](https://docs.docker.com/engine/install) - if you're on Linux, don't forget the [post-installation steps](https://docs.docker.com/engine/install/linux-postinstall/)!
2. Download the latest image of the connector with `docker pull ghcr.io/ark-network/coordinatord:latest`
3. Create a `coordinatord/` folder in your current directory - to mount the datadir as external volume - and start the dockerized service with

```bash
$ docker run -it -d --name coordinatord \
  -u
  -v "$(pwd)/coordinatord:/home/ark/.coordinatord" \
  -e ARK_COORDINATOR_LOG_LEVEL=5 \
  ghcr.io/ark-network/coordinatord:latest
```

You can check the logs of the service at anytime by running `docker logs coordinatord`.

The dockerized Coordinator can be configured by the means of environment variables or by adding a `config.json` file to the `coordinatord/` folder you've created. Learn more about this by visiting [this section](configure-service.md).

The service comes also with an embedded CLI, so it's enough for you to create an alias like the following to use it:

```bash
$ alias coordinator="docker exec coordinatord coordinator"
```

Take a look at how to [configure the CLI](configure-cli.md) before start interacting with the running Coordinator.
