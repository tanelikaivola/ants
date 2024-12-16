ANTS is a tcp tarpitter made with Rust.

# Usage
Start the application with:
```console
sudo cargo run --release -- -i <interface_name> [--passive | -p] [--log-level <level>]
```
Required Flags:

-i <interface_name>: Specify the network interface to use.

Optional Flags:

--passive or -p: Run in passive mode. By default, the application runs in active mode. In passive mode any responses are not sent.

--log-level <level>: Set the logging level (debug, info, error). Defaults to info.

# Docker running

First create docker images of ants and nmap scanner

```console
docker build -f ants.Dockerfile -t ants1 . && docker build -f my_nmap.Dockerfile -t my_nmap .
```

Then create a testnetwork

```console
docker network create -d bridge --subnet=172.19.0.0/16 my_custom_bridge
```

Lastly compose and run containers

```console
docker-compose up
```

After docker compose up open new terminal for interactive use of nmap

```console
docker exec -it scanner bash
```
# Relevant work:
https://labrea.sourceforge.io/Intro-History.html

https://github.com/Hirato/LaBrea/

https://www.cmand.org/papers/degreaser-acsac14.pdf
