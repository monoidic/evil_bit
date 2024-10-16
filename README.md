# Evil bit
This is a basic BPF program to help pentesters comply with [RFC3514](https://datatracker.ietf.org/doc/html/rfc3514) by setting the evil bit on all outgoing traffic on a network interface during an engagement.

Only ethernet and layer 3 tunnels are currently supported.

Note that this may make certain online resources which block traffic with the evil bit set inaccessible.

## Requirements
Dependencies include `clang`, `make`, `iproute2`, and `sed`.

## Build
When building, you need to specify the layer two header size of the interface you wish to attach this program to. When attaching it, you need to specify the device name. If not specified, the defaults of `wg0` and 0 are applied.

Example of building for and attaching to a WireGuard interface named `wg0`:

```sh
L3_OFF=0 make
sudo env DEV=wg0 make run
```

Example of building for and attaching to a regular ethernet interface named `enp1s0`:

```sh
L3_OFF=14 make
sudo env DEV=enp1s0 make run
```

For removing the BPF program/disabling the evil bit from an interface named `enp1s0`:

```sh
sudo env DEV=enp1s0 make clean
```