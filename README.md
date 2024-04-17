# runz

runc's libcontainer example is a bit broken, so this is an attempt at a working
example.

Requires:

1. linux
2. running as root
3. a rootfs

To create the rootfs:

```
mkdir rootfs
cd rootfs

docker export $(docker run --detach ubuntu:22.04) | tar x
```

To run the sample code:
```
go build
sudo ROOTFS=/absolute/path/to/rootfs ./runz
```

You should see something like:

```
2024/04/17 11:13:41 main()
2024/04/17 11:13:41 running!
HELLO123
```

## Resources

- libcontainer readme: https://github.com/opencontainers/runc/blob/main/libcontainer/README.md
- libcontainer nsenter readme: https://github.com/opencontainers/runc/blob/main/libcontainer/nsenter/README.md
