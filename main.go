package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/devices"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	_ "github.com/opencontainers/runc/libcontainer/nsenter"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		// This is the golang entry point for runc init, executed
		// before main() but after libcontainer/nsenter's nsexec().
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()

		logPipeFd, err := strconv.Atoi(os.Getenv("_LIBCONTAINER_LOGPIPE"))
		if err != nil {
			panic(fmt.Sprintf("pipe=> %v", err))
		}

		// libcontainer expects logs in logrus's json format on the pipe fd
		// specified by the env var above
		logrus.SetLevel(logrus.DebugLevel)
		logrus.SetOutput(os.NewFile(uintptr(logPipeFd), "logpipe"))
		logrus.SetFormatter(new(logrus.JSONFormatter))
		logrus.Debug("child process in init()")

		// the following helper performs all kinds of internal libcontainer
		// operations before eventually exec'ing the final user command. Control is
		// never returned to this code so the panic below is never reached.
		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			// as the error is sent back to the parent there is no need to log
			// or write it to stderr because the parent process will handle this
			os.Exit(1)
		}
		panic("libcontainer: container init failed to exec")
	}
}

func main() {
	log.Println("main()")

	if os.Getenv("ROOTFS") == "" {
		log.Println("must set ROOTFS to a linux rootfs (absolute path)")
		os.Exit(99)
	}

	defaultMountFlags := unix.MS_NOEXEC | unix.MS_NOSUID | unix.MS_NODEV
	var devices []*devices.Rule
	for _, device := range specconv.AllowedDevices {
		devices = append(devices, &device.Rule)
	}
	config := &configs.Config{
		Rootfs: os.Getenv("ROOTFS"),
		Capabilities: &configs.Capabilities{
			Bounding: []string{
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_FSETID",
				"CAP_FOWNER",
				"CAP_MKNOD",
				"CAP_NET_RAW",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETFCAP",
				"CAP_SETPCAP",
				"CAP_NET_BIND_SERVICE",
				"CAP_SYS_CHROOT",
				"CAP_KILL",
				"CAP_AUDIT_WRITE",
			},
			Effective: []string{
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_FSETID",
				"CAP_FOWNER",
				"CAP_MKNOD",
				"CAP_NET_RAW",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETFCAP",
				"CAP_SETPCAP",
				"CAP_NET_BIND_SERVICE",
				"CAP_SYS_CHROOT",
				"CAP_KILL",
				"CAP_AUDIT_WRITE",
			},
			Permitted: []string{
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_FSETID",
				"CAP_FOWNER",
				"CAP_MKNOD",
				"CAP_NET_RAW",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETFCAP",
				"CAP_SETPCAP",
				"CAP_NET_BIND_SERVICE",
				"CAP_SYS_CHROOT",
				"CAP_KILL",
				"CAP_AUDIT_WRITE",
			},
			Ambient: []string{
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_FSETID",
				"CAP_FOWNER",
				"CAP_MKNOD",
				"CAP_NET_RAW",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETFCAP",
				"CAP_SETPCAP",
				"CAP_NET_BIND_SERVICE",
				"CAP_SYS_CHROOT",
				"CAP_KILL",
				"CAP_AUDIT_WRITE",
			},
		},
		Namespaces: configs.Namespaces([]configs.Namespace{
			{Type: configs.NEWNS},
			{Type: configs.NEWUTS},
			{Type: configs.NEWIPC},
			{Type: configs.NEWPID},
			// Commented out because (a) nomad doesn't use a user namespace, and (b)
			// the runc example code was broken.
			//{Type: configs.NEWUSER},
			{Type: configs.NEWNET},
			{Type: configs.NEWCGROUP},
		}),
		Cgroups: &configs.Cgroup{
			Name:   "test-container",
			Parent: "system",
			Resources: &configs.Resources{
				MemorySwappiness: nil,
				Devices:          devices,
			},
		},
		MaskPaths: []string{
			"/proc/kcore",
			"/sys/firmware",
		},
		ReadonlyPaths: []string{
			"/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus",
		},
		Devices:  specconv.AllowedDevices,
		Hostname: "testing",
		Mounts: []*configs.Mount{
			{
				Source:      "proc",
				Destination: "/proc",
				Device:      "proc",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "tmpfs",
				Destination: "/dev",
				Device:      "tmpfs",
				Flags:       unix.MS_NOSUID | unix.MS_STRICTATIME,
				Data:        "mode=755",
			},
			{
				Source:      "devpts",
				Destination: "/dev/pts",
				Device:      "devpts",
				Flags:       unix.MS_NOSUID | unix.MS_NOEXEC,
				Data:        "newinstance,ptmxmode=0666,mode=0620,gid=5",
			},
			{
				Device:      "tmpfs",
				Source:      "shm",
				Destination: "/dev/shm",
				Data:        "mode=1777,size=65536k",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "mqueue",
				Destination: "/dev/mqueue",
				Device:      "mqueue",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "sysfs",
				Destination: "/sys",
				Device:      "sysfs",
				Flags:       defaultMountFlags | unix.MS_RDONLY,
			},
		},
		Networks: []*configs.Network{
			{
				Type:    "loopback",
				Address: "127.0.0.1/0",
				Gateway: "localhost",
			},
		},
		Rlimits: []configs.Rlimit{
			{
				Type: unix.RLIMIT_NOFILE,
				Hard: uint64(1025),
				Soft: uint64(1025),
			},
		},
	}

	// Create a container factory
	factory, err := libcontainer.New("/run/containers", nil)
	if err != nil {
		log.Fatalf("New=>", err)
		return
	}

	// Create a container
	container, err := factory.Create("container-id", config)
	if err != nil {
		log.Fatal("Create=>", err)
		return
	}

	// Create the process to run in the container
	process := &libcontainer.Process{
		Args:   []string{"/bin/bash", "-c", "echo HELLO123"},
		Env:    []string{"PATH=/bin"},
		User:   "daemon",
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Init:   true,
	}

	// Actually run the process in the container. Here is where all the
	// reexecing happens.
	if err := container.Run(process); err != nil {
		container.Destroy()
		log.Fatal("Run=>", err)
		return
	}

	// If you see this once and only once, the init() and nsenter business worked
	// as expected.
	log.Println("running!")

	// wait for the process to finish.
	if _, err := process.Wait(); err != nil {
		log.Fatal("Wait=>", err)
	}

	// destroy the container.
	container.Destroy()
}
