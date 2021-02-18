iptables-ecn
============

The `iptables-ecn` script and associated analysis program gathers ECN statistics
on Linux routers with iptables and ipset support.

It was used to create an informational Internet Draft, available [here]().

# Features

`iptables-ecn` collects data into and out of a selected LAN subnet, for:
- IP data, with stateless counters of ECN marked packets by LAN IP address
- TCP flow data by LAN IP address, including TCP SYN and SYN-ACK counts with ECN
  support, ECN marks, and ECE flags
- Conntrack flow data by LAN IP address and destination port, including ECN
  marks

`ecn-stats.go` analyzes the output from `iptables-ecn` and emits textual stats,
including:
- Tables of IP counter data, separated by direction
- TCP initiation stats and tables of ECN signal counts by LAN IP address
- Tables of ECN signal counts for non-TCP conntrack-supported protocols (UDP,
  ICMP, DCCP, SCTP and GRE)

# Sample Data

See the [freenet](freenet) directory in this repo for sample output from the
analysis program, obtained from an ISP's Internet gateway.

# Installation and Running

## iptables-ecn

`iptables-ecn` should be able to run on any Linux router with bash, iptables
and ipset support. Run it without arguments for usage. Sample commands:

1. `iptables-ecn install -s 192.168.100.0/24 --start` installs and starts the
   script to monitor LAN subnet 192.168.100.0/24.
2. `iptables-ecn save` saves results, to be run after some period of data
   collection, and may be run multiple times
3. `iptables-ecn uninstall` removes all created chains and ipsets (any unsaved
   data is lost)

**Important notes:**
* The script uses connmarks to track TCP flows, which could potentially conflict
  with connmarks used for other purposes. Some equivalent statements that use
  connlabels are commented out, but since they were found to require more CPU,
  they are not used by default.
* It has been tested on a /16 subnet for an ISP with around 860 users, and
  seemed to scale well for this load. Larger loads may or may not be possible.
* It has undergone basic, but not extensive lab testing. In particular, support
  for conntrack protocols could use more verification of accuracy, which so far
  was only tested briefly with [IRTT](https://github.com/heistp/irtt).

## ecn-stats.go

The analysis program requires Go, which can be installed either using your OS's
package manager or from [here](https://golang.org/dl/).

To analyze the data, pass it the name of the .tar.gz file containing the data
collected with `iptables-ecn`, as follows:

`go run ./ecn-stats.go ecn_data_20210120_123543.tar.gz`

That will create a .json file with the full data, generate a .key file for IP
address anonymization, and emit the textual stats to stdout. Run `go
run ./ecn-stats.go` by itself for additional command line flags. See the
Configuration section at the top of the file for additional settings.
