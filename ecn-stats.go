package main

// This program analyzes data from iptables-ecn. See the Configuration section
// at the top of the file to set configuration, or use the format flag to
// select a few builtin output formats. Run the program for usage.

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"

	"honnef.co/go/netdb"
)

//
//
// Begin Configuration- edit below to set config
//
//

// IPAnonymizationMask is the mask used for IP address anonymization. For
// example, "/8" will anonymize all but the first octet. Empty string disables.
var IPAnonymizationMask = "/8"

// ShowConntrackPortsByIP means show the conntrack port list, by IP address.
var ShowConntrackPortsByIP = true

// ShowConntrackPortsByPort means show the conntrack port list, by port.
var ShowConntrackPortsByPort = true

// ShowLANToWAN means to show stats for LAN to WAN flows.
var ShowLANtoWAN = true

// ShowWANToLAN means to show stats for WAN to LAN flows.
var ShowWANtoLAN = true

// ActiveIPSynThreshold is the minimum number of TCP SYNs to call an IP active.
var ActiveIPSynThreshold = int64(10)

// MaybeECNThreshold is the number of ECT(0) marks to consider a conntrack flow
// as "maybe ECN".
var MaybeECNThreshold = int64(10)

// InterestingPorts are those listed for conntrack protocols.
var InterestingPorts = []int{
	20,    // ftp-data
	21,    // ftp
	80,    // http
	443,   // https
	500,   // isakmp (l2tp)
	1194,  // openvpn
	1701,  // l2tp
	1723,  // pptp
	3478,  // stun
	4500,  // ipsec-nat-t (l2tp)
	5349,  // stuns
	8080,  // http-alt
	8443,  // https-alt
	51820, // wireguard
}

// CTInterestingByIP is what should be displayed in the conntrack port list by
// IP address.
var CTInterestingByIP = CTInteresting{
	// Verbose overrides other settings and lists all ports.
	Verbose: false,

	// WellKnown: include all well-known ports (>=0 and <1024).
	WellKnown: false,

	// Known: include all ports with servname entries in /etc/services.
	Known: false,

	// BidirActivity: include ports that showed ECN signals both ways.
	BidirActivity: true,

	// MinSignals: include ports with this minimum number of ECN signals.
	MinSignals: 1000,

	// MaybeECN: include ports with nonzero ECT(0) packet counts both dirs.
	MaybeECN: true,

	// LikelyECN: include ports with ECT(0) and CE packets in opposite dirs.
	LikelyECN: true,

	// Ports: an explicit list of ports to include.
	Ports: InterestingPorts,
}

// CTInterestingByPort is what should be displayed in the conntrack port list by
// port.
var CTInterestingByPort = CTInteresting{
	// Verbose overrides other settings and lists all ports.
	Verbose: false,

	// WellKnown: include all well-known ports (>=0 and <1024).
	WellKnown: true,

	// Known: include all ports with servname entries in /etc/services.
	Known: false,

	// BidirActivity: include ports that showed ECN signals both ways.
	BidirActivity: false,

	// MinSignals: include ports with this minimum number of ECN signals.
	MinSignals: 0,

	// MaybeECN: include ports with nonzero ECT(0) packet counts both dirs.
	MaybeECN: false,

	// LikelyECN: include ports with ECT(0) and CE packets in opposite dirs.
	LikelyECN: false,

	// Ports: an explicit list of ports to include.
	Ports: InterestingPorts,
}

// CTNoteworthyByIP is what should be marked with an asterisk in the conntrack
// port list by IP address.
var CTNoteworthyByIP = CTNoteworthy{
	// MaybeECN: include ports with nonzero ECT(0) packet counts both dirs.
	MaybeECN: true,

	// LikelyECN: include ports with ECT(0) and CE packets in opposite dirs.
	LikelyECN: true,
}

// CTNoteworthyByPort is what should be marked with an asterisk in the conntrack
// port list by port.
var CTNoteworthyByPort = CTNoteworthy{
	// MaybeECN: include ports with nonzero ECT(0) packet counts both dirs.
	MaybeECN: false,

	// LikelyECN: include ports with ECT(0) and CE packets in opposite dirs.
	LikelyECN: false,
}

// CTUninterestingByIP is what's uninteresting in the conntrack port list by IP
// address.
var CTUninterestingByIP = CTUninteresting{
	// PortPrefixes is a list of prefixes in the proto:port string to exclude.
	PortPrefixes: []string{
		"icmp",
		"ipencap",
	},

	// Ranges means to not list uninteresting port ranges.
	Ranges: true,
}

// CTUninterestingByPort is what's uninteresting in the conntrack port list by
// port.
var CTUninterestingByPort = CTUninteresting{
	// PortPrefixes is a list of prefixes in the proto:port string to exclude.
	PortPrefixes: []string{},

	// Ranges means to not list uninteresting port ranges.
	Ranges: false,
}

// MaxColumnWidth is the maximum allowed column width for tables.
var MaxColumnWidth = math.MaxInt32

// EmitHeadersEvery is the number of rows in the ports list to repeat headers.
var EmitHeadersEvery = math.MaxInt32

// Formats maps format flag values to funcs that configure the formats.
var Formats = map[string]func(){
	"default": func() {},
	"draft": func() {
		//ShowConntrackPortsByIP = false
		ShowWANtoLAN = false
		MaxColumnWidth = 22
		MaybeECNThreshold = 100
	},
	"full": func() {
		CTInterestingByIP.Verbose = true
		CTInterestingByPort.Verbose = true
		CTUninterestingByIP.PortPrefixes = []string{}
	},
}

//
//
// End Configuration
//
//

//
// globals
//

// conntrackProtocols is the list of non-TCP protocols conntrack supports
const conntrackProtocols = "UDP, ICMP, DCCP, SCTP, GRE"

// anon is the IP anonymizer.
var anon *anonymizer

// dashes is used for underlining
var dashes = make([]byte, 128)

// spaces is used for underlining
var spaces = make([]byte, 128)

func init() {
	for i, _ := range dashes {
		dashes[i] = '-'
		spaces[i] = ' '
	}
}

//
// common types
//

// Origination indicates which direction a flow was initiated in.
type Origination int

const (
	// Incoming was initiated from WAN to LAN.
	Incoming Origination = iota

	// Outgoing was initiated from LAN to WAN.
	Outgoing

	// OrigUnknown is of unknown origination.
	OrigUnknown
)

// From indicates where a packet came from.
type From int

const (
	// LAN means the packet came from the LAN.
	LAN From = iota

	// WAN means the packet came from the WAN.
	WAN
)

// IPKey is an IP address map key.
type IPKey string

// IPToKey returns a new IPKey.
func IPToKey(ip net.IP) IPKey {
	return IPKey(ip.String())
}

// IP returns the IP for the key.
func (k IPKey) IP() net.IP {
	return net.ParseIP(string(k))
}

// IPLessThan returns true if IP a is less than IP b, octet by octet.
func IPLessThan(a, b net.IP) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return true
		} else if a[i] > b[i] {
			return false
		}
	}
	return false
}

// toIP parses and anonymizes an IP address.
func toIP(s string) (ip net.IP) {
	if ip = net.ParseIP(s); ip == nil {
		fail("bad IP address: '%s'", s)
	}

	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	if anon != nil {
		anon.Transform(ip)
	}

	return
}

// IPPort is an IPv4 address and port (proto:num), separated by a comma.
type IPPort struct {
	IP   net.IP
	Port Port
	Str  string
}

// toIPPort returns an IPPort, possibly anonymized.
func toIPPort(s string) (ipp IPPort) {
	f := strings.Split(s, ",")
	if len(f) != 2 {
		fail("bad IP,Port: '%s'", s)
	}

	ipp.IP = toIP(f[0])
	ipp.Port = toPort(f[1])
	ipp.Str = s

	return
}

// IPPortKey is an IPPort map key.
type IPPortKey string

// IPPortToKey returns a new IPPortKey.
func IPPortToKey(ipp IPPort) IPPortKey {
	return IPPortKey(ipp.Str)
}

// IPPort returns the IPPort for the key.
func (k IPPortKey) IPPort() IPPort {
	return toIPPort(string(k))
}

// LessThan performs a comparison by IP and port.
func (a IPPort) LessThan(b IPPort) bool {
	if IPLessThan(a.IP, b.IP) {
		return true
	} else if IPLessThan(b.IP, a.IP) {
		return false
	}
	if a.Port.LessThan(b.Port) {
		return true
	}
	return false
}

// Port is a protocol and port number or name, separated by a colon.
type Port struct {
	Proto    string
	Num      int
	Str      string
	servName string
	resolved bool
}

func toPort(s string) (p Port) {
	f := strings.Split(s, ":")
	if len(f) != 2 {
		fail("bad Port: '%s'", s)
	}

	p.Proto = f[0]
	p.Num, _ = strconv.Atoi(f[1])
	p.Str = s

	return
}

// DisplayName returns the port name and known service, if available.
func (p Port) DisplayName() (name string, known bool) {
	name = p.Str
	if p.Num > 0 {
		p.resolve()
		if p.servName != "" {
			name = fmt.Sprintf("%s (%s)", p.Str, p.servName)
			known = true
		}
	}
	return
}

// Known returns true if the port is known in /etc/services.
func (p Port) Known() bool {
	p.resolve()
	return p.servName != ""
}

// LessThan performs a comparison by protocol then port number.
func (p Port) LessThan(q Port) bool {
	if p.Proto < q.Proto {
		return true
	} else if q.Proto < p.Proto {
		return false
	}
	if p.Num < q.Num {
		return true
	}
	return false
}

// resolve resolves the ServName, if it wasn't already.
func (p *Port) resolve() {
	if p.resolved {
		return
	}
	if p.Num > 0 {
		p.servName = ServName(p.Proto, p.Num)
	}
	p.resolved = true
}

// SameProto returns true if p2 has the same protocol.
func (p Port) SameProto(p2 Port) bool {
	return p.Proto == p2.Proto
}

// Equals returns true if p2 is the same as this port.
func (p Port) Equals(p2 Port) bool {
	return p.Str == p2.Str
}

// NumOneOf returns true if the port number is in nums.
func (p Port) NumOneOf(nums []int) bool {
	for _, n := range nums {
		if p.Num == n {
			return true
		}
	}
	return false
}

// WellKnown returns true for well-known ports (number >= 0 and < 1024).
func (p Port) WellKnown() bool {
	return p.Num >= 0 && p.Num < 1024
}

// PortRange is a start and end port.
type PortRange struct {
	Start Port
	End   Port
}

// String returns a string representing the range.
func (r PortRange) String() string {
	if !r.Start.SameProto(r.End) {
		panic(fmt.Sprintf("%v", r))
	}
	if r.Start.Equals(r.End) {
		return r.Start.Str
	}
	return fmt.Sprintf("%s-%d", r.Start.Str, r.End.Num)
}

// Counters contains counters for packets and bytes.
type Counters struct {
	Packets int64
	Bytes   int64
}

// Add adds the counters in c2.
func (c *Counters) Add(c2 Counters) {
	c.Packets += c2.Packets
	c.Bytes += c2.Bytes
}

// Sub subtracts the counters in c2.
func (c *Counters) Sub(c2 Counters) {
	c.Packets -= c2.Packets
	c.Bytes -= c2.Bytes
}

// Zero returns true if counters are zero.
func (c *Counters) Zero() bool {
	return c.Packets == 0 && c.Bytes == 0
}

// Reset sets the counters to zero.
func (c *Counters) Reset() {
	c.Packets = 0
	c.Bytes = 0
}

// String returns the packets as a string.
func (c Counters) String() string {
	return strconv.FormatInt(c.Packets, 10)
}

// IPCounters holds counters for TCP, non-TCP conntrack and total IP protocols.
type IPCounters struct {
	// TCP includes all of the TCP data, and is taken from a sum of the
	// prot==tcp rows in ecn_from-(lan|wan).
	TCP Counters

	// NonTCP includes all of the non-TCP data, and is taken from the one
	// prot==!tcp line in ecn_from-(lan|wan).
	NonTCP Counters

	// IP includes all of the IP data, and is taken from the lines in ecn_main,
	// selecting "from" based on the target field.
	IP Counters
}

// Add adds the counters in c2 to c.
func (c *IPCounters) Add(c2 *IPCounters) {
	c.TCP.Add(c2.TCP)
	c.NonTCP.Add(c2.NonTCP)
	c.IP.Add(c2.IP)
}

//
// utility funcs
//

// tableWriter is a helper for writing tables
type tableWriter struct {
	*tabwriter.Writer
	indent   string
	truncate int
}

func newTableWriter(indent string) *tableWriter {
	return &tableWriter{
		tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0),
		indent,
		MaxColumnWidth,
	}
}

func newTableTabWriter(tw *tabwriter.Writer, indent string) *tableWriter {
	return &tableWriter{
		tw,
		indent,
		MaxColumnWidth,
	}
}

func (w *tableWriter) emitRow(underline bool, cols ...interface{}) {
	fmt.Fprintf(w, w.indent)
	for i, c := range cols {
		if i != 0 {
			fmt.Fprintf(w, "\t")
		}
		if underline {
			w.Write(dashes[:len(fmt.Sprint(c))])
		} else {
			cs := fmt.Sprintf("%s", c)
			fmt.Fprint(w, Truncate(cs, w.truncate))
		}
	}
	fmt.Fprintln(w)
}

// Row emits a row where each argument is a column.
func (w *tableWriter) Row(cols ...interface{}) {
	w.emitRow(false, cols...)
}

// URow calls Row and adds an underline row.
func (w *tableWriter) URow(cols ...interface{}) {
	w.emitRow(false, cols...)
	w.emitRow(true, cols...)
}

// Printf invokes Fprintf on the underlying writer, w/ indent and newline.
func (w *tableWriter) Printf(f string, a ...interface{}) {
	fmt.Fprintf(w.Writer, w.indent)
	fmt.Fprintf(w.Writer, f, a...)
	if f[len(f)-1] != '\n' {
		fmt.Fprintln(w.Writer)
	}
}

// UPrintf invokes Printf with newline then underlines the string.
func UPrintf(f string, a ...interface{}) {
	s := fmt.Sprintf(f, a...)
	s = strings.TrimRight(s, "\r\n")
	fmt.Println(s)
	sp := 0
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			break
		}
		sp++
	}
	os.Stdout.Write(spaces[:sp])
	os.Stdout.Write(dashes[:len(s)-sp])
	fmt.Println()
}

// Truncate shortens a string and adds an ellipsis.
func Truncate(s string, n int) (r string) {
	r = s
	if len(r) > n {
		if n > 2 {
			n -= 2
		}
		r = r[:n] + ".."
	}
	return
}

// ServName returns the service name, if available.
func ServName(protocol string, portNum int) (name string) {
	proto := netdb.GetProtoByName(protocol)
	if proto == nil {
		return
	}

	serv := netdb.GetServByPort(portNum, proto)
	if serv == nil {
		return
	}

	name = serv.Name

	return
}

//
// data structs
//

// ECNData contains the data parsed from the .tar.gz file.
type ECNData struct {
	// TCPOut is a map of IP addresses to TCPCounters, taken from the ipset data
	// in ecn_out_(!ct)*.
	TCPOut map[IPKey]TCPCounters

	// TCPIn is a map of IP addresses to TCPCounters, taken from the ipset data
	// in ecn_in_(!ct)*.
	TCPIn map[IPKey]TCPCounters

	// CTOut is a map of outgoing IP/dstport pairs to CTCounters, taken from the
	// ipset data in ecn_out_ct*.
	CTOut map[IPPortKey]CTCounters

	// CTIn is a map of incoming IP/dstport pairs to CTCounters, taken from the
	// ipset data in ecn_in_ct*.
	CTIn map[IPPortKey]CTCounters

	// IPECNFromLAN is a map of IP addresses to ECNCounters, taken from the
	// ipset data in ecn_in_(ect0|ect1|ce)-from-lan.
	IPECNFromLAN map[IPKey]ECNCounters

	// IPECNFromWAN is a map of IP addresses to ECNCounters, taken from the
	// ipset data in ecn_in_(ect0|ect1|ce)-from-wan.
	IPECNFromWAN map[IPKey]ECNCounters

	// IPFromLAN contains counters for IP packets from the WAN, documented in
	// the IPCounters struct.
	IPFromLAN IPCounters

	// IPFromWAN contains counters for IP packets from the WAN, documented in
	// the IPCounters struct.
	IPFromWAN IPCounters
}

func NewECNData() *ECNData {
	d := &ECNData{}
	d.TCPOut = make(map[IPKey]TCPCounters)
	d.TCPIn = make(map[IPKey]TCPCounters)
	d.CTOut = make(map[IPPortKey]CTCounters)
	d.CTIn = make(map[IPPortKey]CTCounters)
	d.IPECNFromLAN = make(map[IPKey]ECNCounters)
	d.IPECNFromWAN = make(map[IPKey]ECNCounters)
	return d
}

func (d *ECNData) UpdateTCPOut(ip net.IP, f func(*TCPCounters)) {
	ipk := IPToKey(ip)
	t := d.TCPOut[ipk]
	f(&t)
	d.TCPOut[ipk] = t
}

func (d *ECNData) UpdateTCPIn(ip net.IP, f func(*TCPCounters)) {
	ipk := IPToKey(ip)
	t := d.TCPIn[ipk]
	f(&t)
	d.TCPIn[ipk] = t
}

func (d *ECNData) UpdateCTOut(ipp IPPort, f func(*CTCounters)) {
	ippk := IPPortToKey(ipp)
	t := d.CTOut[ippk]
	f(&t)
	d.CTOut[ippk] = t
}

func (d *ECNData) UpdateCTIn(ipp IPPort, f func(*CTCounters)) {
	ippk := IPPortToKey(ipp)
	t := d.CTIn[ippk]
	f(&t)
	d.CTIn[ippk] = t
}

func (d *ECNData) UpdateECNFromLAN(ip net.IP, f func(*ECNCounters)) {
	ipk := IPToKey(ip)
	e := d.IPECNFromLAN[ipk]
	f(&e)
	d.IPECNFromLAN[ipk] = e
}

func (d *ECNData) UpdateECNFromWAN(ip net.IP, f func(*ECNCounters)) {
	ipk := IPToKey(ip)
	e := d.IPECNFromWAN[ipk]
	f(&e)
	d.IPECNFromWAN[ipk] = e
}

// ToJSONFile writes the ECNData to a json file.
func (d *ECNData) ToJSONFile(name string) error {
	o, err := os.Create(name)
	if err != nil {
		return err
	}
	defer o.Close()

	e := json.NewEncoder(o)
	e.SetIndent("", "  ")

	return e.Encode(d)
}

// ECNCounters contains ECN counters.
type ECNCounters struct {
	ECT0 Counters
	ECT1 Counters
	CE   Counters
}

// Add adds the counters in e2.
func (e *ECNCounters) Add(e2 *ECNCounters) {
	e.ECT0.Add(e2.ECT0)
	e.ECT1.Add(e2.ECT1)
	e.CE.Add(e2.CE)
}

// Sub subtracts the counters in e2.
func (e *ECNCounters) Sub(e2 *ECNCounters) {
	e.ECT0.Sub(e2.ECT0)
	e.ECT1.Sub(e2.ECT1)
	e.CE.Sub(e2.CE)
}

// ECNPackets returns the number of packets with any ECN codepoints set.
func (e *ECNCounters) ECNPackets() int64 {
	return e.ECT0.Packets + e.ECT1.Packets + e.CE.Packets
}

// Reset sets the counters to zero.
func (e *ECNCounters) Reset() {
	e.ECT0.Reset()
	e.ECT1.Reset()
	e.CE.Reset()
}

// Zero returns true if all the counters are zero.
func (e *ECNCounters) Zero() bool {
	return e.ECT0.Zero() && e.CE.Zero() && e.ECT1.Zero()
}

// TCPECNCounters contains IP ECN counters plus ECE.
type TCPECNCounters struct {
	ECNCounters
	ECE Counters
}

func (t *TCPECNCounters) Add(t2 *TCPECNCounters) {
	t.ECNCounters.Add(&t2.ECNCounters)
	t.ECE.Add(t2.ECE)
}

// TCPCounters contains counters for TCP.
type TCPCounters struct {
	AllSyn    Counters
	ECNSyn    Counters
	ECNSynAck Counters
	FromLAN   TCPECNCounters
	FromWAN   TCPECNCounters
}

// CTCounters contains counters for the conntrack supported protocols.
type CTCounters struct {
	FromLAN ECNCounters
	FromWAN ECNCounters
}

// Add adds counters from c2.
func (c *CTCounters) Add(c2 *CTCounters) {
	c.FromLAN.Add(&c2.FromLAN)
	c.FromWAN.Add(&c2.FromWAN)
}

// ECNPackets returns the number of packets with any ECN codepoints set.
func (c *CTCounters) ECNPackets() int64 {
	return c.FromLAN.ECNPackets() + c.FromWAN.ECNPackets()
}

// MaybeECN returns true if ECT(0) is nonzero in both directions.
func (c *CTCounters) MaybeECN() bool {
	return c.FromLAN.ECT0.Packets+c.FromWAN.ECT0.Packets > MaybeECNThreshold
}

// LikelyECN returns true if ECT(0) and CE are nonzero in opposite directions.
func (c *CTCounters) LikelyECN() bool {
	if !c.FromLAN.ECT0.Zero() && !c.FromWAN.CE.Zero() {
		return true
	}

	return !c.FromWAN.ECT0.Zero() && !c.FromLAN.CE.Zero()
}

// Reset sets the counters to zero.
func (c *CTCounters) Reset() {
	c.FromLAN.Reset()
	c.FromWAN.Reset()
}

// BidirActivity returns true if counters from LAN and WAN are both nonzero.
func (c *CTCounters) BidirActivity() bool {
	return !c.FromLAN.Zero() && !c.FromWAN.Zero()
}

//
// IP anonymization
//

type anonymizer struct {
	key  []byte
	xor4 []byte
	xor6 []byte
}

func newAnonymizer() *anonymizer {
	return &anonymizer{
		make([]byte, net.IPv6len),
		make([]byte, net.IPv4len),
		make([]byte, net.IPv6len),
	}
}

func createAnonymizer(zeroes4, zeroes6 int) (a *anonymizer) {
	a = newAnonymizer()
	if _, err := rand.Read(a.key); err != nil {
		fail(err.Error())
	}
	a.setupXor(zeroes4, zeroes6)
	return
}

func (a *anonymizer) setupXor(zeroes4, zeroes6 int) {
	for i := 0; i < len(a.key); i++ {
		if i < len(a.xor4) {
			a.xor4[i] = a.key[i]
		}
		a.xor6[i] = a.key[i]
	}

	for z, b, s := 0, 0, 0; z < zeroes4 && b < net.IPv4len; z++ {
		a.xor4[b] &= (0x80 >> s)
		s++
		if s == 8 {
			s = 0
			b++
		}
	}

	for z, b, s := 0, 0, 0; z < zeroes6 && b < net.IPv6len; z++ {
		a.xor6[b] &= (0x80 >> s)
		s++
		if s == 8 {
			s = 0
			b++
		}
	}
}

func anonFromString(s string, zeroes4, zeroes6 int) (a *anonymizer, err error) {
	var b []byte
	if b, err = hex.DecodeString(s); err != nil {
		return
	}
	if len(b) != net.IPv6len {
		err = fmt.Errorf("bad anonymizer key: '%s'", s)
		return
	}
	a = newAnonymizer()
	a.key = b
	a.setupXor(zeroes4, zeroes6)
	return
}

func (a anonymizer) String() string {
	return hex.EncodeToString(a.key)
}

// Transform xors the input IP with the anonymizer's key.
func (a anonymizer) Transform(ip net.IP) {
	if len(ip) == net.IPv4len {
		for i := 0; i < net.IPv4len; i++ {
			ip[i] ^= a.xor4[i]
		}
		return
	}
	if len(ip) != net.IPv6len {
		fail("impossible IP length: %d", len(ip))
	}
	for i := 0; i < net.IPv6len; i++ {
		ip[i] ^= a.xor6[i]
	}
	return
}

// setupAnon initializes IP anonymization from its flag value and key filename.
func setupAnon(keyFilename string) (err error) {
	anonStr := IPAnonymizationMask

	// parse mask
	if strings.HasPrefix(anonStr, "/") {
		anonStr = anonStr[1:]
	}
	var anonBits int
	if anonBits, err = strconv.Atoi(anonStr); err != nil {
		err = fmt.Errorf("bad anonymization mask: '%s'", IPAnonymizationMask)
		return
	}

	// if no existing key file, create new key
	if _, err = os.Stat(keyFilename); os.IsNotExist(err) {
		anon = createAnonymizer(anonBits, anonBits)
		err = ioutil.WriteFile(keyFilename, []byte(anon.String()), 0600)
		return
	}

	// read existing key file
	var kb []byte
	if kb, err = ioutil.ReadFile(keyFilename); err != nil {
		return
	}
	anon, err = anonFromString(string(kb), anonBits, anonBits)

	return
}

//
// chain parsing
//

// ChainLine contains the information parsed from one line of a chain.
type ChainLine struct {
	Counters
	Target   string
	Protocol string
	Comment  string
}

// ChainAdderFunc adds ipset values to ECNData.
type ChainAdderFunc func(l *ChainLine, d *ECNData)

var chainAdderNoOp = func(l *ChainLine, d *ECNData) {
}

// chainAdders defines the adders for each chain.
var chainAdders = map[string]ChainAdderFunc{
	"ecn_main": func(l *ChainLine, d *ECNData) {
		var c *Counters
		if l.Target == "ecn_from-lan" {
			c = &d.IPFromLAN.IP
		} else if l.Target == "ecn_from-wan" {
			c = &d.IPFromWAN.IP
		} else {
			return
		}

		c.Packets = l.Packets
		c.Bytes = l.Bytes
	},
	"ecn_from-lan": func(l *ChainLine, d *ECNData) {
		switch l.Protocol {
		case "tcp":
			d.IPFromLAN.TCP.Add(l.Counters)
		case "!tcp":
			d.IPFromLAN.NonTCP = l.Counters
		}
	},
	"ecn_from-wan": func(l *ChainLine, d *ECNData) {
		switch l.Protocol {
		case "tcp":
			d.IPFromWAN.TCP.Add(l.Counters)
		case "!tcp":
			d.IPFromWAN.NonTCP = l.Counters
		}
	},
	"ecn_ce-from-lan":   chainAdderNoOp,
	"ecn_ect1-from-lan": chainAdderNoOp,
	"ecn_ect0-from-lan": chainAdderNoOp,
	"ecn_ce-from-wan":   chainAdderNoOp,
	"ecn_ect1-from-wan": chainAdderNoOp,
	"ecn_ect0-from-wan": chainAdderNoOp,
	"ecn_in_syn":        chainAdderNoOp,
	"ecn_in_synack":     chainAdderNoOp,
	"ecn_in_from-lan":   chainAdderNoOp,
	"ecn_in_from-wan":   chainAdderNoOp,
	"ecn_out_syn":       chainAdderNoOp,
	"ecn_out_synack":    chainAdderNoOp,
	"ecn_out_from-lan":  chainAdderNoOp,
	"ecn_out_from-wan":  chainAdderNoOp,
}

// comment extracts the comment from a chain data line
func comment(s string) (c string) {
	start := strings.Index(s, "/* ")
	if start == -1 {
		return
	}
	start += 3
	end := strings.Index(s[start:], " */")
	if end == -1 {
		return
	}
	return s[start : start+end]
}

// parseChainEntry parses chain data from the chain_ files.
func parseChainEntry(r io.Reader, entry string, ecnData *ECNData) (err error) {
	s := bufio.NewScanner(r)

	// read header and discard next line
	s.Scan()
	h := strings.Fields(s.Text())
	name := h[1]
	s.Scan()

	adderFunc, ok := chainAdders[name]
	if !ok {
		log.Printf("Skipping chain '%s', no chainAdder defined", name)
		return
	}

	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 3 {
			err = fmt.Errorf("unexpected chain line: '%s'", s.Text())
			return
		}

		var l ChainLine
		if l.Packets, err = strconv.ParseInt(f[0], 10, 64); err != nil {
			return
		}
		if l.Bytes, err = strconv.ParseInt(f[1], 10, 64); err != nil {
			return
		}
		l.Target = f[2]
		l.Protocol = f[3]
		l.Comment = comment(s.Text())

		adderFunc(&l, ecnData)
	}
	err = s.Err()
	return
}

//
// ipset parsing
//

// IPSetAdderFunc adds ipset values to ECNData.
type IPSetAdderFunc func(k string, c Counters, d *ECNData)

// ipsetAdders defines the adder functions for each ipset.
var ipsetAdders = map[string]IPSetAdderFunc{

	// In:

	"ecn_in_all-syn": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPIn(toIP(k), func(t *TCPCounters) {
			t.AllSyn.Add(c)
		})
	},

	"ecn_in_ce-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPIn(toIP(k), func(t *TCPCounters) {
			t.FromLAN.CE.Add(c)
		})
	},

	"ecn_in_ce-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPIn(toIP(k), func(t *TCPCounters) {
			t.FromWAN.CE.Add(c)
		})
	},

	"ecn_in_ct-ce-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTIn(toIPPort(k), func(t *CTCounters) {
			t.FromLAN.CE.Add(c)
		})
	},

	"ecn_in_ct-ce-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTIn(toIPPort(k), func(t *CTCounters) {
			t.FromWAN.CE.Add(c)
		})
	},

	"ecn_in_ct-ect0-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTIn(toIPPort(k), func(t *CTCounters) {
			t.FromLAN.ECT0.Add(c)
		})
	},

	"ecn_in_ct-ect0-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTIn(toIPPort(k), func(t *CTCounters) {
			t.FromWAN.ECT0.Add(c)
		})
	},

	"ecn_in_ct-ect1-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTIn(toIPPort(k), func(t *CTCounters) {
			t.FromLAN.ECT1.Add(c)
		})
	},

	"ecn_in_ct-ect1-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTIn(toIPPort(k), func(t *CTCounters) {
			t.FromWAN.ECT1.Add(c)
		})
	},

	"ecn_in_ece-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPIn(toIP(k), func(t *TCPCounters) {
			t.FromLAN.ECE.Add(c)
		})
	},

	"ecn_in_ece-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPIn(toIP(k), func(t *TCPCounters) {
			t.FromWAN.ECE.Add(c)
		})
	},

	"ecn_in_ecn-syn": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPIn(toIP(k), func(t *TCPCounters) {
			t.ECNSyn.Add(c)
		})
	},

	"ecn_in_ecn-synack": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPIn(toIP(k), func(t *TCPCounters) {
			t.ECNSynAck.Add(c)
		})
	},

	"ecn_in_ect0-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPIn(toIP(k), func(t *TCPCounters) {
			t.FromLAN.ECT0.Add(c)
		})
	},

	"ecn_in_ect0-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPIn(toIP(k), func(t *TCPCounters) {
			t.FromWAN.ECT0.Add(c)
		})
	},

	"ecn_in_ect1-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPIn(toIP(k), func(t *TCPCounters) {
			t.FromLAN.ECT1.Add(c)
		})
	},

	"ecn_in_ect1-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPIn(toIP(k), func(t *TCPCounters) {
			t.FromWAN.ECT1.Add(c)
		})
	},

	// IP:

	"ecn_ip-ce-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateECNFromLAN(toIP(k), func(e *ECNCounters) {
			e.CE.Add(c)
		})
	},

	"ecn_ip-ce-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateECNFromWAN(toIP(k), func(e *ECNCounters) {
			e.CE.Add(c)
		})
	},

	"ecn_ip-ect0-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateECNFromLAN(toIP(k), func(e *ECNCounters) {
			e.ECT0.Add(c)
		})
	},

	"ecn_ip-ect0-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateECNFromWAN(toIP(k), func(e *ECNCounters) {
			e.ECT0.Add(c)
		})
	},

	"ecn_ip-ect1-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateECNFromLAN(toIP(k), func(e *ECNCounters) {
			e.ECT1.Add(c)
		})
	},

	"ecn_ip-ect1-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateECNFromWAN(toIP(k), func(e *ECNCounters) {
			e.ECT1.Add(c)
		})
	},

	// Out:

	"ecn_out_all-syn": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPOut(toIP(k), func(t *TCPCounters) {
			t.AllSyn.Add(c)
		})
	},

	"ecn_out_ce-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPOut(toIP(k), func(t *TCPCounters) {
			t.FromLAN.CE.Add(c)
		})
	},

	"ecn_out_ce-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPOut(toIP(k), func(t *TCPCounters) {
			t.FromWAN.CE.Add(c)
		})
	},

	"ecn_out_ct-ce-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTOut(toIPPort(k), func(ct *CTCounters) {
			ct.FromLAN.CE.Add(c)
		})
	},

	"ecn_out_ct-ce-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTOut(toIPPort(k), func(ct *CTCounters) {
			ct.FromWAN.CE.Add(c)
		})
	},

	"ecn_out_ct-ect0-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTOut(toIPPort(k), func(ct *CTCounters) {
			ct.FromLAN.ECT0.Add(c)
		})
	},

	"ecn_out_ct-ect0-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTOut(toIPPort(k), func(ct *CTCounters) {
			ct.FromWAN.ECT0.Add(c)
		})
	},

	"ecn_out_ct-ect1-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTOut(toIPPort(k), func(ct *CTCounters) {
			ct.FromLAN.ECT1.Add(c)
		})
	},

	"ecn_out_ct-ect1-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateCTOut(toIPPort(k), func(ct *CTCounters) {
			ct.FromWAN.ECT1.Add(c)
		})
	},

	"ecn_out_ece-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPOut(toIP(k), func(t *TCPCounters) {
			t.FromLAN.ECE.Add(c)
		})
	},

	"ecn_out_ece-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPOut(toIP(k), func(t *TCPCounters) {
			t.FromWAN.ECE.Add(c)
		})
	},

	"ecn_out_ecn-syn": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPOut(toIP(k), func(t *TCPCounters) {
			t.ECNSyn.Add(c)
		})
	},

	"ecn_out_ecn-synack": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPOut(toIP(k), func(t *TCPCounters) {
			t.ECNSynAck.Add(c)
		})
	},

	"ecn_out_ect0-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPOut(toIP(k), func(t *TCPCounters) {
			t.FromLAN.ECT0.Add(c)
		})
	},

	"ecn_out_ect0-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPOut(toIP(k), func(t *TCPCounters) {
			t.FromWAN.ECT0.Add(c)
		})
	},

	"ecn_out_ect1-from-lan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPOut(toIP(k), func(t *TCPCounters) {
			t.FromLAN.ECT1.Add(c)
		})
	},

	"ecn_out_ect1-from-wan": func(k string, c Counters, d *ECNData) {
		d.UpdateTCPOut(toIP(k), func(t *TCPCounters) {
			t.FromWAN.ECT1.Add(c)
		})
	},
}

// parseIPSetEntry parses ipset data from the ipset_ files.
func parseIPSetEntry(r io.Reader, entry string, ecnData *ECNData) (err error) {
	s := bufio.NewScanner(r)
	header := make(map[string]string)

	// read header
	for s.Scan() {
		f := strings.FieldsFunc(s.Text(), func(c rune) bool {
			return unicode.IsSpace(c) || c == ':'
		})

		if f[0] == "Members" {
			break
		}
		header[f[0]] = f[1]
	}

	name := header["Name"]
	if name == "" {
		err = fmt.Errorf("entry '%s' missing Name field", entry)
		return
	}

	addFunc, ok := ipsetAdders[name]
	if !ok {
		log.Printf("Skipping ipset '%s', no ipsetAdder defined", name)
		return
	}

	// read data
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) != 5 {
			err = fmt.Errorf("unexpected ipset line: '%s'", s.Text())
			return
		}

		key := f[0]
		c := Counters{}
		if c.Packets, err = strconv.ParseInt(f[2], 10, 64); err != nil {
			return
		}
		if c.Bytes, err = strconv.ParseInt(f[4], 10, 64); err != nil {
			return
		}

		addFunc(key, c, ecnData)
	}

	err = s.Err()
	return
}

//
// .tar.gz file processing
//

// parseEntry parses one entry from the .tar.gz file.
func parseEntry(reader io.Reader, entry string, ecnData *ECNData) (err error) {
	if strings.HasPrefix(entry, "ipset_ecn_") {
		log.Printf("Reading ipset from %s", entry)

		if err = parseIPSetEntry(reader, entry, ecnData); err != nil {
			return
		}
	} else if strings.HasPrefix(entry, "chain_") {
		log.Printf("Reading chain from %s", entry)
		if err = parseChainEntry(reader, entry, ecnData); err != nil {
			return
		}
	} else {
		log.Printf("Skipping entry %s", entry)
	}

	return
}

// parse reads the data from the .tar.gz file from "iptables-ecn save".
func parse(dataFile string) (ecnData *ECNData, err error) {
	var f *os.File
	if f, err = os.Open(dataFile); err != nil {
		return
	}
	defer f.Close()

	var r io.Reader
	if filepath.Ext(dataFile) == ".gz" {
		if r, err = gzip.NewReader(f); err != nil {
			return
		}
	} else {
		r = f
	}

	ecnData = NewECNData()
	tr := tar.NewReader(r)
	for {
		var hdr *tar.Header
		hdr, err = tr.Next()
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}
		entry := strings.TrimPrefix(hdr.Name, "./")
		if entry == "" {
			continue
		}

		if err = parseEntry(tr, entry, ecnData); err != nil {
			return
		}
	}
}

//
// stats analysis
//

func percent(divisor, dividend int64) float64 {
	return 100.0 * float64(divisor) / float64(dividend)
}

func ipow(a, b int64) int64 {
	var result int64 = 1

	for 0 != b {
		if 0 != (b & 1) {
			result *= a

		}
		b >>= 1
		a *= a
	}

	return result
}

func packetsWithUnits(packets int64) string {
	switch {
	case packets >= 1e12:
		return fmt.Sprintf("%.2f T", float64(packets)/1e12)
	case packets >= 1e9:
		return fmt.Sprintf("%.2f G", float64(packets)/1e9)
	case packets >= 1e6:
		return fmt.Sprintf("%.2f M", float64(packets)/1e6)
	default:
		return fmt.Sprintf("%d", packets)
	}
}

func bytesWithUnits(bytes int64) string {
	switch {
	case bytes >= ipow(1024, 6):
		return fmt.Sprintf("%.2f EB", float64(bytes)/math.Pow(1024, 6))
	case bytes >= ipow(1024, 5):
		return fmt.Sprintf("%.2f PB", float64(bytes)/math.Pow(1024, 5))
	case bytes >= ipow(1024, 4):
		return fmt.Sprintf("%.2f TB", float64(bytes)/math.Pow(1024, 4))
	case bytes >= ipow(1024, 3):
		return fmt.Sprintf("%.2f GB", float64(bytes)/math.Pow(1024, 3))
	case bytes >= ipow(1024, 2):
		return fmt.Sprintf("%.2f MB", float64(bytes)/math.Pow(1024, 2))
	case bytes >= 1024:
		return fmt.Sprintf("%.2f KB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%d", bytes)
	}
}

// ECNStats contains stats calculated from ECNData.
type ECNStats struct {
	TCPOut     TCPStats
	TCPIn      TCPStats
	CTOut      CTStats
	CTIn       CTStats
	IPFromLAN  IPStats
	IPFromWAN  IPStats
	IPFromBoth IPStats
	IPAll      IPCounters
}

// analyze analyzes the ECNData and returns an ECNStats.
func analyze(d *ECNData) (s *ECNStats) {
	s = new(ECNStats)

	// TCP
	s.TCPOut = *analyzeTCP(d.TCPOut)
	s.TCPIn = *analyzeTCP(d.TCPIn)

	// Conntrack
	s.CTOut = *analyzeCT(d.CTOut)
	s.CTIn = *analyzeCT(d.CTIn)

	// IP
	s.IPFromLAN = *analyzeIP(d, LAN)
	s.IPFromWAN = *analyzeIP(d, WAN)

	// IP stats from both directions
	s.IPFromBoth.Add(&s.IPFromLAN)
	s.IPFromBoth.Add(&s.IPFromWAN)

	// counters for all IP
	s.IPAll.Add(&d.IPFromLAN)
	s.IPAll.Add(&d.IPFromWAN)

	return
}

// TCPStats contains statistics for all TCP flows.
type TCPStats struct {
	AllIPs                      int64
	ActiveIPs                   int64
	IPsInitiatedECN             int64
	PercentIPsInitiatedECN      float64
	IPsNegotiatedECN            int64
	PercentIPsNegotiatedECN     float64
	IPsSawECNCongestion         int64
	PercentIPsSawCongestion     float64
	PercentECNIPsSawCongestion  float64
	IPsSawECT1                  int64
	AllSyns                     Counters
	ECNSyns                     Counters
	ECNSynAcks                  Counters
	EstPercentFlowsInitiatedECN float64
	EstPercentECNFlowsAccepted  float64
	TCPECNFromLAN               TCPECNCounters
	TCPECNFromWAN               TCPECNCounters
	ECNByIP                     map[IPKey]TCPCounters
}

func NewTCPStats() *TCPStats {
	s := &TCPStats{}
	s.ECNByIP = make(map[IPKey]TCPCounters)
	return s
}

func analyzeTCP(d map[IPKey]TCPCounters) (s *TCPStats) {
	s = NewTCPStats()

	for ip, tc := range d {
		s.AllIPs++
		if tc.AllSyn.Packets < ActiveIPSynThreshold {
			continue
		}

		s.ActiveIPs++
		s.AllSyns.Add(tc.AllSyn)
		s.ECNSyns.Add(tc.ECNSyn)
		s.ECNSynAcks.Add(tc.ECNSynAck)
		if tc.ECNSyn.Packets > 0 {
			s.IPsInitiatedECN++
		}
		if tc.ECNSynAck.Packets > 0 {
			s.IPsNegotiatedECN++
		}
		if tc.FromLAN.CE.Packets > 0 || tc.FromWAN.CE.Packets > 0 ||
			tc.FromLAN.ECE.Packets > 0 || tc.FromWAN.ECE.Packets > 0 {
			s.IPsSawECNCongestion++
			s.ECNByIP[ip] = tc
		}
		if tc.FromLAN.ECT1.Packets > 0 || tc.FromWAN.ECT1.Packets > 0 {
			s.IPsSawECT1++
		}
		s.TCPECNFromLAN.Add(&tc.FromLAN)
		s.TCPECNFromWAN.Add(&tc.FromWAN)
	}

	if s.AllSyns.Packets > 0 {
		s.EstPercentFlowsInitiatedECN = percent(s.ECNSyns.Packets,
			s.AllSyns.Packets)
	}
	if s.ECNSyns.Packets > 0 {
		s.EstPercentECNFlowsAccepted = percent(s.ECNSynAcks.Packets,
			s.ECNSyns.Packets)
	}

	if s.ActiveIPs > 0 {
		s.PercentIPsInitiatedECN = percent(s.IPsInitiatedECN, s.ActiveIPs)
		s.PercentIPsNegotiatedECN = percent(s.IPsNegotiatedECN, s.ActiveIPs)
		s.PercentIPsSawCongestion = percent(s.IPsSawECNCongestion, s.ActiveIPs)
	}

	if s.IPsNegotiatedECN > 0 {
		s.PercentECNIPsSawCongestion = percent(s.IPsSawECNCongestion,
			s.IPsNegotiatedECN)
	}

	return
}

func (s *TCPStats) Emit(orig Origination) {
	var initSense string
	var sentSense string
	if orig == Incoming {
		initSense = "Received"
		sentSense = "received"
	} else if orig == Outgoing {
		initSense = "initiated"
		sentSense = "sent"
	}

	var w *tableWriter

	fmt.Printf("    IP address counts with TCP and ECN activity:\n")
	fmt.Println()
	w = newTableWriter("        ")
	w.Printf("Active (%s >= %d SYNs):\t%d (of %d)",
		sentSense, ActiveIPSynThreshold, s.ActiveIPs, s.AllIPs)
	w.Printf("%s any ECN flows:\t%d (%.1f%%)",
		strings.Title(initSense), s.IPsInitiatedECN, s.PercentIPsInitiatedECN)
	w.Printf("Negotiated any ECN flows:\t%d (%.1f%%)",
		s.IPsNegotiatedECN, s.PercentIPsNegotiatedECN)
	w.Printf("Saw CE or ECE on ECN flow:\t%d (%.1f%% of ECN, %.1f%% of all)",
		s.IPsSawECNCongestion, s.PercentECNIPsSawCongestion,
		s.PercentIPsSawCongestion)
	w.Printf("Saw ECT(1) on ECN flow:\t%d", s.IPsSawECT1)
	w.Flush()

	fmt.Println()
	fmt.Printf("    SYN packet count totals for active IPs:\n")
	fmt.Println()
	w = newTableWriter("        ")
	w.Printf("All SYNs:\t%s", s.AllSyns)
	w.Printf("ECN SYNs:\t%s (%.2f%% of all)",
		s.ECNSyns, s.EstPercentFlowsInitiatedECN)
	w.Printf("ECN SYN/ACKs:\t%s (%.2f%% of ECN SYNs)",
		s.ECNSynAcks, s.EstPercentECNFlowsAccepted)
	w.Flush()

	fmt.Println()
	fmt.Printf("    ECN packet count totals for active IPs:\n")
	fmt.Println()
	w = newTableWriter("        ")
	w.URow("Direction", "CE", "ECE", "ECT(0)", "ECT(1)")
	w.Row("From LAN",
		s.TCPECNFromLAN.CE,
		s.TCPECNFromLAN.ECE,
		s.TCPECNFromLAN.ECT0,
		s.TCPECNFromLAN.ECT1)
	w.Row("From WAN",
		s.TCPECNFromWAN.CE,
		s.TCPECNFromWAN.ECE,
		s.TCPECNFromWAN.ECT0,
		s.TCPECNFromWAN.ECT1)
	w.Flush()

	if len(s.ECNByIP) > 0 {
		fmt.Println()
		fmt.Printf("    ECN congestion signals by active IP:\n")

		ips := make([]net.IP, 0, len(s.ECNByIP))
		for ipk := range s.ECNByIP {
			ips = append(ips, ipk.IP())
		}
		sort.Slice(ips,
			func(i, j int) bool { return IPLessThan(ips[i], ips[j]) })

		fmt.Println()
		w = newTableWriter("        ")
		//w.Row("", "CE", "ECE", "CE", "ECE")
		//w.Row("", "from", "from", "from", "from")
		w.URow("IP", "CE from WAN", "ECE from LAN", "CE from LAN",
			"ECE from WAN")
		for _, ip := range ips {
			td := s.ECNByIP[IPToKey(ip)]
			w.Row(ip,
				td.FromWAN.CE, td.FromLAN.ECE, td.FromLAN.CE, td.FromWAN.ECE)
		}
		w.Flush()
	}
}

// CTStats contains statistics for non-TCP, conntrack supported protocols.
type CTStats struct {
	ActiveIPs   int64
	Flows       int64
	ECNFromLAN  ECNCounters
	ECNFromWAN  ECNCounters
	ECNByIP     map[IPKey]CTCounters
	ECNByIPPort map[IPKey]map[Port]CTCounters
	ECNByPort   map[Port]CTCounters
}

func NewCTStats() *CTStats {
	s := &CTStats{}
	s.ECNByIP = make(map[IPKey]CTCounters)
	s.ECNByIPPort = make(map[IPKey]map[Port]CTCounters)
	s.ECNByPort = make(map[Port]CTCounters)
	return s
}

func analyzeCT(d map[IPPortKey]CTCounters) (s *CTStats) {
	s = NewCTStats()

	for ippk, ctc := range d {
		ipp := ippk.IPPort()
		s.ECNFromLAN.Add(&ctc.FromLAN)
		s.ECNFromWAN.Add(&ctc.FromWAN)

		ippa := ipp.IP
		if ictc, ok := s.ECNByIP[IPToKey(ippa)]; !ok {
			// create by IP
			s.ECNByIP[IPToKey(ippa)] = ctc

			// create by IP/port
			pm := make(map[Port]CTCounters)
			pm[ipp.Port] = ctc
			s.ECNByIPPort[IPToKey(ippa)] = pm
		} else {
			// add by IP
			ictc.Add(&ctc)
			s.ECNByIP[IPToKey(ippa)] = ictc

			// add by IP/port
			pm := s.ECNByIPPort[IPToKey(ippa)]
			p := ipp.Port
			if pctc, ok := pm[p]; !ok {
				pm[p] = ctc
			} else {
				pctc.Add(&ctc)
				pm[p] = pctc
			}
		}

		p := ipp.Port
		if pctc, ok := s.ECNByPort[p]; !ok {
			s.ECNByPort[p] = ctc
		} else {
			pctc.Add(&ctc)
			s.ECNByPort[p] = pctc
		}
	}

	// count active IPs and flows
	s.ActiveIPs = int64(len(s.ECNByIP))
	for _, m := range s.ECNByIPPort {
		s.Flows += int64(len(m))
	}

	return
}

// ECNByIPIPs returns a sorted slice of IPs in ECNByIPs.
func (s *CTStats) ECNByIPIPs() []net.IP {
	ips := make([]net.IP, 0, len(s.ECNByIP))
	for ipk := range s.ECNByIP {
		ips = append(ips, ipk.IP())
	}
	sort.Slice(ips,
		func(i, j int) bool { return IPLessThan(ips[i], ips[j]) })
	return ips
}

func (s *CTStats) Emit(orig Origination) {
	//var initSense string
	var clientSense string
	if orig == Incoming {
		//initSense = "received"
		clientSense = "server"
	} else if orig == Outgoing {
		//initSense = "initiated"
		clientSense = "client"
	}

	var w *tableWriter

	// emit stats on active IPs
	fmt.Printf("    Active IPs:\n")
	fmt.Println()
	w = newTableWriter("        ")
	w.Printf("Active IPs with ECN signals:\t%d", s.ActiveIPs)
	w.Printf("Active IP/dstport pairs with ECN signals:\t%d",
		s.Flows)
	w.Flush()

	// emit ECN packet count totals
	fmt.Println()
	fmt.Printf("    ECN packet count totals for active IPs:\n")
	fmt.Println()
	w = newTableWriter("        ")
	w.URow("Direction", "CE", "ECT(0)", "ECT(1)")
	w.Row("From LAN", s.ECNFromLAN.CE, s.ECNFromLAN.ECT0, s.ECNFromLAN.ECT1)
	w.Row("From WAN", s.ECNFromWAN.CE, s.ECNFromWAN.ECT0, s.ECNFromWAN.ECT1)
	w.Flush()

	// sortedPorts returns a sorted slice of ports from a map
	sortedPorts := func(m map[Port]CTCounters) []Port {
		ps := make([]Port, 0, len(m))
		for p := range m {
			ps = append(ps, p)
		}
		sort.Slice(ps,
			func(i, j int) bool { return ps[i].LessThan(ps[j]) })
		return ps
	}

	// emitECNByPortHeader emits the header for the ECN by port tables
	emitECNByPortHeader := func() {
		w.Row("", "ECT(0)", "CE", "ECT(1)", "ECT(0)", "CE", "ECT(1)")
		w.Row("", "from", "from", "from", "from", "from", "from")
		w.URow("Port", "LAN", "LAN", "LAN", "WAN", "WAN", "WAN")
	}

	// emitECNByPort emits the port rows, used in two places
	emitECNByPort := func(ctw *CTWriter, m map[Port]CTCounters) {
		ps := sortedPorts(m)

		r := 0
		for _, p := range ps {
			ctc := m[p]

			if r > 0 && r%EmitHeadersEvery == 0 {
				emitECNByPortHeader()
			}
			r++

			ctw.Push(p, &ctc)
		}
		ctw.Flush()
	}

	// emit ECN signals by IP and port
	if ShowConntrackPortsByIP && len(s.ECNByIP) > 0 {
		var portsShown string
		if CTInterestingByIP.Verbose {
			portsShown = "all"
		} else {
			portsShown = "selected"
		}

		fmt.Println()
		fmt.Printf("    ECN codepoint packet counts by %s IP, with %s ports:\n",
			clientSense, portsShown)

		if CTNoteworthyByIP.MaybeECN {
			fmt.Printf("        (ports with '*' had >%d ECT(0) marks)\n",
				MaybeECNThreshold)
		}

		ips := s.ECNByIPIPs()

		fmt.Println()

		r := 0
		w = newTableWriter("        ")
		for _, ip := range ips {
			ipk := IPToKey(ip)
			ctc := s.ECNByIP[ipk]

			if r%EmitHeadersEvery == 0 {
				w.Row("", "ECT(0)", "CE", "ECT(1)", "ECT(0)", "CE", "ECT(1)")
				w.Row("", "from", "from", "from", "from", "from", "from")
				w.URow("IP/Port", "LAN", "LAN", "LAN", "WAN", "WAN", "WAN")
			}
			r++

			w.Row(ip, ctc.FromLAN.ECT0, ctc.FromLAN.CE, ctc.FromLAN.ECT1,
				ctc.FromWAN.ECT0, ctc.FromWAN.CE, ctc.FromWAN.ECT1)

			ctw := NewCTWriter(w, "  ",
				CTInterestingByIP, CTUninterestingByIP, CTNoteworthyByIP)
			emitECNByPort(ctw, s.ECNByIPPort[ipk])
		}
		w.Flush()
	}

	// emit ECN signals by port
	if ShowConntrackPortsByPort && len(s.ECNByPort) > 0 {
		fmt.Println()
		fmt.Printf("    ECN codepoint packet counts for selected ports:\n")

		fmt.Println()
		w = newTableWriter("        ")
		emitECNByPortHeader()

		ctw := NewCTWriter(w, "", CTInterestingByPort, CTUninterestingByPort,
			CTNoteworthyByPort)
		emitECNByPort(ctw, s.ECNByPort)
		w.Flush()
	}
}

// CTNoteworthy tests CTCounter rows to select for highlighting.
type CTNoteworthy struct {
	// MaybeECN means all rows with nonzero ECT(0) in both directions.
	MaybeECN bool

	// LikelyECN means all rows with ECT(0) and CE in opposite dirs.
	LikelyECN bool
}

// Is returns true if the row is noteworthy.
func (n *CTNoteworthy) Is(p Port, ctc *CTCounters) bool {
	if n.MaybeECN && ctc.MaybeECN() {
		return true
	}

	if n.LikelyECN && ctc.LikelyECN() {
		return true
	}

	return false
}

// CTInteresting tests CTCounter rows to select for display.
type CTInteresting struct {
	// Verbose, if true, means show all rows
	Verbose bool

	// WellKnown means show all port numbers >=0 and <1024.
	WellKnown bool

	// Known means show all ports with entries in /etc/services.
	Known bool

	// BidirActivity means show all rows with ECN signals both ways.
	BidirActivity bool

	// MinSignals means show all rows with at least this number of signals.
	MinSignals int64

	// MaybeECN means show all rows with nonzero ECT(0) in both directions.
	MaybeECN bool

	// LikelyECN means show all rows with ECT(0) and CE in opposite directions.
	LikelyECN bool

	// Ports is a list of interesting ports.
	Ports []int
}

// Is returns true if the row is "interesting".
func (i *CTInteresting) Is(p Port, ctc *CTCounters) bool {
	if i.Verbose {
		return true
	}

	if i.WellKnown && p.WellKnown() {
		return true
	}

	if i.Known && p.Known() {
		return true
	}

	if i.BidirActivity && ctc.BidirActivity() {
		return true
	}

	if i.MinSignals > 0 && ctc.ECNPackets() >= i.MinSignals {
		return true
	}

	if i.MaybeECN && ctc.MaybeECN() {
		return true
	}

	if i.LikelyECN && ctc.LikelyECN() {
		return true
	}

	if p.NumOneOf(i.Ports) {
		return true
	}

	return false
}

// CTUninteresting tests CTCounter rows for exclusion from display.
type CTUninteresting struct {
	// PortPrefixes is a list of port string prefixes to exclude.
	PortPrefixes []string

	// Ranges means to exclude ranges of otherwise uninteresting ports.
	Ranges bool
}

// Is returns true if the row is "uninteresting".
func (u *CTUninteresting) Is(p Port, ctc *CTCounters) bool {
	for _, x := range u.PortPrefixes {
		if strings.HasPrefix(p.Str, x) {
			return true
		}
	}

	return false
}

// CTWriter writes CTCounters rows, compressing successive "uninteresting"
// rows where the protocol doesn't change onto one line.
type CTWriter struct {
	*tableWriter
	portPrefix    string
	interesting   CTInteresting
	uninteresting CTUninteresting
	noteworthy    CTNoteworthy

	startPort  *Port
	priorPort  *Port
	accum      CTCounters
	accumPorts int
}

// NewCTWriter returns a new CTWriter for the given underlying writer.
func NewCTWriter(w *tableWriter, portPrefix string, i CTInteresting,
	u CTUninteresting, n CTNoteworthy) *CTWriter {
	return &CTWriter{
		tableWriter:   w,
		portPrefix:    portPrefix,
		interesting:   i,
		uninteresting: u,
		noteworthy:    n,
	}
}

// Push adds one row, and emits it and prior rows on "interesting" rows.
func (w *CTWriter) Push(p Port, ctc *CTCounters) {
	// if line is "interesting", flush and display
	if w.interesting.Is(p, ctc) {
		w.Flush()
		pname, _ := p.DisplayName()
		if !w.uninteresting.Is(p, ctc) {
			highlight := w.noteworthy.Is(p, ctc)
			w.Row(pname, ctc, highlight)
		}
		return
	}

	// if the protocol changed from a prior port, flush
	if w.priorPort != nil && !p.SameProto(*w.startPort) {
		w.Flush()
	}

	// set start and prior ports and accumulate
	if w.startPort == nil {
		w.startPort = &p
	}
	w.priorPort = &p
	w.accum.Add(ctc)
	w.accumPorts++
}

// Row emits a row.
func (w *CTWriter) Row(p string, ctc *CTCounters, highlight bool) {
	prefix := w.portPrefix
	if highlight {
		if len(prefix) > 1 {
			r := []rune(prefix)
			r[0] = '*'
			prefix = string(r)
		} else {
			prefix = "* " + prefix
		}
	}

	w.tableWriter.Row(prefix+p,
		ctc.FromLAN.ECT0, ctc.FromLAN.CE, ctc.FromLAN.ECT1,
		ctc.FromWAN.ECT0, ctc.FromWAN.CE, ctc.FromWAN.ECT1)
}

// Flush writes any accumulated results.
func (w *CTWriter) Flush() {
	if w.startPort == nil || w.priorPort == nil {
		return
	}

	acc := &w.accum

	// display start port to prior port and accumulated results
	if !w.uninteresting.Ranges {
		r := PortRange{*w.startPort, *w.priorPort}
		w.Row(fmt.Sprintf("%s [%d]", r.String(), w.accumPorts), acc, false)
	}

	w.startPort = nil
	w.priorPort = nil
	w.accumPorts = 0
	acc.Reset()
}

// IPStats contains statistics for all IP packets.
type IPStats struct {
	// IPECN counts all ECN marked packets, taken by adding up the values in
	// the IPECN map, which comes from the ipset data.
	IPECN ECNCounters

	// TCPECN counts all ECN marked TCP packets, taken by adding up the values
	// in the TCPECN maps depending on the "from" being analyzed.
	TCPECN TCPECNCounters

	// CTECN counts all ECN marked packets for conntrack supported protocols,
	// taken by adding up the values in the CTECN maps depending on the "from"
	// being analyzed.
	CTECN ECNCounters

	// OtherECN counts ECN marked packets for protocols other than TCP and
	// conntrack-supported, taken by subtracting TCPECN and CTECN from IPECN.
	OtherECN ECNCounters
}

// analyzeIP calculates IPStats from the ECNData.
func analyzeIP(d *ECNData, from From) (s *IPStats) {
	var iem map[IPKey]ECNCounters

	switch from {
	case LAN:
		iem = d.IPECNFromLAN
	case WAN:
		iem = d.IPECNFromWAN
	}

	s = new(IPStats)

	// IP
	for _, c := range iem {
		s.IPECN.Add(&c)
	}

	// TCP
	for _, tc := range d.TCPOut {
		switch from {
		case LAN:
			s.TCPECN.Add(&tc.FromLAN)
		case WAN:
			s.TCPECN.Add(&tc.FromWAN)
		}
	}
	for _, tc := range d.TCPIn {
		switch from {
		case LAN:
			s.TCPECN.Add(&tc.FromLAN)
		case WAN:
			s.TCPECN.Add(&tc.FromWAN)
		}
	}

	// conntrack
	for _, ctc := range d.CTOut {
		switch from {
		case LAN:
			s.CTECN.Add(&ctc.FromLAN)
		case WAN:
			s.CTECN.Add(&ctc.FromWAN)
		}
	}
	for _, ctc := range d.CTIn {
		switch from {
		case LAN:
			s.CTECN.Add(&ctc.FromLAN)
		case WAN:
			s.CTECN.Add(&ctc.FromWAN)
		}
	}

	// other ECN
	s.OtherECN = s.IPECN
	s.OtherECN.Sub(&s.TCPECN.ECNCounters)
	s.OtherECN.Sub(&s.CTECN)

	return
}

// Add adds IPStats in s2 to the current.
func (s *IPStats) Add(s2 *IPStats) {
	s.IPECN.Add(&s2.IPECN)
	s.TCPECN.Add(&s2.TCPECN)
	s.CTECN.Add(&s2.CTECN)
	s.OtherECN.Add(&s2.OtherECN)
}

// Emit prints the IPStats as text to stdout.
func (s *IPStats) Emit(ipc IPCounters) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	// table of all bytes and packets, TCP, Non-TCP and Total
	w := newTableTabWriter(tw, "        ")
	w.URow("", "TCP", "Conntrack [*]", "Other", "Total")
	w.Row("Bytes",
		bytesWithUnits(ipc.TCP.Bytes),
		"->",
		bytesWithUnits(ipc.NonTCP.Bytes),
		bytesWithUnits(ipc.IP.Bytes))
	w.Row("Packets",
		packetsWithUnits(ipc.TCP.Packets),
		"->",
		packetsWithUnits(ipc.NonTCP.Packets),
		packetsWithUnits(ipc.IP.Packets))
	w.Row("|-CE",
		packetsWithUnits(s.TCPECN.CE.Packets),
		packetsWithUnits(s.CTECN.CE.Packets),
		packetsWithUnits(s.OtherECN.CE.Packets),
		packetsWithUnits(s.IPECN.CE.Packets))
	w.Row("|-ECT(0)",
		packetsWithUnits(s.TCPECN.ECT0.Packets),
		packetsWithUnits(s.CTECN.ECT0.Packets),
		packetsWithUnits(s.OtherECN.ECT0.Packets),
		packetsWithUnits(s.IPECN.ECT0.Packets))
	w.Row("|-ECT(1)",
		packetsWithUnits(s.TCPECN.ECT1.Packets),
		packetsWithUnits(s.CTECN.ECT1.Packets),
		packetsWithUnits(s.OtherECN.ECT1.Packets),
		packetsWithUnits(s.IPECN.ECT1.Packets))
	w.Flush()
}

//
// stats output
//

func emitStats(d *ECNData, s *ECNStats) {
	UPrintf("All IP")
	fmt.Println()
	fmt.Println("    Packets, CE, ECT(0) and ECT(1) are packet counts, and use")
	fmt.Println("    units of M, G or T for mega, giga, or terapackets.")
	fmt.Println()
	fmt.Println("    Total (both directions):")
	fmt.Println()
	s.IPFromBoth.Emit(s.IPAll)

	fmt.Println()
	fmt.Println("    WAN to LAN:")
	fmt.Println()
	s.IPFromWAN.Emit(d.IPFromWAN)

	fmt.Println()
	fmt.Println("    LAN to WAN:")
	fmt.Println()
	s.IPFromLAN.Emit(d.IPFromLAN)

	fmt.Println()
	fmt.Printf("        [*] Conntrack protocols: %s\n", conntrackProtocols)
	fmt.Printf("            Conntrack total Bytes and Packets included in Other\n")

	if ShowLANtoWAN {
		fmt.Println()
		UPrintf("TCP initiated from LAN to WAN")
		fmt.Println()
		s.TCPOut.Emit(Outgoing)
	}

	if ShowWANtoLAN {
		fmt.Println()
		UPrintf("TCP initiated from WAN to LAN")
		fmt.Println()
		s.TCPIn.Emit(Incoming)
	}

	emitCTProtocols := func() {
		fmt.Printf("    Protocols included:\n")
		fmt.Println()
		fmt.Printf("        %s\n", conntrackProtocols)
	}

	if ShowLANtoWAN {
		fmt.Println()
		UPrintf("Non-TCP conntrack-supported protocols initiated from LAN to WAN")
		fmt.Println()
		emitCTProtocols()
		fmt.Println()
		s.CTOut.Emit(Outgoing)
	}

	if ShowWANtoLAN {
		fmt.Println()
		UPrintf("Non-TCP conntrack-supported protocols initiated from WAN to LAN")
		fmt.Println()
		emitCTProtocols()
		fmt.Println()
		s.CTIn.Emit(Incoming)
	}
}

//
// main
//

// fail logs an error and exits
func fail(f string, a ...interface{}) {
	log.Fatalf("ERROR: "+f, a...)
}

// outputFilename returns an output filename given the data filename.
func outputFilename(dataFilename, ext string) (of string) {
	of = strings.TrimSuffix(dataFilename, ".gz")
	of = strings.TrimSuffix(of, ".tar")
	of += ext
	return
}

// usage emits program usage
func usage() {
	p := func(f string, a ...interface{}) {
		fmt.Fprintf(flag.CommandLine.Output(), f+"\n", a...)
	}

	p("usage: ecn-stats <-anon> ecn_data_xxx.tar.gz|.tar")
	p("")
	flag.PrintDefaults()
}

// main is the entry point
func main() {
	var format string

	// flags
	flag.Usage = usage
	flag.StringVar(&format, "format", "default",
		"output format, one of default, draft or full")
	flag.Parse()

	// set up output format
	if f, ok := Formats[format]; ok {
		f()
	} else {
		fail("unknown format: '%s'", format)
	}

	// args
	if len(flag.Args()) == 0 {
		usage()
		os.Exit(1)
	}
	dataFilename := flag.Args()[0]

	// logging
	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	// set up anonymization
	if IPAnonymizationMask != "" {
		keyFilename := outputFilename(dataFilename, ".key")
		if err := setupAnon(keyFilename); err != nil {
			fail(err.Error())
		}
	}

	// parse .tar.gz file into ECNData struct
	ecnData, err := parse(dataFilename)
	if err != nil {
		fail(err.Error())
	}

	// write ECNData as json
	jsonFilename := outputFilename(dataFilename, ".json")
	log.Printf("Writing %s", jsonFilename)
	if err = ecnData.ToJSONFile(jsonFilename); err != nil {
		fail(err.Error())
	}

	// analyze ECNData
	ecnStats := analyze(ecnData)

	// emit ECNStats in textual form
	emitStats(ecnData, ecnStats)
}
