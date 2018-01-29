package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"
)

var timeout = time.Millisecond * 200
var maxprocs = runtime.NumCPU()
var threads = maxprocs
var host, low_port, high_port string
var verbose = false
var top_100 = [100]string{"7", "9", "13", "21", "22", "23", "25", "26", "37", "53", "79", "80", "81", "88", "106", "110", "111", "113", "119", "135", "139", "143", "144", "179", "199", "389", "427", "443", "444", "445", "465", "513", "514", "515", "543", "544", "548", "554", "587", "631", "646", "873", "990", "993", "995", "1025", "1026", "1027", "1028", "1029", "1110", "1433", "1720", "1723", "1755", "1900", "2000", "2001", "2049", "2121", "2717", "3000", "3128", "3306", "3389", "3986", "4899", "5000", "5009", "5051", "5060", "5101", "5190", "5357", "5432", "5631", "5666", "5800", "5900", "6000", "6001", "6646", "7070", "8000", "8008", "8009", "8080", "8081", "8443", "8888", "9100", "9999", "10000", "32768", "49152", "49153", "49154", "49155", "49156", "49157"}

func main() {
	parse_args()
	IPs, _ := net.LookupHost(host)
	if len(IPs) < 1 {
		fmt.Fprintln(os.Stderr, "Invalid host specified:", host)
		return
	} else if verbose {
		fmt.Printf("Host %s has the following IP addresses:\n %v\n", host, IPs)
	}
	runtime.GOMAXPROCS(maxprocs)
	var open_ports []string

	start := time.Now()

	// If no port range is specified, scan nmap's top 100.
	// If only a single port is given, just scan that one.
	// If both a low and high port are given, scan that range.
	if low_port == "" {
		open_ports = distribute_work(0, len(top_100), scan_slice_of_ports)
	} else if high_port == "" {
		fmt.Printf("Scanning port %v on %s\n\n", low_port, host)
		if is_tcp_port_open(host, low_port) {
			open_ports = []string{low_port}
		} else {
			fmt.Printf("closed: %s:%s\n", host, low_port)
		}
	} else {
		low, eLow := strconv.ParseInt(low_port, 10, 32)
		high, eHigh := strconv.ParseInt(high_port, 10, 32)
		if eLow != nil || eHigh != nil || low > high {
			fmt.Fprintln(os.Stderr, "Invalid port argument(s) for range. Must be numeric.")
			return
		}
		open_ports = distribute_work(int(low), int(high), scan_range_of_ports)
	}

	for _, port := range open_ports {
		fmt.Printf("OPEN: %s:%s\n", host, port)
	}
	fmt.Println("\nScan completed in", time.Since(start))
}

func distribute_work(min, max int, check_func func(open_ch chan []string, lower, upper int)) (open_ports []string) {
	if threads > max-min+1 {
		threads = max - min + 1
	}
	fmt.Printf("Scanning %d ports on %s, with %d threads across %d CPU cores...\n\n", max-min+1, host, threads, maxprocs)
	open_ch := make(chan []string, threads)
	high := min - 1
	for i := 0; i < threads; i++ {
		low := high + 1
		high = min + (i+1)*(max-min)/threads
		go check_func(open_ch, low, high)
	}
	for i := 0; i < threads; i++ {
		result := <-open_ch
		open_ports = append(open_ports, result...)
	}
	return open_ports
}

func scan_slice_of_ports(open_ch chan []string, lower, upper int) {
	if upper < len(top_100) {
		upper = upper + 1
	}
	ports := top_100[lower:upper]
	var open []string
	for _, port := range ports {
		if is_tcp_port_open(host, port) {
			open = append(open, port)
		}
	}
	open_ch <- open
}

func scan_range_of_ports(open_ch chan []string, lower, upper int) {
	var open []string
	for port := lower; port <= upper; port++ {
		port_s := strconv.Itoa(port)
		if is_tcp_port_open(host, port_s) {
			open = append(open, port_s)
		}
	}
	open_ch <- open
}

// port can be numeric or a service name. e.g. http, ssh, etc.
func is_tcp_port_open(host, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		if verbose {
			fmt.Println("-", err)
		}
		return false
	}
	defer conn.Close()
	if verbose {
		banner, err := bufio.NewReader(conn).ReadString('\n')
		fmt.Printf("- Port %s open: %s %v\n", port, banner, err)
	}
	return true
}

func parse_args() {
	flag.Usage = usage

	flag.IntVar(&threads, "n", threads, "number of goroutines to use")
	flag.IntVar(&maxprocs, "c", maxprocs, "maximum number of CPU cores to spread the work across")
	flag.DurationVar(&timeout, "t", timeout, "connection timeout")
	flag.BoolVar(&verbose, "v", verbose, "print closed port reasons and open port banners")

	flag.Parse()

	host = flag.Arg(0)
	low_port = flag.Arg(1)
	high_port = flag.Arg(2)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] hostname [low_port] [high_port]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Will scan nmap's top 100 ports if no low or high port are given.")
	flag.PrintDefaults()
}
