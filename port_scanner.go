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
var host string
var low_port, high_port int
var verbose = false
var range_supplied = false
var top_100 = [100]string{"7", "9", "13", "21", "22", "23", "25", "26", "37", "53", "79", "80", "81", "88", "106", "110", "111", "113", "119", "135", "139", "143", "144", "179", "199", "389", "427", "443", "444", "445", "465", "513", "514", "515", "543", "544", "548", "554", "587", "631", "646", "873", "990", "993", "995", "1025", "1026", "1027", "1028", "1029", "1110", "1433", "1720", "1723", "1755", "1900", "2000", "2001", "2049", "2121", "2717", "3000", "3128", "3306", "3389", "3986", "4899", "5000", "5009", "5051", "5060", "5101", "5190", "5357", "5432", "5631", "5666", "5800", "5900", "6000", "6001", "6646", "7070", "8000", "8008", "8009", "8080", "8081", "8443", "8888", "9100", "9999", "10000", "32768", "49152", "49153", "49154", "49155", "49156", "49157"}

func main() {
	start := time.Now()

	to_scan_ch := make(chan string, threads + 1)
	open_ch := make(chan string, threads + 1)
	closed_ch := make(chan string, threads + 1)
	total_ports := 100

	for i := 0; i < threads; i++ {
		go scanner(to_scan_ch, open_ch, closed_ch)
	}

	if range_supplied {
		total_ports = high_port - low_port + 1
		go add_port_range(to_scan_ch)
	} else {
		go add_top_100(to_scan_ch)
	}
	fmt.Printf("Scanning %d ports on %s, with %d threads across %d CPU cores...\n\n", total_ports, host, threads, maxprocs)

	// Wait and print results of all the ports we're scanning.
	for i := 0; i < total_ports; i++ {
		select {
		case open_msg := <-open_ch:
			fmt.Printf("OPEN: %s\n", open_msg)
		case closed_msg := <-closed_ch:
			if verbose {
				fmt.Printf("closed: %s\n", closed_msg)
			}
		}
	}
	fmt.Println("\nScan completed in", time.Since(start))
}

func add_top_100(to_scan_ch chan<- string) {
	for _, port := range top_100 {
		to_scan_ch <- net.JoinHostPort(host, port)
	}
	close(to_scan_ch)
}

func add_port_range(to_scan_ch chan<- string) {
	for port := low_port; port <= high_port; port++ {
		to_scan_ch <- net.JoinHostPort(host, strconv.Itoa(port))
	}
	close(to_scan_ch)
}

func scanner(ports_ch <-chan string, open_ch, closed_ch chan<- string) {
	for hostport := range ports_ch {
		conn, err := net.DialTimeout("tcp", hostport, timeout)
		if err != nil {
			closed_ch <- err.Error()
		} else {
			if verbose {
				conn.SetReadDeadline(time.Now().Add(timeout))
				banner, err := bufio.NewReader(conn).ReadString('\n')
				if err == nil {
					hostport = fmt.Sprintf("%s: Banner: %s", hostport, banner)
				} else {
					hostport = fmt.Sprintf("%s: No banner returned: %s", hostport, err.Error())
				}
			}
			conn.Close()
			open_ch <- hostport
		}
	}
}

func init() {
	flag.Usage = usage

	flag.IntVar(&threads, "n", threads, "number of goroutines to use")
	flag.IntVar(&maxprocs, "c", maxprocs, "maximum number of CPU cores to spread the work across")
	flag.DurationVar(&timeout, "t", timeout, "connection timeout")
	flag.BoolVar(&verbose, "v", verbose, "print closed port reasons and open port banners")

	flag.Parse()

	host = flag.Arg(0)
	IPs, _ := net.LookupHost(host)
	if len(IPs) < 1 {
		fmt.Fprintln(os.Stderr, "Invalid host specified:", host)
		os.Exit(1)
	} else if verbose {
		fmt.Printf("Host %s has the following IP addresses:\n %v\n", host, IPs)
	}

	if flag.NArg() > 1 {
		low_arg, eLow := strconv.ParseInt(flag.Arg(1), 10, 32)
		high_arg, eHigh := strconv.ParseInt(flag.Arg(2), 10, 32)
		if eLow != nil || (flag.NArg() > 2 && eHigh != nil) {
			fmt.Fprintln(os.Stderr, "Invalid port argument(s) for range. Must be numeric.")
			os.Exit(1)
		}
		if high_arg < low_arg {
			high_arg = low_arg
		}
		low_port = int(low_arg)
		high_port = int(high_arg)
		range_supplied = true
	}
	

	runtime.GOMAXPROCS(maxprocs)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] hostname [low_port] [high_port]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Will scan nmap's top 100 ports if no low or high port are given.")
	flag.PrintDefaults()
}
