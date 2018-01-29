# port_scanner.go
Like port_scanner.py, but in Go (golang).

Very simple TCP connect (not SYN) port scanner.
Uses goroutines to add both concurrency and parallelism on machines with multiple CPUs/cores.

```
CarpeNoctem@github:~$ go build port_scanner.go 
hiro@macbook-pro:~$ ./port_scanner -h
Usage: ./port_scanner [options] hostname [low_port] [high_port]
Will scan nmap's top 100 ports if no low or high port are given.
  -c int
        maximum number of CPU cores to spread the work across (default 4)
  -n int
        number of goroutines to use (default 4)
  -t duration
        connection timeout (default 200ms)
  -v	print closed port reasons and open port banners
```
