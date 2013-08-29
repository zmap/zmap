/*
TCP banner grabber, implemented in go

This program will make TCP connections to IP addresses provided on
stdin, optionally send a short message, and wait for responses. Each
response is printed to stdout, along with the responding host's IP
address. Status messages appear on stderr.
*/

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

var (
	nConnectFlag = flag.Int("concurrent", 100, "Number of concurrent connections")
	portFlag     = flag.String("port", "80", "Destination port")
	formatFlag   = flag.String("format", "ascii", "Output format for responses ('ascii', 'hex', or 'base64')")
	timeoutFlag  = flag.Int("timeout", 4, "Seconds to wait for each host to respond")
	dataFileFlag = flag.String("data", "", "File containing message to send to responsive hosts ('%s' will be replaced with host IP)")
)

var messageData = make([]byte, 0) // data read from file specified with dataFile flag

// Before running main, parse flags and load message data, if applicable
func init() {
	flag.Parse()
	if *dataFileFlag != "" {
		fi, err := os.Open(*dataFileFlag)
		if err != nil {
			panic(err)
		}
		buf := make([]byte, 1024)
		n, err := fi.Read(buf)
		messageData = buf[0:n]
		if err != nil && err != io.EOF {
			panic(err)
		}
		fi.Close()
	}
	// Increase file descriptor limit
	rlimit := syscall.Rlimit{Max: uint64(*nConnectFlag + 4), Cur: uint64(*nConnectFlag + 4)}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting rlimit: %s", err)
	}
}

type resultStruct struct {
	addr string // address of remote host
	data []byte // data returned from the host, if successful
	err  error  // error, if any
}

// Read addresses from addrChan and grab banners from these hosts.
// Sends resultStructs to resultChan.  Writes to doneChan when complete.
func grabber(addrChan chan string, resultChan chan resultStruct, doneChan chan int) {
	for addr := range addrChan {
		deadline := time.Now().Add(time.Duration(*timeoutFlag) * time.Second)
		dialer := net.Dialer{Deadline: deadline}
		conn, err := dialer.Dial("tcp", net.JoinHostPort(addr, *portFlag))
		if err != nil {
			resultChan <- resultStruct{addr, nil, err}
			continue
		}
		conn.SetDeadline(deadline)
		if len(messageData) > 0 {
			s := strings.Replace(string(messageData), "%s", addr, -1)
			if _, err := conn.Write([]byte(s)); err != nil {
				conn.Close()
				resultChan <- resultStruct{addr, nil, err}
				continue
			}
		}
		var buf [1024]byte
		n, err := conn.Read(buf[:])
		conn.Close()
		if err != nil && (err != io.EOF || n == 0) {
			resultChan <- resultStruct{addr, nil, err}
			continue
		}
		resultChan <- resultStruct{addr, buf[0:n], nil}
	}
	doneChan <- 1
}

// Read resultStructs from resultChan, print output, and maintain
// status counters.  Writes to doneChan when complete.
func output(resultChan chan resultStruct, doneChan chan int) {
	ok, timeout, error := 0, 0, 0
	for result := range resultChan {
		if result.err == nil {
			switch *formatFlag {
			case "hex":
				fmt.Printf("%s: %s\n", result.addr,
					hex.EncodeToString(result.data))
			case "base64":
				fmt.Printf("%s: %s\n", result.addr,
					base64.StdEncoding.EncodeToString(result.data))
			default:
				fmt.Printf("%s: %s\n", result.addr,
					string(result.data))
			}
			ok++
		} else if nerr, ok := result.err.(net.Error); ok && nerr.Timeout() {
			fmt.Fprintf(os.Stderr, "%s: Timeout\n", result.addr)
			timeout++
		} else {
			fmt.Fprintf(os.Stderr, "%s: Error %s\n", result.addr, result.err)
			error++
		}
	}
	fmt.Fprintf(os.Stderr, "Complete (OK=%d, timeout=%d, error=%d)\n",
		ok, timeout, error)
	doneChan <- 1
}

func main() {
	addrChan := make(chan string, *nConnectFlag)         // pass addresses to grabbers
	resultChan := make(chan resultStruct, *nConnectFlag) // grabbers send results to output
	doneChan := make(chan int, *nConnectFlag)            // let grabbers signal completion

	// Start grabbers and output thread
	go output(resultChan, doneChan)
	for i := 0; i < *nConnectFlag; i++ {
		go grabber(addrChan, resultChan, doneChan)
	}

	// Read addresses from stdin and pass to grabbers
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		addrChan <- scanner.Text()
	}
	close(addrChan)

	// Wait for completion
	for i := 0; i < *nConnectFlag; i++ {
		<-doneChan
	}
	close(resultChan)
	<-doneChan
}
