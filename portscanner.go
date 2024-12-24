package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxWorkers      = 500              // Reasonable number of workers for concurrency
	timeout         = 2 * time.Second  // Adjusted timeout for reliability
	resolveRetries  = 3                // Retries for DNS resolution
	resolveDelay    = 200 * time.Millisecond // Delay between retries for DNS resolution
)

// Resolve domain to IP address with retries
func resolveDomain(domain string) string {
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	var resolvedIP string
	for i := 0; i < resolveRetries+2; i++ { // Increase retries
		ips, err := net.LookupHost(domain)
		if err == nil && len(ips) > 0 {
			resolvedIP = ips[0]
			break
		}
		// Removed DNS resolution error message
		time.Sleep(resolveDelay * 2) // Increased delay between retries
	}
	return resolvedIP
}


// Check if a specific port is open
func checkPort(ip string, port int, openPortsChan chan<- string) {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err == nil {
		defer conn.Close()
		openPortsChan <- strconv.Itoa(port)
	}
}

// Worker function for concurrent port scanning
func worker(ip string, ports <-chan int, openPortsChan chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for port := range ports {
		checkPort(ip, port, openPortsChan)
	}
}

// Parse port range from string
func parsePortRange(portRange string) ([]int, error) {
	var ports []int
	parts := strings.Split(portRange, "-")
	if len(parts) == 1 {
		port, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	} else if len(parts) == 2 {
		startPort, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, err
		}
		endPort, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}
		for port := startPort; port <= endPort; port++ {
			ports = append(ports, port)
		}
	} else {
		return nil, fmt.Errorf("invalid port range format")
	}
	return ports, nil
}

// Read domains from file
func readDomains(filename string) ([]string, error) {
	var domains []string
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	return domains, scanner.Err()
}

// Display banner
func printBanner() {
	fmt.Println(`
*******************************
*    PORT SCANNER v6.1        *
*   Ultra-Fast Scan Tool      *
*******************************
`)
}

func main() {
	// Parse command-line arguments
	domainPtr := flag.String("d", "", "Domain or IP to scan")
	listPtr := flag.String("l", "", "File with list of domains/subdomains")
	outputFilePtr := flag.String("o", "", "Output file to save results")
	portRangePtr := flag.String("p", "1-65535", "Port range to scan (e.g., 1-1000)")

	flag.Parse()

	printBanner()

	// Validate input
	var targets []string
	if *domainPtr != "" {
		targets = append(targets, *domainPtr)
	} else if *listPtr != "" {
		domains, err := readDomains(*listPtr)
		if err != nil {
			fmt.Printf("Error reading domains file: %v\n", err)
			return
		}
		targets = domains
	} else {
		fmt.Println("You must provide a domain, IP, or list of domains to scan.")
		return
	}

	// Parse port range
	ports, err := parsePortRange(*portRangePtr)
	if err != nil {
		fmt.Printf("Invalid port range: %v\n", err)
		return
	}

	var allResults []string

	// Handle scanning for each target (domain or IP)
	for _, target := range targets {
		ip := resolveDomain(target)
		if ip == "" {
			fmt.Printf("Skipping unresolved target: %s\n", target) // Added logging here
			continue // Silently skip unresolved domains
		}

		fmt.Printf("Scanning %s (%s)\n", target, ip)

		portChan := make(chan int, len(ports))
		openPortsChan := make(chan string, len(ports))
		var wg sync.WaitGroup

		// Start worker goroutines
		for i := 0; i < maxWorkers; i++ {
			wg.Add(1)
			go worker(ip, portChan, openPortsChan, &wg)
		}

		// Send ports to workers
		go func() {
			for _, port := range ports {
				portChan <- port
			}
			close(portChan)
		}()

		// Wait for all workers to finish and close the results channel
		go func() {
			wg.Wait()
			close(openPortsChan)
		}()

		// Collect results for the current target
		var openPorts []string
		for port := range openPortsChan {
			openPorts = append(openPorts, port)
		}

		if len(openPorts) > 0 {
			result := fmt.Sprintf("%s (%s): open ports %s", target, ip, strings.Join(openPorts, ","))
			fmt.Println(result)
			allResults = append(allResults, result)
		} else {
			// Log when no open ports are found
			fmt.Printf("No open ports found for %s (%s)\n", target, ip)
		}
	}

	// Save results to file if the -o option is provided
	if *outputFilePtr != "" {
		file, err := os.Create(*outputFilePtr)
		if err != nil {
			fmt.Printf("Error saving results: %v\n", err)
			return
		}
		defer file.Close()

		for _, result := range allResults {
			file.WriteString(result + "\n")
		}
		fmt.Printf("Results saved to %s\n", *outputFilePtr)
	}
}
