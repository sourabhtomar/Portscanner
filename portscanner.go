package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxWorkers      = 500              // Reasonable number of workers for concurrency
	timeout         = 5 * time.Second  // Increased timeout for reliability
	resolveRetries  = 3                // Retries for DNS resolution
	resolveDelay    = 200 * time.Millisecond // Delay between retries for DNS resolution
)

// Check if the string is a valid IP address (IPv4)
func isValidIP(ip string) bool {
	re := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	return re.MatchString(ip)
}

// Resolve domain to IP address with retries
func resolveDomain(domain string) string {
	if isValidIP(domain) {
		return domain
	}

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	var resolvedIP string
	for i := 0; i < resolveRetries; i++ {
		ips, err := net.LookupHost(domain)
		if err == nil && len(ips) > 0 {
			resolvedIP = ips[0]
			break
		}
		time.Sleep(resolveDelay)
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

// Function to print the results in a neat and user-friendly way
func printResults(target string, ip string, openPorts []string) {
	fmt.Println("\n--------------------------------------------------")
	fmt.Printf("Target: %s (%s)\n", target, ip)
	fmt.Println("--------------------------------------------------")

	if len(openPorts) > 0 {
		fmt.Println("Open Ports:")
		for _, port := range openPorts {
			fmt.Printf(" - Port %s is OPEN\n", port)
		}
	} else {
		fmt.Println("No open ports found.")
	}

	fmt.Println("--------------------------------------------------")
}

// Save results to the output file
func saveResults(outputFile string, results []string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, result := range results {
		file.WriteString(result + "\n")
	}
	return nil
}

func main() {
	domainPtr := flag.String("d", "", "Domain or IP to scan")
	listPtr := flag.String("l", "", "File with list of domains/subdomains")
	outputFilePtr := flag.String("o", "", "Output file to save results")
	portRangePtr := flag.String("p", "1-65535", "Port range to scan (e.g., 1-1000)")

	flag.Parse()

	printBanner()

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

	ports, err := parsePortRange(*portRangePtr)
	if err != nil {
		fmt.Printf("Invalid port range: %v\n", err)
		return
	}

	var allResults []string

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalChan
		fmt.Println("\n[!] Interrupt received. Saving results...")
		if *outputFilePtr != "" {
			err := saveResults(*outputFilePtr, allResults)
			if err != nil {
				fmt.Printf("[!] Error saving results: %v\n", err)
			} else {
				fmt.Printf("[+] Results saved to %s\n", *outputFilePtr)
			}
		}
		os.Exit(0) // Exit the program cleanly after saving results
	}()

	for _, target := range targets {
		ip := resolveDomain(target)
		if ip == "" {
			fmt.Printf("Skipping unresolved target: %s\n", target)
			continue
		}

		fmt.Printf("Scanning %s (%s)\n", target, ip)

		portChan := make(chan int, len(ports))
		openPortsChan := make(chan string, len(ports))
		var wg sync.WaitGroup

		for i := 0; i < maxWorkers; i++ {
			wg.Add(1)
			go worker(ip, portChan, openPortsChan, &wg)
		}

		go func() {
			for _, port := range ports {
				portChan <- port
			}
			close(portChan)
		}()

		go func() {
			wg.Wait()
			close(openPortsChan)
		}()

		var openPorts []string
		for port := range openPortsChan {
			openPorts = append(openPorts, port)
		}

		printResults(target, ip, openPorts)

		if len(openPorts) > 0 {
			result := fmt.Sprintf("%s (%s): open ports %s", target, ip, strings.Join(openPorts, ","))
			allResults = append(allResults, result)
		} else {
			allResults = append(allResults, fmt.Sprintf("No open ports found for %s (%s)", target, ip))
		}
	}

	if *outputFilePtr != "" {
		err := saveResults(*outputFilePtr, allResults)
		if err != nil {
			fmt.Printf("Error saving results: %v\n", err)
			return
		}
		fmt.Printf("Results saved to %s\n", *outputFilePtr)
	}
}
