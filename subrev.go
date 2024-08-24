package main
import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
	"io/ioutil"
)
type ReverseIPResponse struct {
	Author  string   `json:"author"`
	Domains []string `json:"domains"`
}
type SubdomainResponse struct {
	Author     string   `json:"author"`
	Subdomains []string `json:"subdomains"`
}
type DateGrabResponse struct {
	Author  string   `json:"author"`
	Domains []string `json:"domains"`
}
type ApiKeyValidationResponse struct {
	Author   string `json:"author"`
	Status   string `json:"status"`
	User     string `json:"user"`
	Requests int    `json:"requests"`
}
func clearScreen() {
	var clearCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		clearCmd = exec.Command("cmd", "/c", "cls")
	} else {
		clearCmd = exec.Command("clear")
	}
	clearCmd.Stdout = os.Stdout
	clearCmd.Run()
}
func displayHeader() {
	fmt.Println(`░██████╗██╗░░░██╗██████╗░██████╗░███████╗██╗░░░██╗`)
	fmt.Println(`██╔════╝██║░░░██║██╔══██╗██╔══██╗██╔════╝██║░░░██║`)
	fmt.Println(`╚█████╗░██║░░░██║██████╦╝██████╔╝█████╗░░╚██╗░██╔╝`)
	fmt.Println(`░╚═══██╗██║░░░██║██╔══██╗██╔══██╗██╔══╝░░░╚████╔╝░`)
	fmt.Println(`██████╔╝╚██████╔╝██████╦╝██║░░██║███████╗░░╚██╔╝░░`)
	fmt.Println(`╚═════╝░╚═════╝░╚═════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░`)
	fmt.Println(" - developed by Eclipse Security Labs")
	fmt.Println(" - website : https://eclipsesec.tech/")
}
func httpGet(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(string(body), "<html>") {
		return nil, fmt.Errorf("received HTML response, indicating an error")
	}
	return body, nil
}
func validateApiKey(apikey string) (string, bool) {
	url := fmt.Sprintf("https://eclipsesec.tech/api/?apikey=%s&validate=true", apikey)
	var body []byte
	var err error
	for retries := 0; retries < 10; retries++ {
		body, err = httpGet(url)
		if err == nil {
			break
		}
		fmt.Printf("HTML response or error detected, retrying... (%d/10)\n", retries+1)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return "", false
	}
	var validationResp ApiKeyValidationResponse
	err = json.Unmarshal(body, &validationResp)
	if err != nil {
		return "", false
	}
	if validationResp.Status == "valid" {
		return validationResp.User, true
	}

	return "", false
}
func openRegistrationPage() {
	var err error
	if runtime.GOOS == "windows" {
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", "https://eclipsesec.tech/register").Start()
	} else if runtime.GOOS == "linux" {
		err = exec.Command("xdg-open", "https://eclipsesec.tech/register").Start()
	} else if runtime.GOOS == "darwin" {
		err = exec.Command("open", "https://eclipsesec.tech/register").Start()
	}
	if err != nil {
		fmt.Println("Unable to open the registration page, please visit manually: https://eclipsesec.tech/register")
	}
}
func reverseIP(ip, apikey string, wg *sync.WaitGroup, mu *sync.Mutex, outputFile *os.File) {
	defer wg.Done()
	var result ReverseIPResponse
	url := fmt.Sprintf("https://eclipsesec.tech/api/?reverseip=%s&apikey=%s", ip, apikey)
	for retries := 0; retries < 5; retries++ {
		body, err := httpGet(url)
		if err == nil {
			if len(body) > 0 && isValidJSON(body) {
				err = json.Unmarshal(body, &result)
				if err == nil && len(result.Domains) > 0 {
					break
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
	if len(result.Domains) == 0 {
		mu.Lock()
		color.New(color.FgRed).Printf("[ bad IP ] - %s\n", ip)
		mu.Unlock()
		return
	}
	mu.Lock()
	color.New(color.FgGreen).Print("[reversing] ")
	color.New(color.FgYellow).Printf("%s", ip)
	color.New(color.FgWhite).Print(" -> ")
	color.New(color.FgGreen).Printf("[%d domains found]\n", len(result.Domains))

	for _, domain := range result.Domains {
		outputFile.WriteString(fmt.Sprintf("%s\n", domain))
	}
	mu.Unlock()
}
func subdomainFinder(domain, apikey string, wg *sync.WaitGroup, mu *sync.Mutex, outputFile *os.File) {
	defer wg.Done()

	var result SubdomainResponse
	url := fmt.Sprintf("https://eclipsesec.tech/api/?subdomain=%s&apikey=%s", domain, apikey)
	for retries := 0; retries < 5; retries++ {
		body, err := httpGet(url)
		if err == nil {
			bodyCopy := make([]byte, len(body))
			copy(bodyCopy, body)

			if len(bodyCopy) > 0 && isValidJSON(bodyCopy) {
				err = json.Unmarshal(bodyCopy, &result)
				if err == nil && len(result.Subdomains) > 0 {
					break
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
	if len(result.Subdomains) == 0 {
		mu.Lock()
		color.New(color.FgRed).Printf("[ bad domain ] - %s\n", domain)
		mu.Unlock()
		return
	}
	mu.Lock()
	color.New(color.FgGreen).Print("[extracting] ")
	color.New(color.FgYellow).Printf("%s", domain)
	color.New(color.FgWhite).Print(" -> ")
	color.New(color.FgGreen).Printf("[%d subdomains found]\n", len(result.Subdomains))
	for _, subdomain := range result.Subdomains {
		outputFile.WriteString(fmt.Sprintf("%s\n", subdomain))
	}
	mu.Unlock()
}
func grabByDate(apikey, date string, startPage, endPage int, wg *sync.WaitGroup, resultsChan chan<- string) {
	defer wg.Done()
	for page := startPage; page <= endPage; page++ {
		var result DateGrabResponse
		url := fmt.Sprintf("https://eclipsesec.tech/api/?bydate=%s&page=%d&apikey=%s", date, page, apikey)

		for retries := 0; retries < 5; retries++ {
			body, err := httpGet(url)
			if err == nil {
				if len(body) > 0 && isValidJSON(body) {
					err = json.Unmarshal(body, &result)
					if err == nil && len(result.Domains) > 0 {
						break
					}
				}
			}
			time.Sleep(5 * time.Second)
		}
		if len(result.Domains) == 0 {
			resultsChan <- fmt.Sprintf("page [%d] -> no domains found\n", page)
			continue
		}
		var resultString strings.Builder
		resultString.WriteString(fmt.Sprintf("page [%d] -> domains found [%d]\n", page, len(result.Domains)))
		for _, domain := range result.Domains {
			resultString.WriteString(fmt.Sprintf("%s\n", domain))
		}
		resultsChan <- resultString.String()
	}
}
func isValidJSON(data []byte) bool {
	var js json.RawMessage
	return json.Unmarshal(data, &js) == nil
}
func main() {
	clearScreen()
	displayHeader()
	fmt.Print("Enter API key: ")
	var apikey string
	fmt.Scanln(&apikey)
	user, valid := validateApiKey(apikey)
	if !valid {
		fmt.Println("Invalid API key. Redirecting to registration page...")
		openRegistrationPage()
		return
	}
	fmt.Printf("[ Welcome  %s ] \n", user)
	fmt.Println("1. Reverse IP")
	fmt.Println("2. Subdomain Finder")
	fmt.Println("3. Grab by Date")
	var choice int
	fmt.Print("$ choose: ")
	fmt.Scanln(&choice)
	var inputList string
	var startPage, endPage int
	var date string
	if choice == 1 {
		fmt.Print("$ give me your IP list: ")
		fmt.Scanln(&inputList)
	} else if choice == 2 {
		fmt.Print("$ give me your domain list: ")
		fmt.Scanln(&inputList)
	} else if choice == 3 {
		fmt.Print("$ Enter date (YYYY-MM-DD): ")
		fmt.Scanln(&date)
		fmt.Print("$ Page [ start from ] : ")
		fmt.Scanln(&startPage)
		fmt.Print("$ to page : ")
		fmt.Scanln(&endPage)
	}

	fmt.Print("$ save to: ")
	var outputFileName string
	fmt.Scanln(&outputFileName)
	fmt.Print("$ enter thread count: ")
	var threadCount int
	fmt.Scanln(&threadCount)
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer outputFile.Close()
	resultsChan := make(chan string, endPage-startPage+1)
	var wg sync.WaitGroup
	sem := make(chan struct{}, threadCount)
	if choice == 1 || choice == 2 {
		inputFile, err := os.Open(inputList)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer inputFile.Close()
		scanner := bufio.NewScanner(inputFile)
		for scanner.Scan() {
			line := scanner.Text()
			wg.Add(1)
			sem <- struct{}{}
			go func(line string) {
				defer func() { <-sem }()
				if choice == 1 {
					reverseIP(line, apikey, &wg, &sync.Mutex{}, outputFile)
				} else if choice == 2 {
					subdomainFinder(line, apikey, &wg, &sync.Mutex{}, outputFile)
				}
			}(line)
		}
	} else if choice == 3 {
		for page := startPage; page <= endPage; page++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(page int) {
				defer func() { <-sem }()
				grabByDate(apikey, date, page, page, &wg, resultsChan)
			}(page)
		}
	}
	go func() {
		wg.Wait()
		close(resultsChan)
	}()
	for result := range resultsChan {
		fmt.Print(result)
		outputFile.WriteString(result)
	}
	fmt.Println("Process completed. Results saved to", outputFileName)
}
