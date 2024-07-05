package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"golang.org/x/crypto/ripemd160"

	"btcgo/src/crypto/base58"
	"btcgo/src/crypto/btc_utils"
)

// PromptRangeNumber prompts the user to select a range number
func PromptRangeNumber(totalRanges int, autoSelect int) int {
	reader := bufio.NewReader(os.Stdin)
	charReadline := '\n'

	if runtime.GOOS == "windows" {
		charReadline = '\r'
	}

	if autoSelect > 0 && autoSelect <= totalRanges {
		return autoSelect
	}

	for {
		fmt.Printf("Escolha a carteira (1 a %d): ", totalRanges)
		input, _ := reader.ReadString(byte(charReadline))
		input = strings.TrimSpace(input)
		rangeNumber, err := strconv.Atoi(input)
		if err == nil && rangeNumber >= 1 && rangeNumber <= totalRanges {
			return rangeNumber
		}
		fmt.Println("Numero invalido.")
	}
}

// Contains checks if a string is in a slice of strings
func Contains(slice [][]byte, item []byte) bool {
	for _, a := range slice {
		if bytes.Equal(a, item) {
			return true
		}
	}
	return false
}

// LoadRanges loads ranges from a JSON file
func LoadRanges(filename string) (*Ranges, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var ranges Ranges
	if err := json.Unmarshal(bytes, &ranges); err != nil {
		return nil, err
	}

	return &ranges, nil
}

// LoadWallets loads wallet addresses from a JSON file
func LoadWallets(filename string) (*Wallets, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	type WalletsTemp struct {
		Addresses []string `json:"wallets"`
	}

	var walletsTemp WalletsTemp
	if err := json.Unmarshal(bytes, &walletsTemp); err != nil {
		return nil, err
	}

	var wallets Wallets
	for _, address := range walletsTemp.Addresses {
		wallets.Addresses = append(wallets.Addresses, base58.Decode(address)[1:21])
	}

	return &wallets, nil
}

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
	if err != nil {
		fmt.Printf("Erro ao obter o caminho do executável: %v\n", err)
		return
	}
	rootDir := filepath.Dir(exePath)

	for {
		ranges, err := LoadRanges(filepath.Join(rootDir, "data", "ranges.json"))
		if err != nil {
			log.Fatalf("Failed to load ranges: %v", err)
		}

		color.Cyan("CELI AI - INFERÊNICA DE DADOS")
		color.White("v0.61")

		rangeNumber := PromptRangeNumber(len(ranges.Ranges), 6) // Seleciona automaticamente entre 6 e 9
		privKeyHex := ranges.Ranges[rangeNumber-1].Min

		progressFilePath := filepath.Join(rootDir, "progress.json")
		progress, err := LoadProgress(progressFilePath)
		if err != nil {
			log.Fatalf("Failed to load progress: %v", err)
		}

		privKeyInt := new(big.Int)
		if progress.LastPrivKey != "" {
			privKeyInt.SetString(progress.LastPrivKey[2:], 16)
		} else {
			privKeyInt.SetString(privKeyHex[2:], 16)
		}

		wallets, err := LoadWallets(filepath.Join(rootDir, "data", "wallets.json"))
		if err != nil {
			log.Fatalf("Failed to load wallets: %v", err)
		}

		keysChecked := progress.KeysChecked
		startTime := time.Now()

		numCPU := runtime.NumCPU()
		fmt.Printf("CPUs detectados: %s\n", green(numCPU))
		runtime.GOMAXPROCS(numCPU * 2)

		privKeyChan := make(chan *big.Int, numCPU*2)
		resultChan := make(chan *big.Int)
		var wg sync.WaitGroup

		for i := 0; i < numCPU*2; i++ {
			wg.Add(1)
			go worker(wallets, privKeyChan, resultChan, &wg)
		}

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		done := make(chan struct{})
		closeOnce := sync.Once{}

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
			closeOnce.Do(func() { close(done) })
			os.Exit(0)
		}()

		var foundAddress *big.Int
		select {
		case resultAddress := <-resultChan:
			foundAddress = resultAddress
			progress.LastPrivKey = fmt.Sprintf("0x%064x", privKeyInt)
			progress.KeysChecked = keysChecked
			progress.ElapsedTime += time.Since(startTime).Seconds()
			SaveProgress(progressFilePath, progress)
			closeOnce.Do(func() { close(done) })
		}

		if foundAddress != nil {
			fmt.Printf("Chave privada encontrada: 0x%064x\n", foundAddress)
			wif := btc_utils.GenerateWif(foundAddress)
			color.Yellow("WIF: %s", wif)
			// Converta a chave privada para WIF e endereço Bitcoin
			address, err := WifToAddress(wif)
			if err != nil {
				log.Fatalf("Erro ao converter WIF para endereço: %v", err)
			}
			fmt.Printf("Endereço Bitcoin encontrado: %s\n", address)

			// Consultar saldo da carteira encontrada
			url := fmt.Sprintf("http://192.168.1.30:3006/api/address/%s", address)
            fmt.Printf("Mempool: %s\n", url)
			response, err := http.Get(url)
			if err != nil {
				log.Fatalf("Erro ao consultar saldo: %v", err)
			}
			defer response.Body.Close()

			var result map[string]interface{}
			err = json.NewDecoder(response.Body).Decode(&result)
			if err != nil {
				log.Fatalf("Erro ao decodificar resposta JSON: %v", err)
			}

			fundedTxoSum := result["chain_stats"].(map[string]interface{})["funded_txo_sum"].(float64)
            //fmt.Printf("Retorno Intranet: %s\n", fundedTxoSum)
			balanceBTC := fundedTxoSum / 1e8
			color.Cyan("Saldo: %f BTC", balanceBTC)

			// Imprimir número de transações
			txCount := result["chain_stats"].(map[string]interface{})["tx_count"].(float64)
			fmt.Printf("Número de transações: %.0f\n", txCount)
		}

		closeOnce.Do(func() { close(done) })
		wg.Wait()
	}
}

// worker processes private keys and checks for matches
func worker(wallets *Wallets, privKeyChan <-chan *big.Int, resultChan chan<- *big.Int, wg *sync.WaitGroup) {
	defer wg.Done()

	for privKey := range privKeyChan {
		wif := btc_utils.GenerateWif(privKey)
		address, err := WifToAddress(wif)
		if err != nil {
			log.Fatalf("Erro ao converter WIF para endereço: %v", err)
		}

		if Contains(wallets.Addresses, base58.Decode(address)[1:21]) {
			resultChan <- privKey
			return
		}
	}
}

// WifToAddress converts a WIF to a Bitcoin address
func WifToAddress(wif string) (string, error) {
	decodedWif := base58.Decode(wif)
	privKeyBytes := decodedWif[1:33]

	// Generate public key
	_, pubKey := btcec.PrivKeyFromBytes(privKeyBytes)
	pubKeyBytes := pubKey.SerializeCompressed()

	// Perform SHA-256 hashing on the public key
	sha256Hash := sha256.New()
	sha256Hash.Write(pubKeyBytes)
	sha256Hashed := sha256Hash.Sum(nil)

	// Perform RIPEMD-160 hashing on the result of SHA-256
	ripemd160Hash := ripemd160.New()
	ripemd160Hash.Write(sha256Hashed)
	ripemd160Hashed := ripemd160Hash.Sum(nil)

	// Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
	versionedPayload := append([]byte{0x00}, ripemd160Hashed...)

	// Perform SHA-256 hash twice
	sha256Hash1 := sha256.Sum256(versionedPayload)
	sha256Hash2 := sha256.Sum256(sha256Hash1[:])

	// Take the first 4 bytes of the second SHA-256 hash for checksum
	checksum := sha256Hash2[:4]

	// Append checksum to versioned payload
	fullPayload := append(versionedPayload, checksum...)

	// Convert the result to a base58 string
	address := base58.Encode(fullPayload)

	return address, nil
}
