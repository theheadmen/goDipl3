package clientapi

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/theheadmen/goDipl3/models"
	"github.com/theheadmen/goDipl3/utils"
)

var (
	version   = "development"
	buildDate = time.Now().Format("2006-01-02 15:04:05")
)

func saveCookiesToFile(cookies []*http.Cookie) {
	file, err := os.Create("./cookies.txt")
	if err != nil {
		fmt.Println("Error creating file:", err)
		os.Exit(1)
	}
	defer file.Close()

	for _, cookie := range cookies {
		_, err := file.WriteString(cookie.String() + "\n")
		if err != nil {
			fmt.Println("Error writing to file:", err)
			os.Exit(1)
		}
	}
}

func readCookiesFromFile() []*http.Cookie {
	file, err := os.Open("./cookies.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var cookies []*http.Cookie
	for scanner.Scan() {
		cookieStr := scanner.Text()
		parts := strings.Split(cookieStr, ";")
		if len(parts) > 0 {
			cookieParts := strings.Split(parts[0], "=")
			if len(cookieParts) == 2 {
				cookie := &http.Cookie{
					Name:  cookieParts[0],
					Value: cookieParts[1],
				}
				cookies = append(cookies, cookie)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}

	return cookies
}

// Глобальная переменная для хранения cookie
var authCookies []*http.Cookie

var RootCmd = &cobra.Command{
	Use:   "gophkeeper-cli",
	Short: "GophKeeper CLI is a client for the GophKeeper server.",
	Long: `GophKeeper CLI allows users to register, login, store, and retrieve data.
It is a CLI application that interacts with the GophKeeper server.`,
}

var registerCmd = &cobra.Command{
	Use:   "register USERNAME PASSWORD",
	Short: "Register a new user",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		user := models.User{
			Username: args[0],
			Password: args[1],
		}

		userJson, err := json.Marshal(user)
		if err != nil {
			fmt.Println("Error marshalling user:", err)
			os.Exit(1)
		}

		// Создаем URL с параметром типа данных
		baseURL, err := url.Parse("https://localhost:8080/register")
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			os.Exit(1)
		}
		resp, err := utils.SendRequest(baseURL, bytes.NewBuffer(userJson), "POST", "application/json", false, authCookies)
		if err != nil {
			fmt.Println("Error sending registration request:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			fmt.Println("Registration failed with status:", resp.Status)
			os.Exit(1)
		}

		// Обработка cookie и сохранение их в файл
		authCookies = resp.Cookies()
		saveCookiesToFile(authCookies)

		fmt.Println("User registered successfully.")
	},
}

var loginCmd = &cobra.Command{
	Use:   "login USERNAME PASSWORD",
	Short: "Login an existing user",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		user := models.User{
			Username: args[0],
			Password: args[1],
		}

		userJson, err := json.Marshal(user)
		if err != nil {
			fmt.Println("Error marshalling user:", err)
			os.Exit(1)
		}

		// Создаем URL с параметром типа данных
		baseURL, err := url.Parse("https://localhost:8080/login")
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			os.Exit(1)
		}
		resp, err := utils.SendRequest(baseURL, bytes.NewBuffer(userJson), "POST", "application/json", false, authCookies)
		if err != nil {
			fmt.Println("Error sending login request:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Println("Login failed with status:", resp.Status)
			os.Exit(1)
		}

		// Обработка cookie и сохранение их в файл
		authCookies = resp.Cookies()
		saveCookiesToFile(authCookies)

		fmt.Println("User logged in successfully.")
	},
}

var storeCmd = &cobra.Command{
	Use:   "store TYPE DATA KEY flags",
	Short: "Store user data",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		dataType := args[0]
		data := args[1]
		key := []byte(args[2])

		meta, _ := cmd.Flags().GetString("meta")
		expiry, _ := cmd.Flags().GetString("expiry")
		cvv, _ := cmd.Flags().GetString("cvv")

		encData, err := Encrypt(key, data)
		if err != nil {
			fmt.Println("Error encrypting data:", err)
			os.Exit(1)
		}

		encMeta, err := Encrypt(key, meta)
		if err != nil {
			fmt.Println("Error encrypting meta:", err)
			os.Exit(1)
		}

		var dataToStore interface{}
		switch dataType {
		case "text":
			dataToStore = models.TextData{
				Data: encData,
				Meta: encMeta,
			}
		case "binary":
			dataToStore = models.BinaryData{
				Data: []byte(data),
				Meta: encMeta,
			}
		case "bankcard":
			encExpiry, err := Encrypt(key, expiry)
			if err != nil {
				fmt.Println("Error encrypting expiry:", err)
				os.Exit(1)
			}

			encCVV, err := Encrypt(key, cvv)
			if err != nil {
				fmt.Println("Error encrypting cvv:", err)
				os.Exit(1)
			}

			dataToStore = models.BankCard{
				Number: encData,
				Meta:   encMeta,
				Expiry: encExpiry,
				CVV:    encCVV,
			}
		default:
			fmt.Println("Unsupported data type")
			os.Exit(1)
		}

		dataJson, err := json.Marshal(dataToStore)
		if err != nil {
			fmt.Println("Error marshalling data:", err)
			os.Exit(1)
		}

		// Создаем URL с параметром типа данных
		baseURL, err := url.Parse("https://localhost:8080/store")
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			os.Exit(1)
		}

		params := url.Values{}
		params.Add("type", dataType)
		baseURL.RawQuery = params.Encode()

		resp, err := utils.SendRequest(baseURL, bytes.NewBuffer(dataJson), "POST", "application/json", true, authCookies)
		if err != nil {
			fmt.Println("Error sending store request:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			fmt.Println("Store failed with status:", resp.Status)
			os.Exit(1)
		}

		fmt.Println("Data stored successfully.")
	},
}

var updateCmd = &cobra.Command{
	Use:   "update TYPE DATAID DATA KEY flags",
	Short: "Update user data",
	Args:  cobra.ExactArgs(4),
	Run: func(cmd *cobra.Command, args []string) {
		dataType := args[0]
		dataID := args[1]
		data := args[2]
		key := []byte(args[3])

		meta, _ := cmd.Flags().GetString("meta")
		expiry, _ := cmd.Flags().GetString("expiry")
		cvv, _ := cmd.Flags().GetString("cvv")

		encData, err := Encrypt(key, data)
		if err != nil {
			fmt.Println("Error encrypting data:", err)
			os.Exit(1)
		}

		encMeta, err := Encrypt(key, meta)
		if err != nil {
			fmt.Println("Error encrypting meta:", err)
			os.Exit(1)
		}

		var dataToStore interface{}
		switch dataType {
		case "text":
			dataToStore = models.TextData{
				Data: encData,
				Meta: encMeta,
			}
		case "binary":
			dataToStore = models.BinaryData{
				Data: []byte(data),
				Meta: encMeta,
			}
		case "bankcard":
			encExpiry, err := Encrypt(key, expiry)
			if err != nil {
				fmt.Println("Error encrypting expiry:", err)
				os.Exit(1)
			}

			encCVV, err := Encrypt(key, cvv)
			if err != nil {
				fmt.Println("Error encrypting cvv:", err)
				os.Exit(1)
			}

			dataToStore = models.BankCard{
				Number: encData,
				Meta:   encMeta,
				Expiry: encExpiry,
				CVV:    encCVV,
			}
		default:
			fmt.Println("Unsupported data type")
			os.Exit(1)
		}

		dataJson, err := json.Marshal(dataToStore)
		if err != nil {
			fmt.Println("Error marshalling data:", err)
			os.Exit(1)
		}

		// Создаем URL с параметром типа данных
		baseURL, err := url.Parse("https://localhost:8080/update")
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			os.Exit(1)
		}

		params := url.Values{}
		params.Add("type", dataType)
		params.Add("data_id", dataID)
		baseURL.RawQuery = params.Encode()

		resp, err := utils.SendRequest(baseURL, bytes.NewBuffer(dataJson), "POST", "application/json", true, authCookies)
		if err != nil {
			fmt.Println("Error sending update request:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Println("Update failed with status:", resp.Status)
			os.Exit(1)
		}

		fmt.Println("Data updated successfully.")
	},
}

var getCmd = &cobra.Command{
	Use:   "get TYPE KEY",
	Short: "Get user data",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		dataType := args[0]
		key := []byte(args[1])

		// Создаем URL с параметром типа данных
		baseURL, err := url.Parse("https://localhost:8080/retrieve")
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			os.Exit(1)
		}

		params := url.Values{}
		params.Add("type", dataType)
		baseURL.RawQuery = params.Encode()

		resp, err := utils.SendRequest(baseURL, nil, "GET", "", true, authCookies)
		if err != nil {
			fmt.Println("Error sending get request:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Println("Get failed with status:", resp.Status)
			os.Exit(1)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			os.Exit(1)
		}

		switch dataType {
		case "text":
			var textData []models.TextData
			err = json.Unmarshal(body, &textData)
			if err != nil {
				fmt.Println("Error unmarshalling TextData:", err)
				os.Exit(1)
			}
			for i := range textData {
				decrData, err := Decrypt(key, textData[i].Data)
				if err != nil {
					fmt.Println("Error decrypt TextData.data:", err)
					os.Exit(1)
				}

				decrMeta, err := Decrypt(key, textData[i].Meta)
				if err != nil {
					fmt.Println("Error decrypt TextData.meta:", err)
					os.Exit(1)
				}
				textData[i].Data = decrData
				textData[i].Meta = decrMeta
			}
			fmt.Printf("TextData: %+v\n", textData)
		case "binary":
			var binaryData []models.BinaryData
			err = json.Unmarshal(body, &binaryData)
			if err != nil {
				fmt.Println("Error unmarshalling BinaryData:", err)
				os.Exit(1)
			}
			fmt.Printf("BinaryData: %+v\n", binaryData)
		case "bankcard":
			var bankCard []models.BankCard
			err = json.Unmarshal(body, &bankCard)
			if err != nil {
				fmt.Println("Error unmarshalling BankCard:", err)
				os.Exit(1)
			}
			for i := range bankCard {
				decrNumber, err := Decrypt(key, bankCard[i].Number)
				if err != nil {
					fmt.Println("Error decrypt bankCard.Number:", err)
					os.Exit(1)
				}

				decrExpiry, err := Decrypt(key, bankCard[i].Expiry)
				if err != nil {
					fmt.Println("Error decrypt bankCard.Expiry:", err)
					os.Exit(1)
				}

				decrCVV, err := Decrypt(key, bankCard[i].CVV)
				if err != nil {
					fmt.Println("Error decrypt bankCard.CVV:", err)
					os.Exit(1)
				}

				decrMeta, err := Decrypt(key, bankCard[i].Meta)
				if err != nil {
					fmt.Println("Error decrypt bankCard.meta:", err)
					os.Exit(1)
				}
				bankCard[i].Number = decrNumber
				bankCard[i].Expiry = decrExpiry
				bankCard[i].CVV = decrCVV
				bankCard[i].Meta = decrMeta
			}
			fmt.Printf("BankCard: %+v\n", bankCard)
		default:
			fmt.Println("Unsupported data type")
			os.Exit(1)
		}
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete TYPE ID",
	Short: "Delete user data",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		dataType := args[0]
		dataID := args[1]

		// Создаем URL с параметром типа данных
		baseURL, err := url.Parse("https://localhost:8080/delete")
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			os.Exit(1)
		}

		params := url.Values{}
		params.Add("type", dataType)
		params.Add("id", dataID)
		baseURL.RawQuery = params.Encode()

		resp, err := utils.SendRequest(baseURL, nil, "POST", "", true, authCookies)
		if err != nil {
			fmt.Println("Error sending delete request:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Println("Delete failed with status:", resp.Status)
			os.Exit(1)
		}

		fmt.Println("Data deleted successfully.")
	},
}

var storeFileCmd = &cobra.Command{
	Use:   "filestore [file path] KEY",
	Short: "Store a file on the server",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		key := []byte(args[1])

		err := StoreFile(filePath, key)
		if err != nil {
			fmt.Println("Error storing file:", err)
			os.Exit(1)
		}
	},
}

func StoreFile(filePath string, key []byte) error {
	// Открываем файл
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Читаем содержимое файла
	fileContent, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	// Шифруем содержимое файла
	encryptedContent, err := Encrypt(key, string(fileContent))
	if err != nil {
		return err
	}

	// Создаем буфер для тела запроса
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Добавляем файл в мультипарт-форму
	part, err := writer.CreateFormFile("file", filepath.Base(file.Name()))
	if err != nil {
		return err
	}
	_, err = io.Copy(part, strings.NewReader(encryptedContent))
	if err != nil {
		return err
	}

	// Закрываем мультипарт-форму
	err = writer.Close()
	if err != nil {
		return err
	}

	// Создаем URL с параметром типа данных
	baseURL, err := url.Parse("https://localhost:8080/store_file")
	if err != nil {
		fmt.Println("Error parsing URL:", err)
		return err
	}

	resp, err := utils.SendRequest(baseURL, body, "POST", writer.FormDataContentType(), true, authCookies)
	if err != nil {
		fmt.Println("Error sending store request:", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		fmt.Println("Store failed with status:", resp.Status)
		return err
	}

	fmt.Println("File stored successfully.")
	return nil
}

var listFilesCmd = &cobra.Command{
	Use:   "listfiles",
	Short: "List all file names for a user",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		// Создаем запрос
		// Создаем URL с параметром типа данных
		baseURL, err := url.Parse("https://localhost:8080/get_list_files")
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			os.Exit(1)
		}

		resp, err := utils.SendRequest(baseURL, nil, "GET", "", true, authCookies)
		if err != nil {
			fmt.Println("Error sending list files request:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		// Проверяем статус ответа
		if resp.StatusCode != http.StatusOK {
			fmt.Println("List files failed with status:", resp.Status)
			os.Exit(1)
		}

		// Читаем тело ответа
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			os.Exit(1)
		}

		// Парсим JSON ответа
		var fileNames []string
		err = json.Unmarshal(body, &fileNames)
		if err != nil {
			fmt.Println("Error parsing JSON:", err)
			os.Exit(1)
		}

		// Выводим список имен файлов
		for _, fileName := range fileNames {
			fmt.Println(fileName)
		}
	},
}

var getFileCmd = &cobra.Command{
	Use:   "getfile [server_filename] [local_filename] KEY",
	Short: "Get a file from the server and save it to a local file",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		serverFilename := args[0]
		localFilename := args[1]
		key := []byte(args[2])

		// Создаем URL с параметром типа данных
		baseURL, err := url.Parse("https://localhost:8080/get_file")
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			os.Exit(1)
		}

		params := url.Values{}
		params.Add("fileName", serverFilename)
		baseURL.RawQuery = params.Encode()

		resp, err := utils.SendRequest(baseURL, nil, "GET", "application/json", true, authCookies)
		if err != nil {
			fmt.Println("Error sending get file request:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		// Проверяем статус ответа
		if resp.StatusCode != http.StatusOK {
			fmt.Println("Get file failed with status:", resp.Status)
			os.Exit(1)
		}

		// Читаем тело ответа
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			os.Exit(1)
		}

		// Расшифровываем полученные данные
		decryptedData, err := Decrypt(key, string(body))
		if err != nil {
			fmt.Println("Error decrypting data:", err)
			os.Exit(1)
		}

		// Записываем данные в локальный файл
		err = os.WriteFile(localFilename, []byte(decryptedData), 0644)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			os.Exit(1)
		}

		fmt.Printf("File saved to %s\n", localFilename)
	},
}

var deleteFileCmd = &cobra.Command{
	Use:   "deletefile [fileName]",
	Short: "Delete a file from the server",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fileName := args[0]

		// Создаем URL с параметром fileName
		// Создаем URL с параметром типа данных
		baseURL, err := url.Parse("https://localhost:8080/delete_file")
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			os.Exit(1)
		}

		params := url.Values{}
		params.Add("fileName", fileName)
		baseURL.RawQuery = params.Encode()

		resp, err := utils.SendRequest(baseURL, nil, "DELETE", "", true, authCookies)
		if err != nil {
			fmt.Println("Error sending delete file request:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		// Проверяем статус ответа
		if resp.StatusCode != http.StatusOK {
			fmt.Println("Delete file failed with status:", resp.Status)
			os.Exit(1)
		}

		fmt.Println("File deleted successfully.")
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of GophKeeper CLI",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("GophKeeper CLI version %s, built on %s\n", version, buildDate)
	},
}

// Encrypt encrypts a string using a key of any length
func Encrypt(key []byte, text string) (string, error) {
	plaintext := []byte(text)

	// Pad key to block size
	key = padKeyToBlockSize(key, aes.BlockSize)

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a new Counter Mode block cipher
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Prepend the IV to the ciphertext
	ciphertextWithIV := append(iv, ciphertext...)

	return hex.EncodeToString(ciphertextWithIV), nil
}

// Decrypt decrypts a string using a key of any length
func Decrypt(key []byte, cryptoText string) (string, error) {
	ciphertextWithIV, err := hex.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}

	// Pad key to block size
	key = padKeyToBlockSize(key, aes.BlockSize)

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Extract the IV from the ciphertext
	if len(ciphertextWithIV) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertextWithIV[:aes.BlockSize]
	ciphertext := ciphertextWithIV[aes.BlockSize:]

	// Create a new Counter Mode block cipher
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}

// padKeyToBlockSize pads the key to the block size if it's shorter
func padKeyToBlockSize(key []byte, blockSize int) []byte {
	for len(key) < blockSize {
		key = append(key, 0)
	}
	return key[:blockSize]
}

func init() {
	// Проверяем, существует ли файл с куки
	if _, err := os.Stat("./cookies.txt"); err == nil {
		// Если файл существует, читаем куки из него
		authCookies = readCookiesFromFile()
	}

	RootCmd.AddCommand(registerCmd)
	RootCmd.AddCommand(loginCmd)
	storeCmd.Flags().StringP("meta", "m", "", "Metadata for the data")
	storeCmd.Flags().StringP("expiry", "e", "", "Expiry date for the card")
	storeCmd.Flags().StringP("cvv", "c", "", "CVV code for the card")
	RootCmd.AddCommand(storeCmd)
	RootCmd.AddCommand(getCmd)
	RootCmd.AddCommand(versionCmd)
	RootCmd.AddCommand(deleteCmd)
	updateCmd.Flags().StringP("meta", "m", "", "Metadata for the data")
	updateCmd.Flags().StringP("expiry", "e", "", "Expiry date for the card")
	updateCmd.Flags().StringP("cvv", "c", "", "CVV code for the card")
	RootCmd.AddCommand(updateCmd)
	RootCmd.AddCommand(storeFileCmd)
	RootCmd.AddCommand(listFilesCmd)
	RootCmd.AddCommand(getFileCmd)
	RootCmd.AddCommand(deleteFileCmd)
}
