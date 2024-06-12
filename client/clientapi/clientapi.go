package clientapi

import (
	"bufio"
	"bytes"
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

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
	"github.com/theheadmen/goDipl3/client/dbconnector"
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

		encData, err := utils.Encrypt(key, data)
		if err != nil {
			fmt.Println("Error utils.Encrypting data:", err)
			os.Exit(1)
		}

		encMeta, err := utils.Encrypt(key, meta)
		if err != nil {
			fmt.Println("Error utils.Encrypting meta:", err)
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
				Data: []byte(encData),
				Meta: encMeta,
			}
		case "bankcard":
			encExpiry, err := utils.Encrypt(key, expiry)
			if err != nil {
				fmt.Println("Error utils.Encrypting expiry:", err)
				os.Exit(1)
			}

			encCVV, err := utils.Encrypt(key, cvv)
			if err != nil {
				fmt.Println("Error utils.Encrypting cvv:", err)
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

		encData, err := utils.Encrypt(key, data)
		if err != nil {
			fmt.Println("Error utils.Encrypting data:", err)
			os.Exit(1)
		}

		encMeta, err := utils.Encrypt(key, meta)
		if err != nil {
			fmt.Println("Error utils.Encrypting meta:", err)
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
			encExpiry, err := utils.Encrypt(key, expiry)
			if err != nil {
				fmt.Println("Error utils.Encrypting expiry:", err)
				os.Exit(1)
			}

			encCVV, err := utils.Encrypt(key, cvv)
			if err != nil {
				fmt.Println("Error utils.Encrypting cvv:", err)
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
	Use:   "get TYPE KEY [flags]",
	Short: "Get user data",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		dataType := args[0]
		key := []byte(args[1])

		isLocal, _ := cmd.Flags().GetBool("local")
		if isLocal {
			db := dbconnector.OpenDB()
			defer db.DB.Close()
			switch dataType {
			case "text":
				textLocalData, err := db.GetAllTextData()
				if err != nil {
					fmt.Println("Error getting text data:", err)
					os.Exit(1)
				}
				textData := utils.ConvertLocalToTextData(textLocalData)
				// а затем дешифруем чтобы показать
				err = utils.DecryptTextData(textData, key)
				if err != nil {
					fmt.Println("Error decrypt:", err)
					os.Exit(1)
				}
				fmt.Printf("TextData: %+v\n", textData)
			case "binary":
				binaryLocalData, err := db.GetAllBinaryData()
				if err != nil {
					fmt.Println("Error getting binary data:", err)
					os.Exit(1)
				}
				binaryData := utils.ConvertLocalToBinaryData(binaryLocalData)
				// а затем дешифруем чтобы показать
				err = utils.DecryptBinaryData(binaryData, key)
				if err != nil {
					fmt.Println("Error decrypt:", err)
					os.Exit(1)
				}
				fmt.Printf("BinaryData: %+v\n", binaryData)
			case "bankcard":
				bankLocalCard, err := db.GetAllBankData()
				if err != nil {
					fmt.Println("Error getting bankcard:", err)
					os.Exit(1)
				}

				bankCard := utils.ConvertLocalToBankData(bankLocalCard)
				// а затем дешифруем чтобы показать
				err = utils.DecryptBankData(bankCard, key)
				if err != nil {
					fmt.Println("Error decrypt:", err)
					os.Exit(1)
				}
				fmt.Printf("BankcardData: %+v\n", bankCard)
			default:
				fmt.Println("Unsupported data type")
				os.Exit(1)
			}
		} else {
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

			db := dbconnector.OpenDB()
			defer db.DB.Close()

			switch dataType {
			case "text":
				var textData []models.TextData
				err = json.Unmarshal(body, &textData)
				if err != nil {
					fmt.Println("Error unmarshalling TextData:", err)
					os.Exit(1)
				}
				// переводим данные в локальные и пробуем сохранить
				dataToLocal := utils.ConvertTextToLocalData(textData)
				err = db.SaveAndUpdateTextData(dataToLocal)
				if err != nil {
					fmt.Println("Error save local data:", err)
				}
				// а затем дешифруем чтобы показать
				err = utils.DecryptTextData(textData, key)
				if err != nil {
					fmt.Println("Error decrypt:", err)
					os.Exit(1)
				}
				fmt.Printf("TextData: %+v\n", textData)
			case "binary":
				var binaryData []models.BinaryData
				err = json.Unmarshal(body, &binaryData)
				if err != nil {
					fmt.Println("Error unmarshalling BinaryData:", err)
					os.Exit(1)
				}

				// переводим данные в локальные и пробуем сохранить
				dataToLocal := utils.ConvertBinaryToLocalData(binaryData)
				err = db.SaveAndUpdateBinaryData(dataToLocal)

				if err != nil {
					fmt.Println("Error save local data:", err)
				}
				// а затем дешифруем чтобы показать
				err = utils.DecryptBinaryData(binaryData, key)
				if err != nil {
					fmt.Println("Error decrypt:", err)
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
				// переводим данные в локальные и пробуем сохранить
				dataToLocal := utils.ConvertBankToLocalData(bankCard)
				err = db.SaveAndUpdateBankData(dataToLocal)

				if err != nil {
					fmt.Println("Error save local data:", err)
				}
				// а затем дешифруем чтобы показать
				err = utils.DecryptBankData(bankCard, key)
				if err != nil {
					fmt.Println("Error decrypt:", err)
					os.Exit(1)
				}
				fmt.Printf("BankCard: %+v\n", bankCard)
			default:
				fmt.Println("Unsupported data type")
				os.Exit(1)
			}
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
	encryptedContent, err := utils.Encrypt(key, string(fileContent))
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
		decryptedData, err := utils.Decrypt(key, string(body))
		if err != nil {
			fmt.Println("Error utils.Decrypting data:", err)
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

var syncFromServerCmd = &cobra.Command{
	Use:   "syncfrom KEY",
	Short: "Sync local data with data on server",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		// Вызов команды get с аргументами
		getCmdArgs := []string{"text", key}
		getCmd.Run(getCmd, getCmdArgs)
		getCmdArgs = []string{"binary", key}
		getCmd.Run(getCmd, getCmdArgs)
		getCmdArgs = []string{"bankcard", key}
		getCmd.Run(getCmd, getCmdArgs)
	},
}

var syncToServerCmd = &cobra.Command{
	Use:   "syncto",
	Short: "Sync server data with local data",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		db := dbconnector.OpenDB()
		defer db.DB.Close()

		textLocalData, err := db.GetAllTextData()
		if err != nil {
			fmt.Println("Error getting text data:", err)
			os.Exit(1)
		}
		textData := utils.ConvertLocalToTextData(textLocalData)
		dataJson, err := json.Marshal(textData)
		if err != nil {
			fmt.Println("Error marshalling data:", err)
			os.Exit(1)
		}
		dataType := "text"
		SendDataToSync(dataJson, dataType)

		binaryLocalData, err := db.GetAllBinaryData()
		if err != nil {
			fmt.Println("Error getting binary data:", err)
			os.Exit(1)
		}
		binaryData := utils.ConvertLocalToBinaryData(binaryLocalData)
		dataJson, err = json.Marshal(binaryData)
		if err != nil {
			fmt.Println("Error marshalling data:", err)
			os.Exit(1)
		}
		dataType = "binary"
		SendDataToSync(dataJson, dataType)

		bankLocalData, err := db.GetAllBankData()
		if err != nil {
			fmt.Println("Error getting bank data:", err)
			os.Exit(1)
		}
		bankData := utils.ConvertLocalToBankData(bankLocalData)
		dataJson, err = json.Marshal(bankData)
		if err != nil {
			fmt.Println("Error marshalling data:", err)
			os.Exit(1)
		}
		dataType = "bankcard"
		SendDataToSync(dataJson, dataType)

		fmt.Println("Data synced successfully.")
	},
}

func SendDataToSync(dataJson []byte, dataType string) {
	// Создаем URL с параметром типа данных
	baseURL, err := url.Parse("https://localhost:8080/sync")
	if err != nil {
		fmt.Println("Error parsing URL:", err)
		os.Exit(1)
	}

	params := url.Values{}
	params.Add("type", dataType)
	baseURL.RawQuery = params.Encode()

	resp, err := utils.SendRequest(baseURL, bytes.NewBuffer(dataJson), "POST", "application/json", true, authCookies)
	if err != nil {
		fmt.Println("Error sending sync request:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("sync failed with status:", resp.Status)
		os.Exit(1)
	}
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
	getCmd.Flags().BoolP("local", "l", false, "Get data from local server")
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
	RootCmd.AddCommand(syncFromServerCmd)
	RootCmd.AddCommand(syncToServerCmd)
}
