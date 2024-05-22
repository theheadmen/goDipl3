package clientapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/theheadmen/goDipl3/models"
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

		resp, err := http.Post("http://localhost:8080/register", "application/json", bytes.NewBuffer(userJson))
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

		resp, err := http.Post("http://localhost:8080/login", "application/json", bytes.NewBuffer(userJson))
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
	Use:   "store TYPE DATA flags",
	Short: "Store user data",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		dataType := args[0]
		data := args[1]

		meta, _ := cmd.Flags().GetString("meta")
		expiry, _ := cmd.Flags().GetString("expiry")
		cvv, _ := cmd.Flags().GetString("cvv")

		var dataToStore interface{}
		switch dataType {
		case "text":
			dataToStore = models.TextData{
				Data: data,
				Meta: meta,
			}
		case "binary":
			dataToStore = models.BinaryData{
				Data: []byte(data),
				Meta: meta,
			}
		case "bankcard":
			dataToStore = models.BankCard{
				Number: data,
				Meta:   meta,
				Expiry: expiry,
				CVV:    cvv,
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
		baseURL, err := url.Parse("http://localhost:8080/store")
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			os.Exit(1)
		}

		params := url.Values{}
		params.Add("type", dataType)
		baseURL.RawQuery = params.Encode()

		client := &http.Client{}
		req, err := http.NewRequest("POST", baseURL.String(), bytes.NewBuffer(dataJson))
		if err != nil {
			fmt.Println("Error creating request:", err)
			os.Exit(1)
		}

		req.Header.Set("Content-Type", "application/json")

		// Установка cookie в заголовки запроса
		for _, cookie := range authCookies {
			req.AddCookie(cookie)
		}

		resp, err := client.Do(req)
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

var getCmd = &cobra.Command{
	Use:   "get TYPE",
	Short: "Get user data",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dataType := args[0]

		// Создаем URL с параметром типа данных
		baseURL, err := url.Parse("http://localhost:8080/retrieve")
		if err != nil {
			fmt.Println("Error parsing URL:", err)
			os.Exit(1)
		}

		params := url.Values{}
		params.Add("type", dataType)
		baseURL.RawQuery = params.Encode()

		client := &http.Client{}
		req, err := http.NewRequest("GET", baseURL.String(), nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			os.Exit(1)
		}

		// Установка cookie в заголовки запроса
		for _, cookie := range authCookies {
			req.AddCookie(cookie)
		}

		resp, err := client.Do(req)
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
			fmt.Printf("BankCard: %+v\n", bankCard)
		default:
			fmt.Println("Unsupported data type")
			os.Exit(1)
		}
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of GophKeeper CLI",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("GophKeeper CLI version %s, built on %s\n", version, buildDate)
	},
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
}
