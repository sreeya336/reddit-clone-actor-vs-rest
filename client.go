package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	// Prompt for client ID
	fmt.Print("Please provide your Client ID: ")
	clientIDInput, _ := reader.ReadString('\n')
	clientIDInput = strings.TrimSpace(clientIDInput)
	clientID := clientIDInput

	fmt.Printf("\nHello Client %s! Select an action from the menu below.\n", clientID)

	for {
		fmt.Printf("\nClient %s: Pick an option:\n", clientID)
		fmt.Println(`
1.  Generate RSA Keys
2.  Register an User
3.  Creating a Subreddit
4.  Join a Subreddit
5.  Add Post to Subreddit
6.  List All Subreddits
7.  View Posts in a Subreddit
8.  Add a Comment on a Post
9.  Reply to a Comment
10. Like Post
11. Dislike Post
12. Send a Message
13. View Messages
14. Verify and Retrieve a Post
15. Exit
`)

		fmt.Printf("Client %s: Enter your selection: ", clientID)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			privateKey, publicKey, err := generateKeys()
			if err != nil {
				fmt.Printf("Client %s: Unable to generate keys: %v\n", clientID, err)
				continue
			}
			fmt.Printf("Client %s: Successfully created a Private Key:\n%s\n", clientID, privateKey)
			fmt.Printf("Client %s: Here is your Public Key:\n%s\n", clientID, publicKey)

		case "2":
			fmt.Printf("Client %s: Please enter your username: ", clientID)
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)

			fmt.Printf("Client %s: Paste your public key (PEM format). Hit Enter twice to finish:\n", clientID)
			publicKey := readMultilineInput(reader)

			data := map[string]interface{}{"Username": username, "PublicKey": publicKey}
			sendPostRequest(clientID, "http://localhost:8080/users", data)

		case "3":
			fmt.Printf("Client %s: Enter the name of your subreddit: ", clientID)
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)

			data := map[string]interface{}{"Name": name}
			sendPostRequest(clientID, "http://localhost:8080/subreddits", data)

		case "4":
			fmt.Printf("Client %s: Provide your username: ", clientID)
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)

			fmt.Printf("Client %s: Name the subreddit you wish to join: ", clientID)
			subreddit, _ := reader.ReadString('\n')
			subreddit = strings.TrimSpace(subreddit)

			data := map[string]interface{}{"Username": username, "SubredditName": subreddit}
			sendPostRequest(clientID, "http://localhost:8080/subreddits/join", data)

		case "5": // Create a post in a subreddit
			fmt.Printf("Client %s: Enter your username: ", clientID)
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)

			fmt.Printf("Client %s: Specify the subreddit where you want to post: ", clientID)
			subreddit, _ := reader.ReadString('\n')
			subreddit = strings.TrimSpace(subreddit)

			fmt.Printf("Client %s: Provide a title for your post: ", clientID)
			title, _ := reader.ReadString('\n')
			title = strings.TrimSpace(title)

			fmt.Printf("Client %s: Write the content of your post: ", clientID)
			content, _ := reader.ReadString('\n')
			content = strings.TrimSpace(content)

			fmt.Printf("Client %s: Paste your private key (PEM format). Hit Enter twice when done:\n", clientID)
			privateKey := readMultilineInput(reader)

			createPost(clientID, username, subreddit, title, content, privateKey)

		case "6":
			url := "http://localhost:8080/subreddits"
			sendGetRequest(clientID, url)

		case "7":
			fmt.Printf("Client %s: Enter the subreddit name to view posts: ", clientID)
			subredditName, _ := reader.ReadString('\n')
			subredditName = strings.TrimSpace(subredditName)

			url := fmt.Sprintf("http://localhost:8080/subreddits/%s/posts", subredditName)
			sendGetRequest(clientID, url)

		case "8":
			fmt.Printf("Client %s: Provide your username: ", clientID)
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)

			fmt.Printf("Client %s: Specify the post ID you want to comment on: ", clientID)
			postID, _ := reader.ReadString('\n')
			postID = strings.TrimSpace(postID)

			fmt.Printf("Client %s: Write your comment: ", clientID)
			content, _ := reader.ReadString('\n')
			content = strings.TrimSpace(content)

			data := map[string]interface{}{
				"PostID":   postID,
				"Content":  content,
				"Author":   username,
				"ParentID": "",
			}
			sendPostRequest(clientID, "http://localhost:8080/comments", data)

		case "9":
			fmt.Printf("Client %s: Provide your username: ", clientID)
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)

			fmt.Printf("Client %s: Specify the post ID: ", clientID)
			postID, _ := reader.ReadString('\n')
			postID = strings.TrimSpace(postID)

			fmt.Printf("Client %s: Enter the ID of the parent comment: ", clientID)
			parentID, _ := reader.ReadString('\n')
			parentID = strings.TrimSpace(parentID)

			fmt.Printf("Client %s: Write your reply: ", clientID)
			content, _ := reader.ReadString('\n')
			content = strings.TrimSpace(content)

			data := map[string]interface{}{
				"PostID":   postID,
				"ParentID": parentID,
				"Content":  content,
				"Author":   username,
			}
			sendPostRequest(clientID, "http://localhost:8080/comments", data)

		case "10":
			fmt.Printf("Client %s: Specify the post ID you want to upvote: ", clientID)
			postID, _ := reader.ReadString('\n')
			postID = strings.TrimSpace(postID)

			data := map[string]interface{}{
				"PostID":   postID,
				"IsUpvote": true,
			}
			sendPostRequest(clientID, "http://localhost:8080/votes", data)

		case "11":
			fmt.Printf("Client %s: Specify the post ID you want to downvote: ", clientID)
			postID, _ := reader.ReadString('\n')
			postID = strings.TrimSpace(postID)

			data := map[string]interface{}{
				"PostID":   postID,
				"IsUpvote": false,
			}
			sendPostRequest(clientID, "http://localhost:8080/votes", data)

		case "12":
			fmt.Printf("Client %s: Provide your username: ", clientID)
			from, _ := reader.ReadString('\n')
			from = strings.TrimSpace(from)

			fmt.Printf("Client %s: Enter the recipient's username: ", clientID)
			to, _ := reader.ReadString('\n')
			to = strings.TrimSpace(to)

			fmt.Printf("Client %s: Type your message: ", clientID)
			content, _ := reader.ReadString('\n')
			content = strings.TrimSpace(content)

			data := map[string]interface{}{
				"From":    from,
				"To":      to,
				"Content": content,
			}
			sendPostRequest(clientID, "http://localhost:8080/messages/send", data)

		case "13":
			fmt.Printf("Client %s: Provide your username to view messages: ", clientID)
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)

			data := map[string]interface{}{
				"Username": username,
			}
			sendPostRequest(clientID, "http://localhost:8080/messages/display", data)

		case "14":
			fmt.Printf("Client %s: Specify the post ID to retrieve and verify: ", clientID)
			postID, _ := reader.ReadString('\n')
			postID = strings.TrimSpace(postID)

			url := fmt.Sprintf("http://localhost:8080/posts/%s", postID)
			sendGetRequest(clientID, url)

		case "15":
			fmt.Printf("Client %s: Shutting down. Have a great day!\n", clientID)
			return

		default:
			fmt.Printf("Client %s: Invalid selection. Please try again.\n", clientID)
		}
	}
}




func createPost(clientID, username, subreddit, title, content, privateKey string) {
    // Validate and parse the private key
    fmt.Printf("Client %s: Validating private key...\n", clientID)
    parsedPrivateKey, err := parsePrivateKey(privateKey)
    if err != nil {
        fmt.Printf("Client %s: Invalid private key: %v\n", clientID, err)
        return
    }

    // Generate content hash
    hash := sha256.Sum256([]byte(content))

    // Sign the content
    fmt.Printf("Client %s: Signing content...\n", clientID)
    signature, err := rsa.SignPKCS1v15(rand.Reader, parsedPrivateKey, crypto.SHA256, hash[:])
    if err != nil {
        fmt.Printf("Client %s: Error signing post: %v\n", clientID, err)
        return
    }
    encodedSignature := base64.StdEncoding.EncodeToString(signature)

    // Log signature and hash
    fmt.Printf("Client %s: Content Hash: %x\n", clientID, hash)
    fmt.Printf("Client %s: Signature: %s\n", clientID, encodedSignature)

    // Prepare payload
    data := map[string]interface{}{
        "Username":      username,
        "SubredditName": subreddit,
        "Title":         title,
        "Content":       content,
        "Signature":     encodedSignature,
    }

    // Send post request
    sendPostRequest(clientID, "http://localhost:8080/posts", data)
}

func readMultilineInput(reader *bufio.Reader) string {
    var input strings.Builder
    for {
        line, _ := reader.ReadString('\n')
        if strings.TrimSpace(line) == "" { // Exit on empty line
            break
        }
        input.WriteString(line) // Preserve newlines
    }
    return input.String()
}


func sendPostRequest(clientID string, url string, data map[string]interface{}) {
    jsonData, _ := json.Marshal(data)
    fmt.Printf("Client %s: Sending POST request to %s with payload: %s\n", clientID, url, string(jsonData))

    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        fmt.Printf("Client %s: Error creating request: %v\n", clientID, err)
        return
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Client-ID", clientID)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        fmt.Printf("Client %s: Error sending POST request: %v\n", clientID, err)
        return
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    fmt.Printf("Client %s: Response: %v\n", clientID, result)
}

func sendGetRequest(clientID, url string) {
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        fmt.Printf("Client %s: Error creating GET request: %v\n", clientID, err)
        return
    }
    req.Header.Set("Client-ID", clientID)
    
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        fmt.Printf("Client %s: Error sending GET request: %v\n", clientID, err)
        return
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    fmt.Printf("Client %s: Response: %v\n", clientID, result)
}


func generateKeys() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	publicPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(privatePem), string(publicPem), nil
}

func parsePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(privateKeyPEM))
    if block == nil {
        return nil, errors.New("failed to decode PEM block: block is nil or improperly formatted")
    }
    if block.Type != "RSA PRIVATE KEY" {
        return nil, fmt.Errorf("unexpected PEM block type: %s (expected 'RSA PRIVATE KEY')", block.Type)
    }
    key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
    }
    return key, nil
}


func signPost(content string, privateKey *rsa.PrivateKey) (string, error) {
	hash := sha256.Sum256([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func clientLogger(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Suppress automatic logging for all endpoints
        next.ServeHTTP(w, r)
    })
}
