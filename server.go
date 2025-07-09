package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// Models
type User struct {
	Username  string
	PublicKey string
}

type Subreddit struct {
	Name        string
	Members     []string
	Posts       map[string]*Post
	PostCounter int
}

type Post struct {
	ID        string
	Title     string
	Content   string
	Author    string
	Signature string
	Votes     int
	Comments  []string
}


// Add the Message struct to represent a message between users
type Message struct {
	From    string `json:"From"`
	To      string `json:"To"`
	Content string `json:"Content"`
}

// Global Data
var (
	users      = make(map[string]User)
	subreddits = make(map[string]*Subreddit)
	messages   = make(map[string][]Message) // Define messages map
	mutex      = &sync.Mutex{}
)

// Remove unused "crypto/rand" import from the import section


// Logging Helper
func logAction(clientID, action, details string) {
	log.Printf("%s [CLIENT %s] ACTION: %s | DETAILS: %s", time.Now().Format("2006-01-02 15:04:05"), clientID, action, details)
}

// Register User
func registerUserHandler(w http.ResponseWriter, r *http.Request) {
    clientID := r.Header.Get("Client-ID")
    if clientID == "" {
        clientID = "Unknown"
    }

    var req map[string]string
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    username := req["Username"]
    publicKey := req["PublicKey"]

    mutex.Lock()
    defer mutex.Unlock()

    if _, exists := users[username]; exists {
        http.Error(w, "Username already exists", http.StatusConflict)
        return
    }

    users[username] = User{
        Username:  username,
        PublicKey: publicKey,
    }

    logAction(clientID, "REGISTER_USER", fmt.Sprintf("Username: %s", username))
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

// Create Subreddit
func createSubredditHandler(w http.ResponseWriter, r *http.Request) {
    clientID := r.Header.Get("Client-ID")
    if clientID == "" {
        clientID = "Unknown"
    }

    var req map[string]string
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    name := req["Name"]

    mutex.Lock()
    defer mutex.Unlock()

    if _, exists := subreddits[name]; exists {
        http.Error(w, "Subreddit already exists", http.StatusConflict)
        return
    }

    subreddits[name] = &Subreddit{
        Name:        name,
        Posts:       make(map[string]*Post),
        PostCounter: 0,
    }

    logAction(clientID, "CREATE_SUBREDDIT", fmt.Sprintf("Subreddit: %s", name))
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]string{"message": "Subreddit created successfully"})
}

// Join Subreddit
func joinSubredditHandler(w http.ResponseWriter, r *http.Request) {
    clientID := r.Header.Get("Client-ID")
    if clientID == "" {
        clientID = "Unknown"
    }

    var req map[string]string
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    username := req["Username"]
    subredditName := req["SubredditName"]

    mutex.Lock()
    defer mutex.Unlock()

    subreddit, exists := subreddits[subredditName]
    if !exists {
        http.Error(w, "Subreddit not found", http.StatusNotFound)
        return
    }

    for _, member := range subreddit.Members {
        if member == username {
            w.WriteHeader(http.StatusOK)
            json.NewEncoder(w).Encode(map[string]string{"message": "Already a member"})
            return
        }
    }

    subreddit.Members = append(subreddit.Members, username)
    logAction(clientID, "JOIN_SUBREDDIT", fmt.Sprintf("Subreddit: %s | Username: %s", subredditName, username))
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "Joined subreddit successfully"})
}

// Create Post
func createPostHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username      string `json:"Username"`
        SubredditName string `json:"SubredditName"`
        Title         string `json:"Title"`
        Content       string `json:"Content"`
        Signature     string `json:"Signature"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    mutex.Lock()
    defer mutex.Unlock()

    subreddit, exists := subreddits[req.SubredditName]
    if !exists {
        http.Error(w, "Subreddit not found", http.StatusNotFound)
        return
    }

    user, userExists := users[req.Username]
    if !userExists {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    publicKey, err := parsePublicKey(user.PublicKey)
    if err != nil {
        http.Error(w, "Invalid public key", http.StatusInternalServerError)
        return
    }

    contentHash := sha256.Sum256([]byte(req.Content))
    decodedSignature, err := base64.StdEncoding.DecodeString(req.Signature)
    if err != nil {
        http.Error(w, "Invalid signature format", http.StatusBadRequest)
        return
    }

    if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, contentHash[:], decodedSignature); err != nil {
        http.Error(w, "Signature verification failed", http.StatusUnauthorized)
        return
    }

    postID := fmt.Sprintf("p%d", subreddit.PostCounter+1)
    post := &Post{
        ID:        postID,
        Title:     req.Title,
        Content:   req.Content,
        Author:    req.Username,
        Signature: req.Signature,
        Votes:     0,
    }

    subreddit.Posts[postID] = post
    subreddit.PostCounter++

    logAction("Unknown", "CREATE_POST", fmt.Sprintf("PostID: %s | Subreddit: %s | Author: %s", postID, req.SubredditName, req.Username))
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]string{"message": "Post created successfully", "postID": postID})
}

// Parse Public Key
func parsePublicKey(publicKeyStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

func getUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    username := vars["username"]

    mutex.Lock()
    defer mutex.Unlock()

    user, exists := users[username]
    if !exists {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{"PublicKey": user.PublicKey})
}

func listSubredditsHandler(w http.ResponseWriter, r *http.Request) {
    clientID := r.Header.Get("Client-ID")
    if clientID == "" {
        clientID = "Unknown"
    }

    mutex.Lock()
    defer mutex.Unlock()

    subredditList := make([]string, 0, len(subreddits))
    for name := range subreddits {
        subredditList = append(subredditList, name)
    }

    logAction(clientID, "LIST_SUBREDDITS", fmt.Sprintf("Subreddits: %v", subredditList))
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]interface{}{"Subreddits": subredditList})
}

// List Posts in Subreddit
func listPostsInSubredditHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    subredditName := vars["subredditName"]

    mutex.Lock()
    defer mutex.Unlock()

    subreddit, exists := subreddits[subredditName]
    if !exists {
        http.Error(w, "Subreddit not found", http.StatusNotFound)
        return
    }

    posts := make([]map[string]interface{}, 0)
    for _, post := range subreddit.Posts {
        posts = append(posts, map[string]interface{}{
            "ID":     post.ID,
            "Title":  post.Title,
            "Author": post.Author,
            "Votes":  post.Votes,
        })
    }

    logAction("Unknown", "LIST_POSTS", fmt.Sprintf("Subreddit: %s | Posts: %d", subredditName, len(posts)))
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]interface{}{"posts": posts})
}

// Get Post
func getPostHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	postID := vars["postID"]

	mutex.Lock()
	defer mutex.Unlock()

	// Search for the post by ID
	for _, subreddit := range subreddits {
		if post, exists := subreddit.Posts[postID]; exists {
			// Fetch author details and their public key
			user, userExists := users[post.Author]
			if !userExists {
				http.Error(w, "Author not found", http.StatusNotFound)
				return
			}

			publicKey, err := parsePublicKey(user.PublicKey)
			if err != nil {
				http.Error(w, "Invalid public key", http.StatusInternalServerError)
				return
			}

			// Decode the received signature
			sigBytes, err := base64.StdEncoding.DecodeString(post.Signature)
			if err != nil {
				http.Error(w, "Invalid signature format", http.StatusBadRequest)
				return
			}

			// Compute the hash of the content
			hash := sha256.Sum256([]byte(post.Content))

			// Verify the signature
			err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigBytes)
			if err != nil {
				log.Printf("%s [CLIENT Unknown] ACTION: Verify Post | Post ID: %s | Status: Signature verification failed", time.Now().Format("2006-01-02 15:04:05"), postID)
				http.Error(w, "Signature verification failed", http.StatusUnauthorized)
				return
			}

			// Log the post details and signature
			log.Printf("%s [CLIENT Unknown] ACTION: Retrieve Post | Post ID: %s | Author: %s | Content: %s | Signature: %s", time.Now().Format("2006-01-02 15:04:05"), postID, post.Author, post.Content, post.Signature)

			json.NewEncoder(w).Encode(post)
			return
		}
	}

	http.Error(w, "Post not found", http.StatusNotFound)
}

func addCommentHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        PostID   string `json:"PostID"`
        Content  string `json:"Content"`
        Author   string `json:"Author"`
        ParentID string `json:"ParentID"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    mutex.Lock()
    defer mutex.Unlock()

    for _, subreddit := range subreddits {
        if post, exists := subreddit.Posts[req.PostID]; exists {
            commentID := fmt.Sprintf("c%d", len(post.Comments)+1)
            comment := fmt.Sprintf("%s: %s", req.Author, req.Content)

            post.Comments = append(post.Comments, comment)
            logAction("Unknown", "ADD_COMMENT", fmt.Sprintf("PostID: %s | CommentID: %s | Author: %s", req.PostID, commentID, req.Author))
            w.WriteHeader(http.StatusCreated)
            json.NewEncoder(w).Encode(map[string]string{"message": "Comment added successfully", "commentID": commentID})
            return
        }
    }

    http.Error(w, "Post not found", http.StatusNotFound)
}

func votePostHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        PostID   string `json:"PostID"`
        IsUpvote bool   `json:"IsUpvote"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    mutex.Lock()
    defer mutex.Unlock()

    for _, subreddit := range subreddits {
        if post, exists := subreddit.Posts[req.PostID]; exists {
            if req.IsUpvote {
                post.Votes++
            } else {
                post.Votes--
            }
            logAction("Unknown", "VOTE_POST", fmt.Sprintf("PostID: %s | NewVotes: %d", req.PostID, post.Votes))
            w.WriteHeader(http.StatusOK)
            json.NewEncoder(w).Encode(map[string]interface{}{"message": "Vote recorded", "newVotes": post.Votes})
            return
        }
    }

    http.Error(w, "Post not found", http.StatusNotFound)
}

// Send Message
func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	var req Message

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	messages[req.To] = append(messages[req.To], req)
	logAction("Unknown", "SEND_MESSAGE", fmt.Sprintf("From: %s | To: %s | Content: %s", req.From, req.To, req.Content))
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Message sent successfully"})
}

// Display Messages
func displayMessagesHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.Header.Get("Client-ID")
	if clientID == "" {
		clientID = "Unknown"
	}

	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	username := req["Username"]

	mutex.Lock()
	defer mutex.Unlock()

	userMessages, exists := messages[username]
	if !exists || len(userMessages) == 0 {
		log.Printf("%s [CLIENT %s] ACTION: View Messages | User: %s | Messages: No messages found", time.Now().Format("2006-01-02 15:04:05"), clientID, username)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]Message{}) // Return an empty list if no messages exist
		return
	}

	// Log messages on server side
	log.Printf("%s [CLIENT %s] ACTION: View Messages | User: %s | Messages: %+v", time.Now().Format("2006-01-02 15:04:05"), clientID, username, userMessages)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userMessages) // Return the messages for the user
}

// Main Function
func main() {
	r := mux.NewRouter()

	// User management
	r.HandleFunc("/users", registerUserHandler).Methods("POST")
	r.HandleFunc("/users/{username}/publickey", getUserPublicKeyHandler).Methods("GET")

	// Subreddit management
	r.HandleFunc("/subreddits", createSubredditHandler).Methods("POST")
	r.HandleFunc("/subreddits", listSubredditsHandler).Methods("GET")
	r.HandleFunc("/subreddits/join", joinSubredditHandler).Methods("POST")
	r.HandleFunc("/subreddits/{subredditName}/posts", listPostsInSubredditHandler).Methods("GET")

	// Post management
	r.HandleFunc("/posts", createPostHandler).Methods("POST")
	r.HandleFunc("/posts/{postID}", getPostHandler).Methods("GET")

	// Comments
	r.HandleFunc("/comments", addCommentHandler).Methods("POST")

	// Voting
	r.HandleFunc("/votes", votePostHandler).Methods("POST")

	// Messaging
	r.HandleFunc("/messages/send", sendMessageHandler).Methods("POST")
	r.HandleFunc("/messages/display", displayMessagesHandler).Methods("POST")

	log.Printf("%s [SERVER] Server is live at port 8080", time.Now().Format("2006-01-02 15:04:05"))
	log.Fatal(http.ListenAndServe(":8080", r))
}
