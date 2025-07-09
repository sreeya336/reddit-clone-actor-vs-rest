# Reddit Engine MultiModel

![Go](https://img.shields.io/badge/Language-Go-blue)
![Actor Model](https://img.shields.io/badge/Model-Actor--Based-purple)
![REST API](https://img.shields.io/badge/Model-REST--API-green)
![Security](https://img.shields.io/badge/Security-RSA--2048-important)
![Concurrency](https://img.shields.io/badge/Feature-Concurrent--Users-informational)


This project demonstrates two implementations of a Reddit-like platform:

<p align="center">
  <img src="https://github.com/sreeya336/reddit-clone-actor-vs-rest/blob/main/reddit-image.png?raw=true" width="150" alt="Reddit Logo">
</p>




1. **Actor-Based Simulation** – Built using an actor model where users, posts, comments, and messages are modeled as asynchronous message-passing entities. It enables concurrency and tests distributed behavior by simulating multiple users interacting simultaneously.
2. **REST API with RSA Security** – Developed in Go, this version provides a secure, interactive Reddit clone with support for user actions and RSA-2048 digital signature verification for integrity and authenticity.

---

## Features

- User registration and login
- Subreddit creation and joining
- Posting and commenting
- Upvoting and downvoting
- Private messaging between users
- Secure communication via digital signatures (REST version)
- Concurrent interactions via message passing (Actor version)

---

## Project Structure

reddit-engine-multimodel/
│
├── client.go # Command-line interface for interacting with the server
├── server.go # REST API server handling core logic
├── go.mod / go.sum # Go module files
│
├── docs/
│ ├── report.pdf # Detailed project report
│ └── video_demo.mov # Demo video (if too large, host externally and link)
│
└── actor_model/ # Actor-based simulation (optional, if included)

---

## Tech Stack

| Component       | Technology                         |
|-----------------|------------------------------------|
| Language        | Go                                 |
| REST API        | Go net/http                        |
| CLI             | Go                                 |
| Simulation      | Actor model with message passing   |
| Security        | RSA-2048 digital signature         |
| Report          | PDF                                |

---

## How to Run (REST API Version)

1. Clone the repository:

```bash
git clone https://github.com/sreeya336/reddit-engine-multimodel.git
cd reddit-engine-multimodel

## How to Run (REST API Version)

1. Run the server:

    ```bash
    go run server.go
    ```

2. In another terminal, run the client:

    ```bash
    go run client.go
    ```

3. Follow the prompts to register, create subreddits, post, comment, vote, and send private messages.

## Example User Flow

- User1 registers and creates a subreddit named "tech"
- User2 joins the "tech" subreddit
- User1 creates a post titled "Best programming language in 2025?"
- User2 comments and upvotes the post
- User1 and User2 exchange private messages
- The server verifies RSA signatures for each message to ensure authenticity

## Resources

- Project Report (PDF): docs/report.pdf
- Demo Video: [Demo Link](https://drive.google.com/your-video-link) *(replace with your actual link)*

## Authors

Sreeya Rudrangi  
Hemanth Krishna  
University of Florida  
Distributed Operating Systems Programming – Fall 2024
