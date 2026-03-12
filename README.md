# CYBR 3200 - Session Hijacking CTF

A set of four progressive Capture The Flag challenges designed to teach session management vulnerabilities. Students exploit intentionally vulnerable Flask web applications to learn about authentication weaknesses, session hijacking, and secure session management practices.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- A web browser with developer tools (for cookie inspection)
- Python 3 (optional, for writing exploit scripts)
- Familiarity with HTTP cookies and sessions

## Quick Start

```bash
cd session-hijacking-ctf

# Build and launch all four challenges
docker-compose up -d --build

# Verify everything is running
docker ps
```

Challenges will be available at:

| Port | Challenge | Difficulty | Vulnerability | CWE |
|------|-----------|------------|---------------|-----|
| 5001 | Predictable Tokens | Easy | Weak token generation (base64 user ID) | CWE-330 |
| 5002 | The Undying Session | Easy | No session expiration | CWE-613 |
| 5003 | Logout is a Lie | Easy-Medium | Client-side only logout | CWE-613 |
| 5004 | Token Entropy Crisis | Medium-Hard | Insufficient entropy (1000 possibilities) | CWE-330/331 |

## Customizing Flags

Edit the `FLAG` environment variables in `session-hijacking-ctf/docker-compose.yml` before deploying. The default values in the Dockerfiles are overridden by whatever you set in the compose file.

## CTFd Integration

A CTFd-compatible import file is provided at `session-hijacking-ctf/ctfd-import/challenges.json`. See the [session-hijacking-ctf README](session-hijacking-ctf/README.md) for import instructions.

## Project Structure

```
cybr3200/
├── README.md                              # This file
└── session-hijacking-ctf/
    ├── README.md                          # Challenge details and flags
    ├── INSTRUCTOR_GUIDE.md                # Solutions, oral defense questions, pedagogy
    ├── docker-compose.yml                 # Deploys all 4 challenges
    ├── ctfd-import/
    │   └── challenges.json                # CTFd platform import
    ├── challenge1-predictable-tokens/
    │   ├── app.py                         # Flask app
    │   └── Dockerfile
    ├── challenge2-undying-session/
    │   ├── app.py
    │   └── Dockerfile
    ├── challenge3-logout-lie/
    │   ├── app.py
    │   └── Dockerfile
    └── challenge4-entropy-crisis/
        ├── app.py
        ├── Dockerfile
        └── solver.py                      # Reference brute-force solution
```

## For Instructors

See [`session-hijacking-ctf/INSTRUCTOR_GUIDE.md`](session-hijacking-ctf/INSTRUCTOR_GUIDE.md) for:

- Detailed expected solutions and common student mistakes
- Oral defense / viva questions per challenge
- Deployment notes (including Cloudflare Tunnel setup)
- Variant ideas for future semesters
- Troubleshooting guide

## Learning Objectives

After completing these challenges, students should be able to:

- Identify weak session token generation schemes
- Explain why sessions must be expired server-side
- Demonstrate session replay and token forgery attacks
- Articulate the importance of cryptographic entropy in token generation
- Map vulnerabilities to OWASP A07:2021 (Identification and Authentication Failures)

## Stopping the Challenges

```bash
cd session-hijacking-ctf
docker-compose down
```

## License

Educational use only. Created for CYBR 3200 coursework.
