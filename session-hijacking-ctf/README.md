# Session Hijacking CTF Challenges

Four progressive challenges for teaching session management vulnerabilities in CYBR 3200.

## Quick Start

```bash
# Build and run all challenges
docker-compose up -d --build

# Verify containers are running
docker ps

# Test locally
curl http://localhost:5001  # Challenge 1
curl http://localhost:5002  # Challenge 2
curl http://localhost:5003  # Challenge 3
curl http://localhost:5004  # Challenge 4
```

## Challenge Overview

| Port | Challenge | Difficulty | Vulnerability |
|------|-----------|------------|---------------|
| 5001 | Predictable Tokens | Easy | Weak token generation (base64 user ID) |
| 5002 | The Undying Session | Easy | No session expiration |
| 5003 | Logout is a Lie | Easy-Medium | Client-side only logout |
| 5004 | Token Entropy Crisis | Medium-Hard | Insufficient entropy (1000 possibilities) |

## CTFd Import

1. In CTFd Admin, go to **Admin Panel → Config → Backup**
2. Click **Import** 
3. Upload `ctfd-import/challenges.json`
4. Edit each challenge description to add your actual URLs

## Flags

| Challenge | Flag |
|-----------|------|
| 1 | `flag{pr3d1ct4bl3_t0k3ns_4r3_n0t_s3cur3}` |
| 2 | `flag{s3ss10ns_sh0uld_3xp1r3_s0m3t1m3}` |
| 3 | `flag{l0g0ut_sh0uld_k1ll_s3rv3r_s3ss10n}` |
| 4 | `flag{3ntr0py_m4tt3rs_1000_1s_n0t_3n0ugh}` |

To customize flags, modify the environment variables in `docker-compose.yml`.

## Files

```
session-hijacking-ctf/
├── docker-compose.yml          # Deploy all challenges
├── INSTRUCTOR_GUIDE.md         # Detailed pedagogical notes
├── README.md                   # This file
├── ctfd-import/
│   └── challenges.json         # CTFd import file
├── challenge1-predictable-tokens/
│   ├── app.py
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
    └── solver.py               # Reference solution
```

## See Also

- `INSTRUCTOR_GUIDE.md` for detailed solutions, oral defense questions, and variant ideas
- `challenge4-entropy-crisis/solver.py` for the expected brute-force solution
