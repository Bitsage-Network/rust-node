# BitSage Network - Mainnet Deployment Checklist

## Pre-Deployment Verification

### 1. Code Readiness
- [x] All tests passing (70+ tests)
- [x] Proof generation pipeline complete (GPU + CPU fallback)
- [x] Backend mock data replaced with PostgreSQL queries
- [x] Starknet transaction signing implemented (ECDSA on STARK curve)
- [x] BFT validator consensus complete (SageGuard)
- [x] Privacy layer (ElGamal encryption) functional
- [x] No TODO/FIXME items in critical paths

### 2. Security Audit
- [ ] Smart contracts audited
- [ ] Rust node security review
- [ ] Private key handling verified (keystore encryption)
- [ ] Rate limiting configured
- [ ] TLS certificates provisioned

---

## Environment Configuration

### 3. Create Production `.env`
```bash
cp .env.example .env
```

**Required Variables:**
```env
# Database (use strong password)
DATABASE_URL=postgresql://bitsage:STRONG_PASSWORD@db-host:5432/bitsage
DB_PASSWORD=STRONG_PASSWORD

# Starknet Mainnet
STARKNET_NETWORK=mainnet
STARKNET_RPC_URL=https://rpc.starknet.lava.build

# Deployer Account (for transactions)
DEPLOYER_ADDRESS=0xYOUR_MAINNET_ACCOUNT_ADDRESS
DEPLOYER_PRIVATE_KEY=YOUR_PRIVATE_KEY
# OR use keystore (more secure):
KEYSTORE_PATH=./deployment/mainnet_keystore.json
KEYSTORE_PASSWORD=YOUR_KEYSTORE_PASSWORD

# Dashboard
NEXT_PUBLIC_API_URL=https://api.bitsage.network
NEXT_PUBLIC_WS_URL=wss://api.bitsage.network/ws
```

### 4. Update Contract Addresses
Edit `config/coordinator.toml` with mainnet contract addresses after deployment:
```toml
[starknet]
network = "mainnet"
rpc_url = "https://rpc.starknet.lava.build"
sage_token_address = "0x..."
prover_staking_address = "0x..."
job_manager_address = "0x..."
# ... other contracts
```

---

## Infrastructure Setup

### 5. Database
```bash
# Create PostgreSQL database
psql -c "CREATE DATABASE bitsage;"
psql -c "CREATE USER bitsage WITH PASSWORD 'your_password';"
psql -c "GRANT ALL PRIVILEGES ON DATABASE bitsage TO bitsage;"

# Run migrations
psql -d bitsage -f rust-node/migrations/001_initial_schema.sql
```

### 6. Build Docker Images
```bash
# Build coordinator
docker build -t bitsage-coordinator:latest -f rust-node/Dockerfile.coordinator .

# Build worker
docker build -t bitsage-worker:latest -f rust-node/Dockerfile.worker .
```

### 7. Deploy with Docker Compose
```bash
# Start services
docker-compose -f docker-compose.prod.yml up -d

# With monitoring (Prometheus + Grafana)
docker-compose -f docker-compose.prod.yml --profile monitoring up -d

# Check logs
docker-compose -f docker-compose.prod.yml logs -f coordinator
```

---

## Cairo Contract Deployment

### 8. Deploy Contracts to Mainnet
```bash
cd BitSage-Cairo-Smart-Contracts

# Build contracts
scarb build

# Deploy (requires funded mainnet account)
node scripts/deploy_mainnet.mjs
```

**Deployment Order:**
1. SageToken (ERC20)
2. ProverStaking
3. ReputationManager
4. JobManager
5. ProofVerifier / StwoBatchVerifier
6. PaymentRouter
7. Escrow
8. FeeManager

### 9. Initialize Contracts
```bash
# Set contract owner
# Configure fee parameters
# Whitelist initial validators
```

---

## Post-Deployment Verification

### 10. Health Checks
```bash
# API health
curl https://api.bitsage.network/api/health

# Validator status
curl https://api.bitsage.network/api/validator/status

# WebSocket connectivity
wscat -c wss://api.bitsage.network/ws
```

### 11. Functional Tests
- [ ] Worker registration works
- [ ] Job submission works
- [ ] Proof generation completes
- [ ] Proof verification on-chain succeeds
- [ ] Payment claims work
- [ ] Faucet disabled on mainnet

### 12. Monitoring Setup
- [ ] Prometheus scraping metrics
- [ ] Grafana dashboards configured
- [ ] Alerts configured (`alerts.yml`)
- [ ] Log aggregation (optional: ELK/Loki)

---

## Operational Runbook

### Start Services
```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Stop Services
```bash
docker-compose -f docker-compose.prod.yml down
```

### View Logs
```bash
docker-compose -f docker-compose.prod.yml logs -f coordinator
```

### Database Backup
```bash
pg_dump -h localhost -U bitsage bitsage > backup_$(date +%Y%m%d).sql
```

### Emergency: Pause Job Processing
```bash
# Set via config or restart with flag
docker-compose -f docker-compose.prod.yml restart coordinator
```

---

## Contract Addresses Reference

### Sepolia (Current - Testnet)
| Contract | Address |
|----------|---------|
| SageToken | `0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850` |
| ProverStaking | `0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b` |
| JobManager | `0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3` |
| Faucet | `0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3` |
| ProofVerifier | `0x17ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b` |

### Mainnet (After Deployment)
| Contract | Address |
|----------|---------|
| SageToken | `TBD` |
| ProverStaking | `TBD` |
| JobManager | `TBD` |
| ProofVerifier | `TBD` |

---

## Security Checklist

- [ ] Private keys stored securely (HSM/KMS recommended)
- [ ] Database credentials rotated
- [ ] TLS enabled on all public endpoints
- [ ] Rate limiting configured
- [ ] CORS restricted to known origins
- [ ] Faucet disabled on mainnet
- [ ] Audit logs enabled
- [ ] Backup strategy implemented
- [ ] Incident response plan documented

---

## Contact

- **Technical Issues:** [GitHub Issues](https://github.com/bitsage/bitsage-network/issues)
- **Security Vulnerabilities:** security@bitsage.network
