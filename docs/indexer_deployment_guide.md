# CIRO Network Indexer Deployment Guide

## 🎯 Overview

This guide walks through deploying the CIRO Network blockchain event indexer to solve the issue where StarkScan shows "0 events" for our contracts. Our custom indexer will provide:

- ✅ **Real-time blockchain event monitoring**
- ✅ **Custom dashboard for viewing activity**
- ✅ **Historical event indexing**
- ✅ **API for querying blockchain data**
- ✅ **Independence from third-party explorers**

## 🚨 Problem Statement

**Issue**: StarkScan and other block explorers show "0 events, 0 transactions" for CIRO Network accounts and contracts, even though:
- Our contracts are deployed and functional
- Transactions exist on-chain (verified via `starkli`)
- Contract calls return correct data

**Root Cause**: External explorer indexing delays/issues with Sepolia testnet

**Solution**: Deploy our own blockchain event indexer

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Starknet      │───▶│   Event         │───▶│   PostgreSQL    │
│   RPC Node      │    │   Indexer       │    │   Database      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   Web Dashboard │
                       │   (Port 3000)   │
                       └─────────────────┘
```

## 📋 Prerequisites

### **System Requirements**
- Rust 1.70+ with Cargo
- PostgreSQL 13+
- 4GB+ RAM
- 50GB+ storage (for blockchain data)
- Stable internet connection

### **Environment Setup**
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install PostgreSQL (Ubuntu/Debian)
sudo apt update
sudo apt install postgresql postgresql-contrib

# Install PostgreSQL (macOS)
brew install postgresql@14
brew services start postgresql@14
```

## 🚀 Quick Start Deployment

### **Step 1: Clone and Build**
```bash
cd rust-node
cargo build --release --bin indexer --bin dashboard
```

### **Step 2: Database Setup**
```bash
# Create database
sudo -u postgres createdb ciro_indexer

# Create user
sudo -u postgres psql
CREATE USER ciro_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE ciro_indexer TO ciro_user;
\q

# Run migrations
export DATABASE_URL="postgresql://ciro_user:secure_password@localhost/ciro_indexer"
sqlx migrate run --source migrations
```

### **Step 3: Start Indexer**
```bash
./target/release/indexer \
  --rpc-url "https://starknet-sepolia.public.blastapi.io" \
  --database-url "postgresql://ciro_user:secure_password@localhost/ciro_indexer" \
  --treasury-timelock "0x04736828c69fda6977bdb97c982db6bf1bbcae0396a2faac450b2ec7338089c7" \
  --reputation-manager "0x02f0ce7e13e113e91f3a4669f742e7470f2bdfb3c7146aff1d449fddf92b7dc0" \
  --poll-interval 5 \
  --index-historical
```

### **Step 4: Start Dashboard**
```bash
./target/release/dashboard \
  --database-url "postgresql://ciro_user:secure_password@localhost/ciro_indexer" \
  --port 3000
```

### **Step 5: Access Dashboard**
Open browser to: **http://localhost:3000**

## 🔧 Production Deployment

### **Docker Compose Setup**
```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: ciro_indexer
      POSTGRES_USER: ciro_user
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    restart: unless-stopped

  indexer:
    image: ciro/indexer:latest
    environment:
      DATABASE_URL: "postgresql://ciro_user:${POSTGRES_PASSWORD}@postgres:5432/ciro_indexer"
      RUST_LOG: "info,ciro_node=debug"
    depends_on:
      - postgres
    restart: unless-stopped
    command: >
      indexer
      --rpc-url "https://starknet-sepolia.public.blastapi.io"
      --treasury-timelock "0x04736828c69fda6977bdb97c982db6bf1bbcae0396a2faac450b2ec7338089c7"
      --reputation-manager "0x02f0ce7e13e113e91f3a4669f742e7470f2bdfb3c7146aff1d449fddf92b7dc0"
      --poll-interval 3
      --batch-size 200
      --index-historical

  dashboard:
    image: ciro/dashboard:latest
    environment:
      DATABASE_URL: "postgresql://ciro_user:${POSTGRES_PASSWORD}@postgres:5432/ciro_indexer"
    ports:
      - "3000:3000"
    depends_on:
      - postgres
    restart: unless-stopped

volumes:
  postgres_data:
```

### **Environment Variables**
```bash
# .env file
POSTGRES_PASSWORD=your_secure_password_here
DATABASE_URL=postgresql://ciro_user:${POSTGRES_PASSWORD}@localhost:5432/ciro_indexer
RUST_LOG=info,ciro_node=debug
```

## 📊 Monitoring & Maintenance

### **Health Checks**
```bash
# Check indexer status
curl http://localhost:3000/api/stats

# Check database connection
psql $DATABASE_URL -c "SELECT COUNT(*) FROM blockchain_events;"

# Check latest indexed block
psql $DATABASE_URL -c "SELECT last_processed_block FROM indexer_state WHERE indexer_name='ciro_network_indexer';"
```

### **Log Monitoring**
```bash
# Indexer logs
journalctl -u ciro-indexer -f

# Dashboard logs  
journalctl -u ciro-dashboard -f

# Database logs
sudo journalctl -u postgresql -f
```

### **Performance Tuning**
```bash
# PostgreSQL optimization
sudo -u postgres psql -d ciro_indexer

-- Increase work memory
ALTER SYSTEM SET work_mem = '256MB';

-- Optimize for analytics workloads
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';

-- Restart PostgreSQL
sudo systemctl restart postgresql
```

## 🔍 Troubleshooting

### **Common Issues**

#### **1. Indexer Not Starting**
```bash
# Check RPC connectivity
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"starknet_blockNumber","params":[],"id":1}' \
  https://starknet-sepolia.public.blastapi.io

# Check database connection
psql $DATABASE_URL -c "SELECT 1;"
```

#### **2. No Events Being Indexed**
```bash
# Check if contracts have recent activity
starkli call 0x04736828c69fda6977bdb97c982db6bf1bbcae0396a2faac450b2ec7338089c7 \
  get_required_approvals --network sepolia

# Check indexer logs for errors
tail -f /var/log/ciro-indexer.log
```

#### **3. Dashboard Not Loading**
```bash
# Check dashboard service
systemctl status ciro-dashboard

# Check port availability
netstat -tulpn | grep :3000

# Check database queries
psql $DATABASE_URL -c "SELECT COUNT(*) FROM recent_events;"
```

#### **4. High Memory Usage**
```bash
# Optimize batch size
./indexer --batch-size 50  # Reduce from default 100

# Monitor memory usage
htop -p $(pgrep indexer)

# Database vacuum
psql $DATABASE_URL -c "VACUUM ANALYZE;"
```

## 📈 Scaling Considerations

### **High-Volume Production**
```bash
# Multiple indexer instances (different block ranges)
./indexer --start-block 0 --end-block 1000000 &
./indexer --start-block 1000001 --end-block 2000000 &

# Read replicas for dashboard
DATABASE_READ_URL="postgresql://readonly_user:pass@read-replica:5432/ciro_indexer"

# Load balancer for dashboard
nginx upstream configuration
```

### **Monitoring Stack**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ciro-indexer'
    static_configs:
      - targets: ['localhost:9090']
  
  - job_name: 'ciro-dashboard'
    static_configs:
      - targets: ['localhost:3000']
```

## 🎯 Expected Results

### **Immediate Benefits**
- ✅ **Real-time visibility** into CIRO Network transactions
- ✅ **Independence** from StarkScan/third-party explorers
- ✅ **Custom analytics** tailored to CIRO Network needs
- ✅ **Historical data** for all contract interactions

### **Performance Metrics**
```
📊 Expected Performance:
├── Event Processing: 1000+ events/minute
├── API Response Time: <100ms
├── Dashboard Load Time: <2 seconds
├── Database Storage: ~100MB/month
└── Memory Usage: ~512MB RAM
```

### **Data Coverage**
```
📋 Indexed Events:
├── Treasury Timelock: ✅ All governance transactions
├── Reputation Manager: ✅ All reputation updates  
├── Job Manager: 🔄 Ready for deployment
├── CDC Pool: 🔄 Ready for deployment
└── CIRO Token: 🔄 Ready for deployment
```

## 🚀 Going Live

### **Final Checklist**
- [ ] Database migrations applied
- [ ] Indexer service running and healthy
- [ ] Dashboard accessible and showing data
- [ ] Monitoring configured
- [ ] Backup strategy implemented
- [ ] SSL certificates configured (for production)
- [ ] Firewall rules configured
- [ ] Log rotation configured

### **Community Announcement**
```markdown
🎉 CIRO Network Indexer is LIVE!

While third-party explorers show limited data, our custom indexer provides:
- Real-time transaction monitoring
- Complete event history
- Custom analytics dashboard

Access: https://explorer.ciro.network
```

---

## 📞 Support

- **Technical Issues**: Check logs and troubleshooting section
- **Performance**: Monitor dashboard metrics and optimize batch sizes
- **Scaling**: Follow scaling guidelines for high-volume scenarios
- **Community**: Share indexer status in governance channels

**🎯 Result**: Complete independence from third-party block explorers with real-time visibility into CIRO Network activity!