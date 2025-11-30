# Bitsage Network Coordinator

A production-ready coordinator system for the Bitsage Network, designed to manage job distribution, worker registration, and blockchain integration on Starknet.

## 🚀 Current Status

### ✅ Working Components
- **Simple Coordinator** - Basic job and worker management
- **Core Types** - Job, Worker, and Blockchain integration types
- **Configuration System** - Comprehensive configuration management
- **Basic Blockchain Integration** - Starknet client and contract interactions
- **Database Integration** - SQLite-based job and worker storage

### ❌ Known Issues
- **Network Module Compilation Errors** - P2P network, discovery, and gossip protocol issues
- **Enhanced Coordinator Type Mismatches** - NetworkCoordinator vs NetworkCoordinatorService conflicts
- **Missing Methods** - Several components have incomplete implementations
- **Async/Await Issues** - Incorrect handling of futures and async tasks

## 🏗️ Architecture

### Simple Coordinator (Working)
```
SimpleCoordinator
├── Job Management
│   ├── Job submission and tracking
│   ├── Job status updates
│   └── Job result collection
├── Worker Management
│   ├── Worker registration
│   ├── Health monitoring
│   └── Load balancing
├── Blockchain Integration
│   ├── Starknet client
│   ├── Contract interactions
│   └── Transaction management
└── REST API
    ├── Health endpoints
    ├── Job management
    └── Worker management
```

### Enhanced Coordinator (In Development)
```
EnhancedCoordinator
├── KafkaCoordinator
├── NetworkCoordinator
├── JobProcessor
├── WorkerManager
├── BlockchainIntegration
└── MetricsCollector
```

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+
- SQLite
- Starknet Sepolia testnet access

### Build and Run

1. **Build the project:**
```bash
cargo build
```

2. **Run the simple coordinator:**
```bash
cargo run --bin ciro-coordinator
```

3. **Run with custom config:**
```bash
cargo run --bin ciro-coordinator config.json
```

### Configuration

Create a `config.json` file:
```json
{
  "server_port": 8080,
  "blockchain": {
    "rpc_url": "https://alpha-sepolia.starknet.io",
    "chain_id": "SN_SEPOLIA",
    "contract_address": "0x1234567890abcdef",
    "private_key": "0x0000000000000000000000000000000000000000000000000000000000000001"
  },
  "database": {
    "url": "sqlite://./coordinator.db"
  }
}
```

## 📋 Available Commands

### Job Management
- Submit jobs with different types and priorities
- Track job status and completion
- Collect job results and distribute rewards

### Worker Management
- Register workers with capabilities
- Monitor worker health and performance
- Balance load across available workers

### Blockchain Integration
- Submit jobs to smart contracts
- Track transaction status
- Handle job completion and reward distribution

## 🔧 Development

### Current Focus Areas

1. **Fix Network Module Issues**
   - Resolve P2P network compilation errors
   - Fix discovery protocol implementation
   - Complete gossip protocol implementation

2. **Resolve Type Mismatches**
   - Align NetworkCoordinator and NetworkCoordinatorService
   - Fix missing method implementations
   - Correct async/await handling

3. **Complete Enhanced Coordinator**
   - Fix Kafka integration issues
   - Complete metrics collection
   - Implement proper error handling

### Compilation Issues to Address

#### Network Module (src/network/)
- **P2P Network**: Mutable borrow issues with Arc<P2PNetwork>
- **Discovery**: Future trait implementation issues
- **Gossip**: Missing P2PMessage variants and method signatures

#### Coordinator Module (src/coordinator/)
- **Type Mismatches**: NetworkCoordinator vs NetworkCoordinatorService
- **Missing Methods**: get_blockchain_stats, proper async handling
- **Kafka Integration**: Consumer/producer initialization issues

#### Blockchain Integration
- **Transaction Handling**: FieldElement unwrap_or issues
- **Error Handling**: Proper Result type handling

### Testing Strategy

1. **Unit Tests**
   - Test individual components
   - Mock external dependencies
   - Verify error handling

2. **Integration Tests**
   - Test coordinator workflows
   - Verify blockchain interactions
   - Test API endpoints

3. **End-to-End Tests**
   - Complete job lifecycle
   - Worker registration and job assignment
   - Blockchain transaction flow

## 🐛 Troubleshooting

### Common Issues

1. **Compilation Errors**
   - Most errors are in the enhanced coordinator
   - Use simple coordinator for immediate functionality
   - Focus on network module fixes first

2. **Blockchain Connection**
   - Verify RPC URL and network configuration
   - Check contract address and private key
   - Ensure sufficient balance for transactions

3. **Database Issues**
   - Verify SQLite file permissions
   - Check database URL format
   - Ensure proper schema initialization

### Debug Mode

Enable debug logging:
```bash
RUST_LOG=debug cargo run --bin ciro-coordinator
```

## 📊 Monitoring

### Health Checks
- Coordinator status endpoint: `GET /health`
- Component status: `GET /status`
- Job statistics: `GET /jobs/stats`
- Worker statistics: `GET /workers/stats`

### Metrics
- Job completion rates
- Worker performance metrics
- Blockchain transaction success rates
- Network connectivity status

## 🔄 Next Steps

### Phase 1: Fix Critical Issues (Priority 1)
1. **Resolve Network Module Compilation**
   - Fix P2P network mutable borrow issues
   - Complete discovery protocol implementation
   - Fix gossip protocol message handling

2. **Fix Type Mismatches**
   - Align NetworkCoordinator types
   - Implement missing methods
   - Fix async/await patterns

### Phase 2: Complete Enhanced Coordinator (Priority 2)
1. **Kafka Integration**
   - Fix consumer/producer initialization
   - Implement proper message handling
   - Add error recovery mechanisms

2. **Metrics and Monitoring**
   - Complete metrics collection
   - Add comprehensive logging
   - Implement health monitoring

### Phase 3: Production Features (Priority 3)
1. **Security**
   - Add authentication and authorization
   - Implement rate limiting
   - Add input validation

2. **Scalability**
   - Add load balancing
   - Implement caching
   - Add horizontal scaling support

3. **Reliability**
   - Add circuit breakers
   - Implement retry mechanisms
   - Add backup and recovery

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Make changes and add tests
4. Ensure all tests pass
5. Submit a pull request

### Code Style
- Follow Rust conventions
- Add comprehensive documentation
- Include unit tests for new features
- Update this README for significant changes

### Testing
- Run `cargo test` before submitting
- Add integration tests for new features
- Verify blockchain interactions work correctly

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review existing issues
3. Create a new issue with detailed information
4. Include logs and error messages

---

**Note**: The enhanced coordinator is currently under development. Use the simple coordinator for immediate functionality while the enhanced version is being completed.
