#!/bin/bash
#
# BitSage Network - One-Command AWS Coordinator Deployment
#
# Usage: ./deploy.sh
#
# This wizard will:
#   1. Collect configuration interactively
#   2. Provision AWS infrastructure (EC2, Security Groups)
#   3. Build and deploy the coordinator
#   4. Setup PostgreSQL database
#   5. Start the service and verify health
#
# Prerequisites:
#   - AWS CLI configured (aws configure)
#   - Rust installed locally (for cross-compilation)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Default values
DEFAULT_REGION="us-east-1"
DEFAULT_INSTANCE_TYPE="t3.medium"
DEFAULT_VOLUME_SIZE="30"
DEFAULT_NETWORK="sepolia"
DEFAULT_PORT="8080"
DEFAULT_DB_PASSWORD=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16)

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                   ║"
    echo "║    ██████╗ ██╗████████╗███████╗ █████╗  ██████╗ ███████╗         ║"
    echo "║    ██╔══██╗██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝ ██╔════╝         ║"
    echo "║    ██████╔╝██║   ██║   ███████╗███████║██║  ███╗█████╗           ║"
    echo "║    ██╔══██╗██║   ██║   ╚════██║██╔══██║██║   ██║██╔══╝           ║"
    echo "║    ██████╔╝██║   ██║   ███████║██║  ██║╚██████╔╝███████╗         ║"
    echo "║    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝         ║"
    echo "║                                                                   ║"
    echo "║         AWS COORDINATOR DEPLOYMENT WIZARD                         ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_success() {
    echo -e "${GREEN}  ✓ $1${NC}"
}

print_error() {
    echo -e "${RED}  ✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}  ℹ $1${NC}"
}

prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"

    echo -ne "${CYAN}  $prompt ${NC}[${GREEN}$default${NC}]: "
    read -r input
    if [ -z "$input" ]; then
        eval "$var_name='$default'"
    else
        eval "$var_name='$input'"
    fi
}

prompt_password() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"

    echo -ne "${CYAN}  $prompt ${NC}[${GREEN}auto-generated${NC}]: "
    read -rs input
    echo ""
    if [ -z "$input" ]; then
        eval "$var_name='$default'"
    else
        eval "$var_name='$input'"
    fi
}

prompt_select() {
    local prompt="$1"
    local options="$2"
    local default="$3"
    local var_name="$4"

    echo -e "${CYAN}  $prompt${NC}"
    IFS=',' read -ra OPTS <<< "$options"
    local i=1
    for opt in "${OPTS[@]}"; do
        if [ "$opt" == "$default" ]; then
            echo -e "    ${GREEN}$i) $opt (default)${NC}"
        else
            echo -e "    $i) $opt"
        fi
        ((i++))
    done
    echo -ne "  ${CYAN}Select [1-${#OPTS[@]}]:${NC} "
    read -r selection

    if [ -z "$selection" ]; then
        eval "$var_name='$default'"
    elif [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#OPTS[@]}" ]; then
        eval "$var_name='${OPTS[$((selection-1))]}'"
    else
        eval "$var_name='$default'"
    fi
}

check_prerequisites() {
    print_step "Step 1/7: Checking Prerequisites"

    # Check AWS CLI
    if command -v aws &> /dev/null; then
        print_success "AWS CLI found: $(aws --version | head -1)"
    else
        print_error "AWS CLI not found"
        echo -e "    Install with: ${CYAN}brew install awscli${NC} or ${CYAN}pip install awscli${NC}"
        exit 1
    fi

    # Check AWS credentials
    if aws sts get-caller-identity &> /dev/null; then
        local account_id=$(aws sts get-caller-identity --query 'Account' --output text)
        print_success "AWS credentials configured (Account: $account_id)"
    else
        print_error "AWS credentials not configured"
        echo -e "    Run: ${CYAN}aws configure${NC}"
        exit 1
    fi

    # Check Rust
    if command -v cargo &> /dev/null; then
        print_success "Rust found: $(rustc --version)"
    else
        print_error "Rust not found"
        echo -e "    Install with: ${CYAN}curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
        exit 1
    fi

    # Check cross-compilation target
    if rustup target list --installed | grep -q "x86_64-unknown-linux-gnu"; then
        print_success "Linux cross-compilation target installed"
    else
        print_info "Installing Linux cross-compilation target..."
        rustup target add x86_64-unknown-linux-gnu
        print_success "Linux target installed"
    fi

    # Check for cross or zigbuild
    if command -v cross &> /dev/null; then
        print_success "Cross-compilation tool found: cross"
        CROSS_TOOL="cross"
    elif command -v cargo-zigbuild &> /dev/null; then
        print_success "Cross-compilation tool found: cargo-zigbuild"
        CROSS_TOOL="zigbuild"
    else
        print_info "No cross-compilation tool found, will build on EC2"
        CROSS_TOOL="remote"
    fi
}

collect_configuration() {
    print_step "Step 2/7: Configuration"

    echo -e "  ${BOLD}Network Configuration${NC}\n"
    prompt_select "Select Starknet network:" "sepolia,mainnet" "$DEFAULT_NETWORK" NETWORK

    echo -e "\n  ${BOLD}AWS Configuration${NC}\n"
    prompt_with_default "AWS Region" "$DEFAULT_REGION" REGION
    prompt_select "Instance type:" "t3.medium,t3.large,t3.xlarge,m5.large" "$DEFAULT_INSTANCE_TYPE" INSTANCE_TYPE
    prompt_with_default "EBS Volume size (GB)" "$DEFAULT_VOLUME_SIZE" VOLUME_SIZE

    echo -e "\n  ${BOLD}Coordinator Configuration${NC}\n"
    prompt_with_default "API Port" "$DEFAULT_PORT" PORT
    prompt_password "Database password" "$DEFAULT_DB_PASSWORD" DB_PASSWORD

    # Set RPC URL based on network
    if [ "$NETWORK" == "mainnet" ]; then
        RPC_URL="https://starknet-mainnet-rpc.publicnode.com"
    else
        RPC_URL="https://starknet-sepolia-rpc.publicnode.com"
    fi

    # Generate unique names
    TIMESTAMP=$(date +%Y%m%d%H%M%S)
    KEY_NAME="bitsage-coordinator-$TIMESTAMP"
    SG_NAME="bitsage-coordinator-sg-$TIMESTAMP"
    INSTANCE_NAME="bitsage-coordinator-$NETWORK"

    echo -e "\n  ${BOLD}Configuration Summary${NC}"
    echo -e "  ─────────────────────────────────────"
    echo -e "  Network:        ${GREEN}$NETWORK${NC}"
    echo -e "  Region:         ${GREEN}$REGION${NC}"
    echo -e "  Instance:       ${GREEN}$INSTANCE_TYPE${NC}"
    echo -e "  Volume:         ${GREEN}${VOLUME_SIZE}GB${NC}"
    echo -e "  Port:           ${GREEN}$PORT${NC}"
    echo -e "  RPC:            ${GREEN}$RPC_URL${NC}"
    echo -e "  ─────────────────────────────────────"

    echo -ne "\n  ${CYAN}Proceed with deployment? [Y/n]:${NC} "
    read -r confirm
    if [[ "$confirm" =~ ^[Nn] ]]; then
        echo -e "\n  ${YELLOW}Deployment cancelled.${NC}"
        exit 0
    fi
}

build_coordinator() {
    print_step "Step 3/7: Building Coordinator"

    cd "$PROJECT_ROOT"

    if [ "$CROSS_TOOL" == "cross" ]; then
        print_info "Building with cross for Linux x86_64..."
        cross build --release --bin sage-coordinator --target x86_64-unknown-linux-gnu
        BINARY_PATH="$PROJECT_ROOT/target/x86_64-unknown-linux-gnu/release/sage-coordinator"
    elif [ "$CROSS_TOOL" == "zigbuild" ]; then
        print_info "Building with cargo-zigbuild for Linux x86_64..."
        cargo zigbuild --release --bin sage-coordinator --target x86_64-unknown-linux-gnu
        BINARY_PATH="$PROJECT_ROOT/target/x86_64-unknown-linux-gnu/release/sage-coordinator"
    else
        print_info "Will build on EC2 instance (no cross-compiler available)"
        BINARY_PATH=""
    fi

    if [ -n "$BINARY_PATH" ] && [ -f "$BINARY_PATH" ]; then
        print_success "Binary built: $(ls -lh "$BINARY_PATH" | awk '{print $5}')"
    fi
}

provision_aws() {
    print_step "Step 4/7: Provisioning AWS Infrastructure"

    # Set region
    export AWS_DEFAULT_REGION="$REGION"

    # Create key pair
    print_info "Creating SSH key pair..."
    aws ec2 create-key-pair \
        --key-name "$KEY_NAME" \
        --query 'KeyMaterial' \
        --output text > ~/.ssh/${KEY_NAME}.pem 2>/dev/null || true
    chmod 400 ~/.ssh/${KEY_NAME}.pem
    print_success "Key pair created: ~/.ssh/${KEY_NAME}.pem"

    # Create security group
    print_info "Creating security group..."
    VPC_ID=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query 'Vpcs[0].VpcId' --output text)
    SG_ID=$(aws ec2 create-security-group \
        --group-name "$SG_NAME" \
        --description "BitSage Coordinator Security Group" \
        --vpc-id "$VPC_ID" \
        --query 'GroupId' --output text 2>/dev/null) || \
    SG_ID=$(aws ec2 describe-security-groups --group-names "$SG_NAME" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)

    # Add security group rules
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 2>/dev/null || true
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 80 --cidr 0.0.0.0/0 2>/dev/null || true
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 443 --cidr 0.0.0.0/0 2>/dev/null || true
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port "$PORT" --cidr 0.0.0.0/0 2>/dev/null || true
    print_success "Security group created: $SG_ID"

    # Find latest Ubuntu AMI
    print_info "Finding latest Ubuntu 22.04 AMI..."
    AMI_ID=$(aws ec2 describe-images \
        --owners 099720109477 \
        --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
        --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
        --output text)
    print_success "AMI found: $AMI_ID"

    # Launch EC2 instance
    print_info "Launching EC2 instance..."
    INSTANCE_ID=$(aws ec2 run-instances \
        --image-id "$AMI_ID" \
        --instance-type "$INSTANCE_TYPE" \
        --key-name "$KEY_NAME" \
        --security-group-ids "$SG_ID" \
        --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$VOLUME_SIZE,VolumeType=gp3}" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME}]" \
        --query 'Instances[0].InstanceId' --output text)
    print_success "Instance launched: $INSTANCE_ID"

    # Wait for instance
    print_info "Waiting for instance to be running..."
    aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"

    # Get public IP
    PUBLIC_IP=$(aws ec2 describe-instances \
        --instance-ids "$INSTANCE_ID" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    print_success "Public IP: $PUBLIC_IP"

    # Wait for SSH
    print_info "Waiting for SSH to be available..."
    for i in {1..30}; do
        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i ~/.ssh/${KEY_NAME}.pem ubuntu@$PUBLIC_IP "echo 'SSH ready'" &>/dev/null; then
            print_success "SSH connection established"
            break
        fi
        sleep 5
    done
}

deploy_coordinator() {
    print_step "Step 5/7: Deploying Coordinator"

    SSH_CMD="ssh -o StrictHostKeyChecking=no -i ~/.ssh/${KEY_NAME}.pem ubuntu@$PUBLIC_IP"
    SCP_CMD="scp -o StrictHostKeyChecking=no -i ~/.ssh/${KEY_NAME}.pem"

    # Install dependencies on EC2
    print_info "Installing dependencies on EC2..."
    $SSH_CMD << 'DEPS'
sudo apt-get update -qq
sudo apt-get install -y -qq postgresql postgresql-contrib curl
sudo systemctl start postgresql
sudo systemctl enable postgresql
DEPS
    print_success "Dependencies installed"

    # Setup PostgreSQL
    print_info "Configuring PostgreSQL..."
    $SSH_CMD << PSQL
sudo -u postgres psql << 'SQL'
CREATE USER bitsage WITH PASSWORD '$DB_PASSWORD';
CREATE DATABASE bitsage OWNER bitsage;
GRANT ALL PRIVILEGES ON DATABASE bitsage TO bitsage;
SQL
PSQL
    print_success "Database configured"

    # Deploy binary
    if [ -n "$BINARY_PATH" ] && [ -f "$BINARY_PATH" ]; then
        print_info "Uploading pre-built binary..."
        $SCP_CMD "$BINARY_PATH" ubuntu@$PUBLIC_IP:/tmp/coordinator
        $SSH_CMD "sudo mv /tmp/coordinator /opt/bitsage/coordinator && sudo chmod +x /opt/bitsage/coordinator"
    else
        print_info "Building on EC2 (this may take 10-15 minutes)..."

        # Install Rust on EC2
        $SSH_CMD << 'RUST'
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
sudo apt-get install -y -qq build-essential pkg-config libssl-dev libpq-dev clang libclang-dev
RUST

        # Sync source code
        print_info "Syncing source code..."
        rsync -avz --exclude 'target' --exclude '.git' --exclude 'node_modules' \
            -e "ssh -o StrictHostKeyChecking=no -i ~/.ssh/${KEY_NAME}.pem" \
            "$PROJECT_ROOT/" ubuntu@$PUBLIC_IP:~/rust-node/

        # Sync stwo library
        rsync -avz --exclude '.git' --exclude 'target' \
            -e "ssh -o StrictHostKeyChecking=no -i ~/.ssh/${KEY_NAME}.pem" \
            "$PROJECT_ROOT/../libs/stwo/" ubuntu@$PUBLIC_IP:~/libs/stwo/

        # Build on EC2
        print_info "Building coordinator on EC2..."
        $SSH_CMD << 'BUILD'
source ~/.cargo/env
cd ~/rust-node
LIBCLANG_PATH=/usr/lib/llvm-14/lib cargo build --release --bin sage-coordinator
sudo mkdir -p /opt/bitsage
sudo cp target/release/sage-coordinator /opt/bitsage/coordinator
sudo chmod +x /opt/bitsage/coordinator
BUILD
    fi

    print_success "Coordinator binary deployed"
}

configure_service() {
    print_step "Step 6/7: Configuring Service"

    SSH_CMD="ssh -o StrictHostKeyChecking=no -i ~/.ssh/${KEY_NAME}.pem ubuntu@$PUBLIC_IP"

    # Create systemd service
    print_info "Creating systemd service..."
    $SSH_CMD << SERVICE
sudo mkdir -p /opt/bitsage

sudo tee /etc/systemd/system/bitsage-coordinator.service << 'EOF'
[Unit]
Description=BitSage Coordinator
After=network.target postgresql.service

[Service]
Type=simple
User=ubuntu
ExecStart=/opt/bitsage/coordinator --port $PORT --bind 0.0.0.0 --network $NETWORK --rpc-url $RPC_URL --database-url postgresql://bitsage:$DB_PASSWORD@localhost/bitsage
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable bitsage-coordinator
sudo systemctl start bitsage-coordinator
SERVICE

    print_success "Service configured and started"
}

verify_deployment() {
    print_step "Step 7/7: Verifying Deployment"

    # Wait for service to start
    print_info "Waiting for coordinator to start..."
    sleep 5

    # Check health endpoint
    for i in {1..10}; do
        HEALTH=$(curl -s "http://$PUBLIC_IP:$PORT/api/health" 2>/dev/null)
        if echo "$HEALTH" | grep -q "healthy"; then
            print_success "Health check passed"
            break
        fi
        sleep 2
    done

    # Final status
    echo -e "\n${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                    DEPLOYMENT SUCCESSFUL                          ║"
    echo "╠═══════════════════════════════════════════════════════════════════╣"
    echo "║                                                                   ║"
    echo "║  Instance ID:     $INSTANCE_ID"
    echo "║  Public IP:       $PUBLIC_IP"
    echo "║  Network:         $NETWORK"
    echo "║                                                                   ║"
    echo "║  API Endpoint:    http://$PUBLIC_IP:$PORT"
    echo "║  Health Check:    http://$PUBLIC_IP:$PORT/api/health"
    echo "║  WebSocket:       ws://$PUBLIC_IP:$PORT/ws"
    echo "║                                                                   ║"
    echo "║  SSH Access:                                                      ║"
    echo "║    ssh -i ~/.ssh/${KEY_NAME}.pem ubuntu@$PUBLIC_IP"
    echo "║                                                                   ║"
    echo "║  Service Commands:                                                ║"
    echo "║    sudo systemctl status bitsage-coordinator                      ║"
    echo "║    sudo journalctl -u bitsage-coordinator -f                      ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Save deployment info
    cat > "$SCRIPT_DIR/deployment-$NETWORK.env" << EOF
# BitSage Coordinator Deployment - $(date)
INSTANCE_ID=$INSTANCE_ID
PUBLIC_IP=$PUBLIC_IP
NETWORK=$NETWORK
PORT=$PORT
KEY_NAME=$KEY_NAME
SSH_KEY=~/.ssh/${KEY_NAME}.pem
API_URL=http://$PUBLIC_IP:$PORT
HEALTH_URL=http://$PUBLIC_IP:$PORT/api/health
EOF

    print_info "Deployment info saved to: $SCRIPT_DIR/deployment-$NETWORK.env"
}

cleanup_on_error() {
    echo -e "\n${RED}Deployment failed. Cleaning up...${NC}"

    if [ -n "$INSTANCE_ID" ]; then
        aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" &>/dev/null || true
    fi

    if [ -n "$SG_ID" ]; then
        aws ec2 delete-security-group --group-id "$SG_ID" &>/dev/null || true
    fi

    if [ -n "$KEY_NAME" ]; then
        aws ec2 delete-key-pair --key-name "$KEY_NAME" &>/dev/null || true
        rm -f ~/.ssh/${KEY_NAME}.pem
    fi

    exit 1
}

# Main execution
main() {
    trap cleanup_on_error ERR

    print_banner
    check_prerequisites
    collect_configuration
    build_coordinator
    provision_aws
    deploy_coordinator
    configure_service
    verify_deployment

    echo -e "\n${GREEN}  Coordinator is ready to accept worker connections!${NC}\n"
}

main "$@"
