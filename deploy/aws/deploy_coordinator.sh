#!/bin/bash
#
# BitSage Network - AWS EC2 Coordinator Deployment
#
# This script deploys the coordinator to AWS EC2 with RDS PostgreSQL
#
# Prerequisites:
#   - AWS CLI configured with credentials
#   - Domain configured in Route53 (optional but recommended)
#
# Usage:
#   ./deploy_coordinator.sh [sepolia|mainnet]
#

set -e

NETWORK="${1:-sepolia}"
REGION="${AWS_REGION:-us-east-1}"
INSTANCE_TYPE="${INSTANCE_TYPE:-t3.medium}"
KEY_NAME="${KEY_NAME:-bitsage-coordinator}"

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║       BITSAGE COORDINATOR - AWS EC2 DEPLOYMENT                    ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo
echo "Network:       $NETWORK"
echo "Region:        $REGION"
echo "Instance Type: $INSTANCE_TYPE"
echo

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo "ERROR: AWS CLI not found. Install with: brew install awscli"
    exit 1
fi

# Check credentials
if ! aws sts get-caller-identity &> /dev/null; then
    echo "ERROR: AWS credentials not configured. Run: aws configure"
    exit 1
fi

echo "[1/7] Creating security group..."
SG_ID=$(aws ec2 create-security-group \
    --group-name bitsage-coordinator-sg \
    --description "BitSage Coordinator Security Group" \
    --query 'GroupId' --output text 2>/dev/null || \
    aws ec2 describe-security-groups \
        --group-names bitsage-coordinator-sg \
        --query 'SecurityGroups[0].GroupId' --output text)

# Allow SSH, HTTPS, and coordinator port
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0 2>/dev/null || true
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 443 --cidr 0.0.0.0/0 2>/dev/null || true
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 8080 --cidr 0.0.0.0/0 2>/dev/null || true

echo "  Security Group: $SG_ID"

echo
echo "[2/7] Creating key pair (if not exists)..."
if ! aws ec2 describe-key-pairs --key-names $KEY_NAME &>/dev/null; then
    aws ec2 create-key-pair --key-name $KEY_NAME --query 'KeyMaterial' --output text > ~/.ssh/${KEY_NAME}.pem
    chmod 400 ~/.ssh/${KEY_NAME}.pem
    echo "  Key saved to: ~/.ssh/${KEY_NAME}.pem"
else
    echo "  Key pair already exists"
fi

echo
echo "[3/7] Finding latest Ubuntu AMI..."
AMI_ID=$(aws ec2 describe-images \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text)
echo "  AMI: $AMI_ID"

echo
echo "[4/7] Creating user data script..."
cat > /tmp/coordinator-userdata.sh << 'USERDATA'
#!/bin/bash
set -e

# Install dependencies
apt-get update
apt-get install -y docker.io docker-compose nginx certbot python3-certbot-nginx postgresql-client

# Start Docker
systemctl enable docker
systemctl start docker

# Create bitsage user
useradd -m -s /bin/bash bitsage || true
usermod -aG docker bitsage

# Clone repository
cd /home/bitsage
git clone https://github.com/Ciro-AI-Labs/bitsage-network || (cd bitsage-network && git pull)
cd bitsage-network/rust-node

# Build coordinator
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
cargo build --release --bin sage-coordinator

# Create config directory
mkdir -p /etc/bitsage
cat > /etc/bitsage/coordinator.toml << 'CONFIG'
[server]
host = "0.0.0.0"
port = 8080

[database]
url = "postgresql://bitsage:CHANGE_ME@localhost/bitsage"

[blockchain]
network = "sepolia"
rpc_url = "https://starknet-sepolia-rpc.publicnode.com"

[jobs]
max_concurrent = 1000
timeout_secs = 3600
CONFIG

# Create systemd service
cat > /etc/systemd/system/bitsage-coordinator.service << 'SERVICE'
[Unit]
Description=BitSage Coordinator
After=network.target postgresql.service

[Service]
Type=simple
User=bitsage
ExecStart=/home/bitsage/bitsage-network/rust-node/target/release/sage-coordinator --config /etc/bitsage/coordinator.toml
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable bitsage-coordinator

echo "Coordinator installed. Configure database and start with: systemctl start bitsage-coordinator"
USERDATA

echo
echo "[5/7] Launching EC2 instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id $AMI_ID \
    --instance-type $INSTANCE_TYPE \
    --key-name $KEY_NAME \
    --security-group-ids $SG_ID \
    --user-data file:///tmp/coordinator-userdata.sh \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=bitsage-coordinator-$NETWORK}]" \
    --query 'Instances[0].InstanceId' --output text)

echo "  Instance ID: $INSTANCE_ID"

echo
echo "[6/7] Waiting for instance to be running..."
aws ec2 wait instance-running --instance-ids $INSTANCE_ID

PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids $INSTANCE_ID \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

echo "  Public IP: $PUBLIC_IP"

echo
echo "[7/7] Creating RDS PostgreSQL (optional)..."
echo "  Skipping RDS - configure manually or use local PostgreSQL"

echo
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                    DEPLOYMENT COMPLETE                            ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║                                                                   ║"
echo "║  Instance ID:   $INSTANCE_ID"
echo "║  Public IP:     $PUBLIC_IP"
echo "║                                                                   ║"
echo "║  NEXT STEPS:                                                      ║"
echo "║  1. SSH: ssh -i ~/.ssh/${KEY_NAME}.pem ubuntu@$PUBLIC_IP"
echo "║  2. Wait for setup: tail -f /var/log/cloud-init-output.log"
echo "║  3. Configure database password in /etc/bitsage/coordinator.toml"
echo "║  4. Start: sudo systemctl start bitsage-coordinator"
echo "║  5. Setup SSL: sudo certbot --nginx -d coordinator.bitsage.network"
echo "║                                                                   ║"
echo "║  Coordinator URL: http://$PUBLIC_IP:8080"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo
echo "To configure DNS, add an A record:"
echo "  coordinator-$NETWORK.bitsage.network -> $PUBLIC_IP"
