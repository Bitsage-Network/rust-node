// =============================================================================
// REAL-TIME AML MONITORING SYSTEM
// =============================================================================
//
// Provides privacy-preserving anti-money laundering monitoring for the Obelysk
// privacy layer. Integrates with ZK compliance proofs while detecting suspicious
// patterns in real-time.
//
// Key Features:
// - Transaction pattern detection (structuring, smurfing, layering)
// - Behavioral analytics and anomaly detection
// - Risk scoring engine with multi-factor analysis
// - Real-time streaming transaction analysis
// - Alert generation and management
// - Integration with ZK compliance proofs
//
// Architecture:
// ┌─────────────────────────────────────────────────────────────────┐
// │                    Real-Time AML Monitor                        │
// ├─────────────────────────────────────────────────────────────────┤
// │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
// │  │ Transaction │──│  Pattern    │──│   Risk      │              │
// │  │  Ingest     │  │  Detector   │  │  Scorer     │              │
// │  └─────────────┘  └─────────────┘  └──────┬──────┘              │
// │         │                                  │                     │
// │         ▼                                  ▼                     │
// │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
// │  │  Behavior   │  │   Alert     │  │  Compliance │              │
// │  │  Baseline   │  │  Manager    │  │  Reporter   │              │
// │  └─────────────┘  └─────────────┘  └─────────────┘              │
// └─────────────────────────────────────────────────────────────────┘

use crate::obelysk::elgamal::{Felt252, ECPoint, ElGamalCiphertext, hash_felts};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use parking_lot::RwLock;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// AML monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmlMonitorConfig {
    /// Threshold for CTR (Currency Transaction Report) - typically $10,000
    pub ctr_threshold: u64,
    /// Structuring detection threshold (% of CTR) - typically 80%
    pub structuring_threshold_percent: u8,
    /// Number of transactions to trigger structuring alert
    pub structuring_tx_count: u32,
    /// Time window for velocity analysis (seconds)
    pub velocity_window_secs: u64,
    /// Maximum velocity (total amount in window)
    pub velocity_max_amount: u64,
    /// Time window for rapid succession detection (seconds)
    pub rapid_succession_window_secs: u64,
    /// Rapid succession transaction count threshold
    pub rapid_succession_count: u32,
    /// Behavioral baseline window (days)
    pub baseline_window_days: u32,
    /// Anomaly detection sensitivity (0.0-1.0, higher = more sensitive)
    pub anomaly_sensitivity: f64,
    /// High risk score threshold for auto-flag
    pub high_risk_threshold: f64,
    /// Critical risk score threshold for auto-block
    pub critical_risk_threshold: f64,
    /// Enable privacy-preserving mode (use ZK proofs for verification)
    pub privacy_preserving_mode: bool,
    /// Maximum alerts per user before escalation
    pub max_alerts_before_escalation: u32,
}

impl Default for AmlMonitorConfig {
    fn default() -> Self {
        Self {
            ctr_threshold: 10_000_000_000_000_000_000, // 10,000 in 18 decimals (10^22 scaled down)
            structuring_threshold_percent: 80,
            structuring_tx_count: 3,
            velocity_window_secs: 86400, // 24 hours
            velocity_max_amount: 5_000_000_000_000_000_000, // 5,000 in 18 decimals (adjustable)
            rapid_succession_window_secs: 300, // 5 minutes
            rapid_succession_count: 5,
            baseline_window_days: 30,
            anomaly_sensitivity: 0.7,
            high_risk_threshold: 0.7,
            critical_risk_threshold: 0.9,
            privacy_preserving_mode: true,
            max_alerts_before_escalation: 3,
        }
    }
}

// =============================================================================
// DETECTION PATTERNS
// =============================================================================

/// Types of suspicious patterns that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SuspiciousPattern {
    /// Multiple transactions just under reporting threshold
    Structuring,
    /// Breaking large amounts into many small transactions
    Smurfing,
    /// Funds moving through multiple accounts rapidly
    Layering,
    /// Unusual velocity of transactions
    VelocityAnomaly,
    /// Many transactions in quick succession
    RapidSuccession,
    /// Transaction to/from high-risk jurisdiction
    HighRiskJurisdiction,
    /// Round-trip transaction (send and receive to/from same entity)
    RoundTrip,
    /// Transaction amount deviates significantly from baseline
    AmountAnomaly,
    /// Unusual transaction timing pattern
    TimingAnomaly,
    /// New counterparty with high-value transaction
    NewHighValueCounterparty,
    /// Dormant account suddenly active
    DormantAccountActivity,
    /// Pattern matching known illicit activity
    KnownPattern,
}

impl SuspiciousPattern {
    /// Get the base risk weight for this pattern (0.0-1.0)
    pub fn base_risk_weight(&self) -> f64 {
        match self {
            SuspiciousPattern::Structuring => 0.8,
            SuspiciousPattern::Smurfing => 0.85,
            SuspiciousPattern::Layering => 0.9,
            SuspiciousPattern::VelocityAnomaly => 0.5,
            SuspiciousPattern::RapidSuccession => 0.4,
            SuspiciousPattern::HighRiskJurisdiction => 0.7,
            SuspiciousPattern::RoundTrip => 0.75,
            SuspiciousPattern::AmountAnomaly => 0.3,
            SuspiciousPattern::TimingAnomaly => 0.2,
            SuspiciousPattern::NewHighValueCounterparty => 0.4,
            SuspiciousPattern::DormantAccountActivity => 0.5,
            SuspiciousPattern::KnownPattern => 0.95,
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            SuspiciousPattern::Structuring => "Multiple transactions just under reporting threshold",
            SuspiciousPattern::Smurfing => "Large amount broken into many small transactions",
            SuspiciousPattern::Layering => "Rapid movement through multiple accounts",
            SuspiciousPattern::VelocityAnomaly => "Unusual transaction velocity",
            SuspiciousPattern::RapidSuccession => "Many transactions in quick succession",
            SuspiciousPattern::HighRiskJurisdiction => "High-risk jurisdiction involved",
            SuspiciousPattern::RoundTrip => "Funds returning to origin",
            SuspiciousPattern::AmountAnomaly => "Amount deviates from normal behavior",
            SuspiciousPattern::TimingAnomaly => "Unusual transaction timing",
            SuspiciousPattern::NewHighValueCounterparty => "New counterparty with large transaction",
            SuspiciousPattern::DormantAccountActivity => "Dormant account suddenly active",
            SuspiciousPattern::KnownPattern => "Matches known illicit pattern",
        }
    }
}

/// Detection result for a specific pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDetection {
    /// The detected pattern
    pub pattern: SuspiciousPattern,
    /// Confidence score (0.0-1.0)
    pub confidence: f64,
    /// Contributing factors
    pub factors: Vec<DetectionFactor>,
    /// Timestamp of detection
    pub detected_at: u64,
    /// Transaction IDs involved
    pub transaction_ids: Vec<Felt252>,
}

/// A factor contributing to pattern detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFactor {
    /// Factor name
    pub name: String,
    /// Factor value
    pub value: String,
    /// Weight in detection
    pub weight: f64,
}

// =============================================================================
// TRANSACTION REPRESENTATION
// =============================================================================

/// A transaction for AML analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmlTransaction {
    /// Unique transaction ID
    pub tx_id: Felt252,
    /// Sender public key hash (privacy-preserving)
    pub sender_hash: Felt252,
    /// Recipient public key hash (privacy-preserving)
    pub recipient_hash: Felt252,
    /// Transaction amount (may be encrypted in privacy mode)
    pub amount: TransactionAmount,
    /// Timestamp (unix seconds)
    pub timestamp: u64,
    /// Transaction type
    pub tx_type: TransactionType,
    /// Optional jurisdiction code
    pub jurisdiction: Option<JurisdictionCode>,
    /// Whether this is first interaction with counterparty
    pub is_new_counterparty: bool,
}

/// Transaction amount - can be plaintext or encrypted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionAmount {
    /// Plaintext amount (for non-privacy transactions)
    Plaintext(u64),
    /// Encrypted amount with optional range proof
    Encrypted {
        ciphertext: ElGamalCiphertext,
        /// Whether range compliance proof verified
        range_verified: bool,
        /// Verified upper bound (if range proof provided)
        verified_upper_bound: Option<u64>,
    },
}

impl TransactionAmount {
    /// Get plaintext amount if available
    pub fn plaintext(&self) -> Option<u64> {
        match self {
            TransactionAmount::Plaintext(amt) => Some(*amt),
            TransactionAmount::Encrypted { .. } => None,
        }
    }

    /// Check if amount is below threshold (using verified upper bound for encrypted)
    pub fn is_below_threshold(&self, threshold: u64) -> Option<bool> {
        match self {
            TransactionAmount::Plaintext(amt) => Some(*amt < threshold),
            TransactionAmount::Encrypted { verified_upper_bound, .. } => {
                verified_upper_bound.map(|bound| bound < threshold)
            }
        }
    }

    /// Check if amount is just below threshold (structuring indicator)
    pub fn is_near_but_below(&self, threshold: u64, percent: u8) -> Option<bool> {
        let lower_bound = (threshold as f64 * (percent as f64 / 100.0)) as u64;
        match self {
            TransactionAmount::Plaintext(amt) => {
                Some(*amt >= lower_bound && *amt < threshold)
            }
            TransactionAmount::Encrypted { verified_upper_bound, .. } => {
                // For encrypted, we can only check if upper bound suggests structuring
                verified_upper_bound.map(|bound| bound >= lower_bound && bound < threshold)
            }
        }
    }
}

/// Transaction type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionType {
    /// Regular transfer
    Transfer,
    /// Deposit from external source
    Deposit,
    /// Withdrawal to external destination
    Withdrawal,
    /// Exchange/swap operation
    Exchange,
    /// Smart contract interaction
    ContractCall,
    /// Staking operation
    Staking,
    /// Reward/yield payment
    Reward,
}

/// Jurisdiction code for geographic risk
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JurisdictionCode(pub u16);

impl JurisdictionCode {
    /// FATF high-risk jurisdictions (as of implementation)
    pub const HIGH_RISK: &'static [u16] = &[
        408, // North Korea
        364, // Iran
        104, // Myanmar
    ];

    /// Check if this is a high-risk jurisdiction
    pub fn is_high_risk(&self) -> bool {
        Self::HIGH_RISK.contains(&self.0)
    }
}

// =============================================================================
// USER BEHAVIOR BASELINE
// =============================================================================

/// Behavioral baseline for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBehaviorBaseline {
    /// User identifier (hashed for privacy)
    pub user_hash: Felt252,
    /// Average transaction amount
    pub avg_amount: f64,
    /// Standard deviation of amounts
    pub amount_std_dev: f64,
    /// Average transactions per day
    pub avg_tx_per_day: f64,
    /// Common counterparties (hashes)
    pub common_counterparties: Vec<Felt252>,
    /// Typical active hours (0-23)
    pub active_hours: Vec<u8>,
    /// First transaction timestamp
    pub first_seen: u64,
    /// Last transaction timestamp
    pub last_seen: u64,
    /// Total transaction count
    pub total_tx_count: u64,
    /// Account status
    pub account_status: AccountStatus,
    /// Number of transactions in baseline
    pub baseline_tx_count: u32,
}

impl UserBehaviorBaseline {
    /// Create a new empty baseline
    pub fn new(user_hash: Felt252, timestamp: u64) -> Self {
        Self {
            user_hash,
            avg_amount: 0.0,
            amount_std_dev: 0.0,
            avg_tx_per_day: 0.0,
            common_counterparties: Vec::new(),
            active_hours: Vec::new(),
            first_seen: timestamp,
            last_seen: timestamp,
            total_tx_count: 0,
            account_status: AccountStatus::New,
            baseline_tx_count: 0,
        }
    }

    /// Check if account is dormant (no activity for 90 days)
    pub fn is_dormant(&self, current_time: u64) -> bool {
        current_time.saturating_sub(self.last_seen) > 90 * 24 * 3600
    }

    /// Update baseline with new transaction
    pub fn update(&mut self, amount: Option<u64>, timestamp: u64, counterparty: Felt252) {
        self.total_tx_count += 1;
        self.baseline_tx_count += 1;
        self.last_seen = timestamp;

        // Update average amount using Welford's online algorithm
        if let Some(amt) = amount {
            let delta = amt as f64 - self.avg_amount;
            self.avg_amount += delta / self.baseline_tx_count as f64;
            let delta2 = amt as f64 - self.avg_amount;
            // Update variance (std_dev squared)
            let m2 = self.amount_std_dev.powi(2) * (self.baseline_tx_count - 1) as f64;
            let new_m2 = m2 + delta * delta2;
            self.amount_std_dev = (new_m2 / self.baseline_tx_count as f64).sqrt();
        }

        // Update active hours
        let hour = ((timestamp % 86400) / 3600) as u8;
        if !self.active_hours.contains(&hour) {
            self.active_hours.push(hour);
        }

        // Update counterparties (keep top 20)
        if !self.common_counterparties.contains(&counterparty) {
            if self.common_counterparties.len() < 20 {
                self.common_counterparties.push(counterparty);
            }
        }

        // Update tx per day
        let days_active = ((timestamp - self.first_seen) / 86400).max(1) as f64;
        self.avg_tx_per_day = self.total_tx_count as f64 / days_active;

        // Update account status
        self.account_status = if self.total_tx_count > 100 {
            AccountStatus::Established
        } else if self.total_tx_count > 10 {
            AccountStatus::Active
        } else {
            AccountStatus::New
        };
    }

    /// Calculate z-score for amount (how many std devs from mean)
    pub fn amount_z_score(&self, amount: u64) -> f64 {
        if self.amount_std_dev < 0.001 {
            return 0.0;
        }
        (amount as f64 - self.avg_amount) / self.amount_std_dev
    }

    /// Check if timing is unusual
    pub fn is_unusual_timing(&self, timestamp: u64) -> bool {
        let hour = ((timestamp % 86400) / 3600) as u8;
        !self.active_hours.is_empty() && !self.active_hours.contains(&hour)
    }
}

/// Account status for risk assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountStatus {
    /// New account (< 10 transactions)
    New,
    /// Active account (10-100 transactions)
    Active,
    /// Established account (> 100 transactions)
    Established,
    /// Flagged for review
    Flagged,
    /// Blocked/frozen
    Blocked,
}

// =============================================================================
// RISK SCORING
// =============================================================================

/// Risk score for a transaction or user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Overall risk score (0.0-1.0)
    pub overall: f64,
    /// Component scores
    pub components: RiskComponents,
    /// Risk level classification
    pub level: RiskLevel,
    /// Factors contributing to the score
    pub factors: Vec<RiskFactor>,
    /// Timestamp of scoring
    pub scored_at: u64,
}

/// Risk score components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskComponents {
    /// Pattern-based risk (from detected patterns)
    pub pattern_risk: f64,
    /// Behavioral risk (deviation from baseline)
    pub behavioral_risk: f64,
    /// Counterparty risk
    pub counterparty_risk: f64,
    /// Geographic/jurisdiction risk
    pub geographic_risk: f64,
    /// Transaction characteristic risk
    pub transaction_risk: f64,
    /// Historical risk (from past alerts)
    pub historical_risk: f64,
}

impl RiskComponents {
    /// Calculate weighted overall score
    pub fn calculate_overall(&self) -> f64 {
        // Weighted average with pattern and behavioral given higher weight
        let weights = [0.25, 0.20, 0.15, 0.15, 0.15, 0.10];
        let scores = [
            self.pattern_risk,
            self.behavioral_risk,
            self.counterparty_risk,
            self.geographic_risk,
            self.transaction_risk,
            self.historical_risk,
        ];

        let weighted_sum: f64 = scores.iter()
            .zip(weights.iter())
            .map(|(s, w)| s * w)
            .sum();

        // Clamp to 0.0-1.0
        weighted_sum.clamp(0.0, 1.0)
    }
}

/// Risk level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Low risk (< 0.3)
    Low,
    /// Medium risk (0.3-0.5)
    Medium,
    /// High risk (0.5-0.7)
    High,
    /// Critical risk (0.7-0.9)
    Critical,
    /// Blocked (> 0.9)
    Blocked,
}

impl RiskLevel {
    /// Get risk level from score
    pub fn from_score(score: f64) -> Self {
        if score < 0.3 {
            RiskLevel::Low
        } else if score < 0.5 {
            RiskLevel::Medium
        } else if score < 0.7 {
            RiskLevel::High
        } else if score < 0.9 {
            RiskLevel::Critical
        } else {
            RiskLevel::Blocked
        }
    }
}

/// A factor contributing to risk score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Factor category
    pub category: String,
    /// Factor name
    pub name: String,
    /// Factor value
    pub value: String,
    /// Impact on score (positive = increases risk)
    pub impact: f64,
}

// =============================================================================
// ALERTS
// =============================================================================

/// An AML alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmlAlert {
    /// Unique alert ID
    pub alert_id: Felt252,
    /// User hash that triggered the alert
    pub user_hash: Felt252,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert type/category
    pub alert_type: AlertType,
    /// Detected patterns that triggered this alert
    pub patterns: Vec<SuspiciousPattern>,
    /// Risk score at time of alert
    pub risk_score: f64,
    /// Transaction IDs involved
    pub transaction_ids: Vec<Felt252>,
    /// Alert status
    pub status: AlertStatus,
    /// Created timestamp
    pub created_at: u64,
    /// Last updated timestamp
    pub updated_at: u64,
    /// Assigned reviewer (if any)
    pub assigned_to: Option<String>,
    /// Review notes
    pub notes: Vec<AlertNote>,
    /// Whether auto-generated or manual
    pub is_auto: bool,
}

impl AmlAlert {
    /// Create a new alert
    pub fn new(
        user_hash: Felt252,
        severity: AlertSeverity,
        alert_type: AlertType,
        patterns: Vec<SuspiciousPattern>,
        risk_score: f64,
        transaction_ids: Vec<Felt252>,
        timestamp: u64,
    ) -> Self {
        // Generate alert ID from components
        let id_components = vec![
            user_hash,
            Felt252::from_u64(timestamp),
            Felt252::from_u64(patterns.len() as u64),
        ];
        let alert_id = hash_felts(&id_components);

        Self {
            alert_id,
            user_hash,
            severity,
            alert_type,
            patterns,
            risk_score,
            transaction_ids,
            status: AlertStatus::New,
            created_at: timestamp,
            updated_at: timestamp,
            assigned_to: None,
            notes: Vec::new(),
            is_auto: true,
        }
    }
}

/// Alert severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Low - for review when time permits
    Low = 1,
    /// Medium - review within 24 hours
    Medium = 2,
    /// High - review within 4 hours
    High = 3,
    /// Critical - immediate review required
    Critical = 4,
    /// Emergency - auto-blocked, immediate escalation
    Emergency = 5,
}

impl AlertSeverity {
    /// Get severity from risk score
    pub fn from_risk_score(score: f64) -> Self {
        if score < 0.3 {
            AlertSeverity::Low
        } else if score < 0.5 {
            AlertSeverity::Medium
        } else if score < 0.7 {
            AlertSeverity::High
        } else if score < 0.9 {
            AlertSeverity::Critical
        } else {
            AlertSeverity::Emergency
        }
    }
}

/// Alert type categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertType {
    /// Potential structuring/smurfing
    StructuringAlert,
    /// Velocity threshold exceeded
    VelocityAlert,
    /// Behavioral anomaly detected
    BehaviorAlert,
    /// High-risk counterparty
    CounterpartyAlert,
    /// Geographic/jurisdiction risk
    JurisdictionAlert,
    /// Multiple pattern triggers
    MultiPatternAlert,
    /// Manual review requested
    ManualReview,
    /// Escalated from lower level
    Escalation,
}

/// Alert status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    /// New, unreviewed
    New,
    /// Assigned for review
    Assigned,
    /// Under investigation
    Investigating,
    /// Resolved - false positive
    ResolvedFalsePositive,
    /// Resolved - no action needed
    ResolvedNoAction,
    /// Resolved - action taken
    ResolvedActionTaken,
    /// Escalated to higher authority
    Escalated,
    /// Reported to regulatory authority
    Reported,
}

/// A note on an alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertNote {
    /// Timestamp
    pub timestamp: u64,
    /// Author
    pub author: String,
    /// Note content
    pub content: String,
}

// =============================================================================
// REAL-TIME AML MONITOR
// =============================================================================

/// Real-time AML monitoring engine
pub struct AmlMonitor {
    /// Configuration
    config: AmlMonitorConfig,
    /// User behavior baselines
    baselines: Arc<RwLock<HashMap<Felt252, UserBehaviorBaseline>>>,
    /// Recent transactions per user (sliding window)
    recent_transactions: Arc<RwLock<HashMap<Felt252, VecDeque<AmlTransaction>>>>,
    /// Active alerts
    alerts: Arc<RwLock<HashMap<Felt252, Vec<AmlAlert>>>>,
    /// High-risk counterparty list
    high_risk_counterparties: Arc<RwLock<Vec<Felt252>>>,
    /// Alert counter for statistics
    alert_count: Arc<RwLock<AlertStatistics>>,
}

/// Alert statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertStatistics {
    pub total_alerts: u64,
    pub alerts_by_severity: HashMap<String, u64>,
    pub alerts_by_type: HashMap<String, u64>,
    pub resolved_alerts: u64,
    pub escalated_alerts: u64,
    pub false_positives: u64,
}

impl AmlMonitor {
    /// Create a new AML monitor with default configuration
    pub fn new() -> Self {
        Self::with_config(AmlMonitorConfig::default())
    }

    /// Create a new AML monitor with custom configuration
    pub fn with_config(config: AmlMonitorConfig) -> Self {
        Self {
            config,
            baselines: Arc::new(RwLock::new(HashMap::new())),
            recent_transactions: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(HashMap::new())),
            high_risk_counterparties: Arc::new(RwLock::new(Vec::new())),
            alert_count: Arc::new(RwLock::new(AlertStatistics::default())),
        }
    }

    /// Process a transaction in real-time
    pub fn process_transaction(&self, tx: &AmlTransaction) -> TransactionAnalysisResult {
        let mut result = TransactionAnalysisResult {
            tx_id: tx.tx_id,
            patterns_detected: Vec::new(),
            risk_score: RiskScore {
                overall: 0.0,
                components: RiskComponents {
                    pattern_risk: 0.0,
                    behavioral_risk: 0.0,
                    counterparty_risk: 0.0,
                    geographic_risk: 0.0,
                    transaction_risk: 0.0,
                    historical_risk: 0.0,
                },
                level: RiskLevel::Low,
                factors: Vec::new(),
                scored_at: tx.timestamp,
            },
            alerts_generated: Vec::new(),
            action: RecommendedAction::Allow,
            analysis_time_ms: 0,
        };

        let start = std::time::Instant::now();

        // 1. Update baseline and detect behavioral anomalies
        let behavioral_risk = self.analyze_behavior(tx);
        result.risk_score.components.behavioral_risk = behavioral_risk;

        // 2. Detect patterns
        let patterns = self.detect_patterns(tx);
        result.patterns_detected = patterns.clone();

        // Calculate pattern risk from detected patterns
        if !patterns.is_empty() {
            let max_pattern_risk: f64 = patterns.iter()
                .map(|p| p.pattern.base_risk_weight() * p.confidence)
                .fold(0.0, f64::max);
            result.risk_score.components.pattern_risk = max_pattern_risk;
        }

        // 3. Assess counterparty risk
        result.risk_score.components.counterparty_risk = self.assess_counterparty_risk(tx);

        // 4. Assess geographic risk
        result.risk_score.components.geographic_risk = self.assess_geographic_risk(tx);

        // 5. Assess transaction characteristics
        result.risk_score.components.transaction_risk = self.assess_transaction_risk(tx);

        // 6. Get historical risk
        result.risk_score.components.historical_risk = self.get_historical_risk(&tx.sender_hash);

        // 7. Calculate overall risk
        result.risk_score.overall = result.risk_score.components.calculate_overall();
        result.risk_score.level = RiskLevel::from_score(result.risk_score.overall);

        // 8. Build risk factors
        result.risk_score.factors = self.build_risk_factors(tx, &result.risk_score.components, &patterns);

        // 9. Generate alerts if needed
        if result.risk_score.overall >= self.config.high_risk_threshold {
            let alert = self.generate_alert(tx, &patterns, result.risk_score.overall);
            result.alerts_generated.push(alert);
        }

        // 10. Determine recommended action
        result.action = if result.risk_score.overall >= self.config.critical_risk_threshold {
            RecommendedAction::Block
        } else if result.risk_score.overall >= self.config.high_risk_threshold {
            RecommendedAction::Flag
        } else if result.risk_score.overall >= 0.5 {
            RecommendedAction::Monitor
        } else {
            RecommendedAction::Allow
        };

        // 11. Store transaction for future analysis
        self.store_transaction(tx.clone());

        result.analysis_time_ms = start.elapsed().as_millis() as u64;
        result
    }

    /// Analyze behavioral patterns
    fn analyze_behavior(&self, tx: &AmlTransaction) -> f64 {
        let mut baselines = self.baselines.write();
        let baseline = baselines
            .entry(tx.sender_hash)
            .or_insert_with(|| UserBehaviorBaseline::new(tx.sender_hash, tx.timestamp));

        let mut risk: f64 = 0.0;

        // Check dormant account
        if baseline.is_dormant(tx.timestamp) {
            risk = 0.5; // Significant risk for dormant account activity
        }

        // Check amount anomaly
        if let Some(amount) = tx.amount.plaintext() {
            let z_score = baseline.amount_z_score(amount);
            if z_score.abs() > 3.0 {
                risk = risk.max(0.4_f64); // 3+ std devs is notable
            } else if z_score.abs() > 2.0 {
                risk = risk.max(0.2_f64); // 2+ std devs is somewhat notable
            }
        }

        // Check timing anomaly
        if baseline.baseline_tx_count > 10 && baseline.is_unusual_timing(tx.timestamp) {
            risk = risk.max(0.15_f64);
        }

        // Check new counterparty with high value
        if tx.is_new_counterparty {
            if let Some(amount) = tx.amount.plaintext() {
                if amount as f64 > baseline.avg_amount * 2.0 && baseline.avg_amount > 0.0 {
                    risk = risk.max(0.35_f64);
                }
            }
        }

        // Update baseline with this transaction
        baseline.update(
            tx.amount.plaintext(),
            tx.timestamp,
            tx.recipient_hash,
        );

        risk
    }

    /// Detect suspicious patterns
    fn detect_patterns(&self, tx: &AmlTransaction) -> Vec<PatternDetection> {
        let mut patterns = Vec::new();

        // Get recent transactions for this user
        let recent = self.recent_transactions.read();
        let user_txs = recent.get(&tx.sender_hash);

        // Pattern 1: Structuring detection
        if let Some(detection) = self.detect_structuring(tx, user_txs) {
            patterns.push(detection);
        }

        // Pattern 2: Rapid succession
        if let Some(detection) = self.detect_rapid_succession(tx, user_txs) {
            patterns.push(detection);
        }

        // Pattern 3: Velocity anomaly
        if let Some(detection) = self.detect_velocity_anomaly(tx, user_txs) {
            patterns.push(detection);
        }

        // Pattern 4: Round-trip detection (needs to check recipient's transactions)
        let recipient_txs = recent.get(&tx.recipient_hash);
        if let Some(detection) = self.detect_round_trip(tx, recipient_txs) {
            patterns.push(detection);
        }

        // Pattern 5: High-risk jurisdiction
        if let Some(detection) = self.detect_high_risk_jurisdiction(tx) {
            patterns.push(detection);
        }

        patterns
    }

    /// Detect structuring pattern
    fn detect_structuring(
        &self,
        tx: &AmlTransaction,
        recent_txs: Option<&VecDeque<AmlTransaction>>,
    ) -> Option<PatternDetection> {
        // Check if current transaction is near but below threshold
        let is_near_threshold = tx.amount.is_near_but_below(
            self.config.ctr_threshold,
            self.config.structuring_threshold_percent,
        )?;

        if !is_near_threshold {
            return None;
        }

        // Count recent transactions also near threshold
        let mut near_threshold_count = 1u32;
        let mut tx_ids = vec![tx.tx_id];

        if let Some(txs) = recent_txs {
            for past_tx in txs.iter() {
                // Only look at transactions within velocity window
                if tx.timestamp.saturating_sub(past_tx.timestamp) > self.config.velocity_window_secs {
                    break;
                }

                if past_tx.amount.is_near_but_below(
                    self.config.ctr_threshold,
                    self.config.structuring_threshold_percent,
                ).unwrap_or(false) {
                    near_threshold_count += 1;
                    tx_ids.push(past_tx.tx_id);
                }
            }
        }

        if near_threshold_count >= self.config.structuring_tx_count {
            let confidence = (near_threshold_count as f64 / self.config.structuring_tx_count as f64)
                .min(1.0);

            Some(PatternDetection {
                pattern: SuspiciousPattern::Structuring,
                confidence,
                factors: vec![
                    DetectionFactor {
                        name: "near_threshold_count".to_string(),
                        value: near_threshold_count.to_string(),
                        weight: 0.8,
                    },
                    DetectionFactor {
                        name: "threshold_percent".to_string(),
                        value: format!("{}%", self.config.structuring_threshold_percent),
                        weight: 0.2,
                    },
                ],
                detected_at: tx.timestamp,
                transaction_ids: tx_ids,
            })
        } else {
            None
        }
    }

    /// Detect rapid succession pattern
    fn detect_rapid_succession(
        &self,
        tx: &AmlTransaction,
        recent_txs: Option<&VecDeque<AmlTransaction>>,
    ) -> Option<PatternDetection> {
        let txs = recent_txs?;

        let mut count = 1u32;
        let mut tx_ids = vec![tx.tx_id];

        for past_tx in txs.iter() {
            if tx.timestamp.saturating_sub(past_tx.timestamp) <= self.config.rapid_succession_window_secs {
                count += 1;
                tx_ids.push(past_tx.tx_id);
            } else {
                break;
            }
        }

        if count >= self.config.rapid_succession_count {
            let confidence = (count as f64 / self.config.rapid_succession_count as f64)
                .min(1.0);

            Some(PatternDetection {
                pattern: SuspiciousPattern::RapidSuccession,
                confidence,
                factors: vec![
                    DetectionFactor {
                        name: "tx_count".to_string(),
                        value: count.to_string(),
                        weight: 0.7,
                    },
                    DetectionFactor {
                        name: "window_secs".to_string(),
                        value: self.config.rapid_succession_window_secs.to_string(),
                        weight: 0.3,
                    },
                ],
                detected_at: tx.timestamp,
                transaction_ids: tx_ids,
            })
        } else {
            None
        }
    }

    /// Detect velocity anomaly
    fn detect_velocity_anomaly(
        &self,
        tx: &AmlTransaction,
        recent_txs: Option<&VecDeque<AmlTransaction>>,
    ) -> Option<PatternDetection> {
        let current_amount = tx.amount.plaintext()?;
        let txs = recent_txs?;

        let mut total_amount = current_amount;
        let mut tx_ids = vec![tx.tx_id];

        for past_tx in txs.iter() {
            if tx.timestamp.saturating_sub(past_tx.timestamp) <= self.config.velocity_window_secs {
                if let Some(amt) = past_tx.amount.plaintext() {
                    total_amount = total_amount.saturating_add(amt);
                    tx_ids.push(past_tx.tx_id);
                }
            } else {
                break;
            }
        }

        if total_amount >= self.config.velocity_max_amount {
            let confidence = (total_amount as f64 / self.config.velocity_max_amount as f64)
                .min(1.0);

            Some(PatternDetection {
                pattern: SuspiciousPattern::VelocityAnomaly,
                confidence,
                factors: vec![
                    DetectionFactor {
                        name: "total_amount".to_string(),
                        value: total_amount.to_string(),
                        weight: 0.6,
                    },
                    DetectionFactor {
                        name: "threshold".to_string(),
                        value: self.config.velocity_max_amount.to_string(),
                        weight: 0.4,
                    },
                ],
                detected_at: tx.timestamp,
                transaction_ids: tx_ids,
            })
        } else {
            None
        }
    }

    /// Detect round-trip transactions
    fn detect_round_trip(
        &self,
        tx: &AmlTransaction,
        recipient_txs: Option<&VecDeque<AmlTransaction>>,
    ) -> Option<PatternDetection> {
        let txs = recipient_txs?;

        // Look for transactions where the current recipient previously sent to the current sender
        // i.e., past_tx: recipient -> sender, current tx: sender -> recipient (round trip)
        for past_tx in txs.iter() {
            // Check if this is a reverse transaction:
            // past_tx was from current recipient (sender) to current sender (recipient)
            if past_tx.sender_hash == tx.recipient_hash &&
               past_tx.recipient_hash == tx.sender_hash {
                // Found potential round-trip
                let time_diff = tx.timestamp.saturating_sub(past_tx.timestamp);

                // More suspicious if amounts are similar and time is short
                let mut confidence: f64 = 0.5;

                if time_diff < 3600 { // Within 1 hour
                    confidence += 0.3;
                } else if time_diff < 86400 { // Within 24 hours
                    confidence += 0.15;
                }

                // Check if amounts are similar
                if let (Some(current_amt), Some(past_amt)) =
                    (tx.amount.plaintext(), past_tx.amount.plaintext()) {
                    let diff_ratio = (current_amt as f64 - past_amt as f64).abs()
                        / (past_amt.max(1) as f64);
                    if diff_ratio < 0.1 { // Within 10%
                        confidence += 0.2;
                    }
                }

                return Some(PatternDetection {
                    pattern: SuspiciousPattern::RoundTrip,
                    confidence: confidence.min(1.0_f64),
                    factors: vec![
                        DetectionFactor {
                            name: "time_between_secs".to_string(),
                            value: time_diff.to_string(),
                            weight: 0.5,
                        },
                    ],
                    detected_at: tx.timestamp,
                    transaction_ids: vec![tx.tx_id, past_tx.tx_id],
                });
            }
        }

        None
    }

    /// Detect high-risk jurisdiction
    fn detect_high_risk_jurisdiction(&self, tx: &AmlTransaction) -> Option<PatternDetection> {
        let jurisdiction = tx.jurisdiction?;

        if jurisdiction.is_high_risk() {
            Some(PatternDetection {
                pattern: SuspiciousPattern::HighRiskJurisdiction,
                confidence: 0.9,
                factors: vec![
                    DetectionFactor {
                        name: "jurisdiction_code".to_string(),
                        value: jurisdiction.0.to_string(),
                        weight: 1.0,
                    },
                ],
                detected_at: tx.timestamp,
                transaction_ids: vec![tx.tx_id],
            })
        } else {
            None
        }
    }

    /// Assess counterparty risk
    fn assess_counterparty_risk(&self, tx: &AmlTransaction) -> f64 {
        let high_risk = self.high_risk_counterparties.read();

        let mut risk: f64 = 0.0;

        // Check if counterparty is on high-risk list
        if high_risk.contains(&tx.recipient_hash) {
            risk = 0.8;
        }

        // New counterparty adds some risk
        if tx.is_new_counterparty {
            risk = risk.max(0.2_f64);
        }

        risk
    }

    /// Assess geographic risk
    fn assess_geographic_risk(&self, tx: &AmlTransaction) -> f64 {
        if let Some(jurisdiction) = tx.jurisdiction {
            if jurisdiction.is_high_risk() {
                return 0.8;
            }
        }
        0.0
    }

    /// Assess transaction characteristics risk
    fn assess_transaction_risk(&self, tx: &AmlTransaction) -> f64 {
        let mut risk: f64 = 0.0;

        // Large round numbers are more suspicious
        if let Some(amount) = tx.amount.plaintext() {
            // Check if it's a round number
            if amount > 0 && amount % 1_000_000_000_000_000_000 == 0 {
                risk = risk.max(0.15_f64);
            }

            // Very large transactions
            if amount > self.config.ctr_threshold.saturating_mul(5) {
                risk = risk.max(0.3_f64);
            }
        }

        // Transaction type risk
        match tx.tx_type {
            TransactionType::Exchange => risk = risk.max(0.1_f64),
            TransactionType::Withdrawal => risk = risk.max(0.05_f64),
            _ => {}
        }

        risk
    }

    /// Get historical risk from past alerts
    fn get_historical_risk(&self, user_hash: &Felt252) -> f64 {
        let alerts = self.alerts.read();

        if let Some(user_alerts) = alerts.get(user_hash) {
            // Count active/unresolved alerts
            let active_alerts: usize = user_alerts.iter()
                .filter(|a| matches!(a.status,
                    AlertStatus::New |
                    AlertStatus::Assigned |
                    AlertStatus::Investigating
                ))
                .count();

            // Past alerts increase historical risk
            let risk = (active_alerts as f64 * 0.15).min(0.6);

            return risk;
        }

        0.0
    }

    /// Build risk factors list
    fn build_risk_factors(
        &self,
        _tx: &AmlTransaction,
        components: &RiskComponents,
        patterns: &[PatternDetection],
    ) -> Vec<RiskFactor> {
        let mut factors = Vec::new();

        if components.pattern_risk > 0.0 {
            for pattern in patterns {
                factors.push(RiskFactor {
                    category: "Pattern".to_string(),
                    name: format!("{:?}", pattern.pattern),
                    value: format!("{:.2} confidence", pattern.confidence),
                    impact: pattern.pattern.base_risk_weight() * pattern.confidence,
                });
            }
        }

        if components.behavioral_risk > 0.1 {
            factors.push(RiskFactor {
                category: "Behavioral".to_string(),
                name: "Behavioral Anomaly".to_string(),
                value: format!("{:.2}", components.behavioral_risk),
                impact: components.behavioral_risk,
            });
        }

        if components.counterparty_risk > 0.1 {
            factors.push(RiskFactor {
                category: "Counterparty".to_string(),
                name: "Counterparty Risk".to_string(),
                value: format!("{:.2}", components.counterparty_risk),
                impact: components.counterparty_risk,
            });
        }

        if components.geographic_risk > 0.1 {
            factors.push(RiskFactor {
                category: "Geographic".to_string(),
                name: "Jurisdiction Risk".to_string(),
                value: format!("{:.2}", components.geographic_risk),
                impact: components.geographic_risk,
            });
        }

        factors
    }

    /// Generate an alert
    fn generate_alert(
        &self,
        tx: &AmlTransaction,
        patterns: &[PatternDetection],
        risk_score: f64,
    ) -> AmlAlert {
        let severity = AlertSeverity::from_risk_score(risk_score);

        let alert_type = if patterns.len() > 1 {
            AlertType::MultiPatternAlert
        } else if patterns.iter().any(|p| matches!(p.pattern, SuspiciousPattern::Structuring | SuspiciousPattern::Smurfing)) {
            AlertType::StructuringAlert
        } else if patterns.iter().any(|p| matches!(p.pattern, SuspiciousPattern::VelocityAnomaly)) {
            AlertType::VelocityAlert
        } else if patterns.iter().any(|p| matches!(p.pattern, SuspiciousPattern::HighRiskJurisdiction)) {
            AlertType::JurisdictionAlert
        } else {
            AlertType::BehaviorAlert
        };

        let pattern_types: Vec<SuspiciousPattern> = patterns.iter()
            .map(|p| p.pattern)
            .collect();

        let tx_ids: Vec<Felt252> = patterns.iter()
            .flat_map(|p| p.transaction_ids.clone())
            .collect();

        let alert = AmlAlert::new(
            tx.sender_hash,
            severity,
            alert_type,
            pattern_types,
            risk_score,
            tx_ids,
            tx.timestamp,
        );

        // Store alert
        let mut alerts = self.alerts.write();
        alerts.entry(tx.sender_hash)
            .or_insert_with(Vec::new)
            .push(alert.clone());

        // Update statistics
        let mut stats = self.alert_count.write();
        stats.total_alerts += 1;
        *stats.alerts_by_severity
            .entry(format!("{:?}", severity))
            .or_insert(0) += 1;
        *stats.alerts_by_type
            .entry(format!("{:?}", alert_type))
            .or_insert(0) += 1;

        alert
    }

    /// Store transaction for future analysis
    fn store_transaction(&self, tx: AmlTransaction) {
        let mut recent = self.recent_transactions.write();
        let user_txs = recent.entry(tx.sender_hash).or_insert_with(VecDeque::new);

        // Add new transaction at front
        user_txs.push_front(tx.clone());

        // Remove old transactions beyond velocity window
        while let Some(old_tx) = user_txs.back() {
            if tx.timestamp.saturating_sub(old_tx.timestamp) > self.config.velocity_window_secs * 2 {
                user_txs.pop_back();
            } else {
                break;
            }
        }

        // Cap at 1000 transactions per user
        while user_txs.len() > 1000 {
            user_txs.pop_back();
        }
    }

    /// Add a counterparty to the high-risk list
    pub fn add_high_risk_counterparty(&self, counterparty_hash: Felt252) {
        let mut list = self.high_risk_counterparties.write();
        if !list.contains(&counterparty_hash) {
            list.push(counterparty_hash);
        }
    }

    /// Remove a counterparty from the high-risk list
    pub fn remove_high_risk_counterparty(&self, counterparty_hash: Felt252) {
        let mut list = self.high_risk_counterparties.write();
        list.retain(|h| *h != counterparty_hash);
    }

    /// Get alert by ID
    pub fn get_alert(&self, alert_id: &Felt252) -> Option<AmlAlert> {
        let alerts = self.alerts.read();
        for user_alerts in alerts.values() {
            if let Some(alert) = user_alerts.iter().find(|a| a.alert_id == *alert_id) {
                return Some(alert.clone());
            }
        }
        None
    }

    /// Get alerts for a user
    pub fn get_user_alerts(&self, user_hash: &Felt252) -> Vec<AmlAlert> {
        let alerts = self.alerts.read();
        alerts.get(user_hash).cloned().unwrap_or_default()
    }

    /// Update alert status
    pub fn update_alert_status(
        &self,
        alert_id: &Felt252,
        new_status: AlertStatus,
        note: Option<AlertNote>,
    ) -> bool {
        let mut alerts = self.alerts.write();
        for user_alerts in alerts.values_mut() {
            if let Some(alert) = user_alerts.iter_mut().find(|a| a.alert_id == *alert_id) {
                let _old_status = alert.status;
                alert.status = new_status;
                alert.updated_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if let Some(n) = note {
                    alert.notes.push(n);
                }

                // Update statistics
                let mut stats = self.alert_count.write();
                if matches!(new_status, AlertStatus::Escalated) {
                    stats.escalated_alerts += 1;
                }
                if matches!(new_status, AlertStatus::ResolvedFalsePositive) {
                    stats.false_positives += 1;
                }
                if matches!(new_status,
                    AlertStatus::ResolvedFalsePositive |
                    AlertStatus::ResolvedNoAction |
                    AlertStatus::ResolvedActionTaken
                ) {
                    stats.resolved_alerts += 1;
                }

                return true;
            }
        }
        false
    }

    /// Get alert statistics
    pub fn get_statistics(&self) -> AlertStatistics {
        self.alert_count.read().clone()
    }

    /// Get user behavior baseline
    pub fn get_user_baseline(&self, user_hash: &Felt252) -> Option<UserBehaviorBaseline> {
        let baselines = self.baselines.read();
        baselines.get(user_hash).cloned()
    }

    /// Get configuration
    pub fn config(&self) -> &AmlMonitorConfig {
        &self.config
    }

    /// Batch process transactions
    pub fn process_batch(&self, transactions: &[AmlTransaction]) -> Vec<TransactionAnalysisResult> {
        transactions.iter()
            .map(|tx| self.process_transaction(tx))
            .collect()
    }

    /// Get pending alerts (new/assigned/investigating)
    pub fn get_pending_alerts(&self) -> Vec<AmlAlert> {
        let alerts = self.alerts.read();
        alerts.values()
            .flat_map(|user_alerts| {
                user_alerts.iter().filter(|a| {
                    matches!(a.status,
                        AlertStatus::New |
                        AlertStatus::Assigned |
                        AlertStatus::Investigating
                    )
                }).cloned()
            })
            .collect()
    }

    /// Export alerts for regulatory reporting
    pub fn export_alerts_for_reporting(&self, since_timestamp: u64) -> Vec<AmlAlert> {
        let alerts = self.alerts.read();
        alerts.values()
            .flat_map(|user_alerts| {
                user_alerts.iter()
                    .filter(|a| a.created_at >= since_timestamp)
                    .filter(|a| matches!(a.severity, AlertSeverity::High | AlertSeverity::Critical | AlertSeverity::Emergency))
                    .cloned()
            })
            .collect()
    }
}

impl Default for AmlMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// ANALYSIS RESULTS
// =============================================================================

/// Result of analyzing a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAnalysisResult {
    /// Transaction ID
    pub tx_id: Felt252,
    /// Patterns detected
    pub patterns_detected: Vec<PatternDetection>,
    /// Risk score
    pub risk_score: RiskScore,
    /// Alerts generated (if any)
    pub alerts_generated: Vec<AmlAlert>,
    /// Recommended action
    pub action: RecommendedAction,
    /// Time taken for analysis (ms)
    pub analysis_time_ms: u64,
}

/// Recommended action based on analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendedAction {
    /// Allow the transaction
    Allow,
    /// Allow but add to monitoring
    Monitor,
    /// Flag for review
    Flag,
    /// Block/reject the transaction
    Block,
}

// =============================================================================
// COMPLIANCE INTEGRATION
// =============================================================================

/// Integration with ZK compliance proofs
pub struct ComplianceIntegration;

impl ComplianceIntegration {
    /// Verify that amount is below CTR threshold using ZK range proof
    /// (Delegates to existing range compliance proof system)
    pub fn verify_amount_below_threshold_zk(
        _ciphertext: &ElGamalCiphertext,
        range_proof_verified: bool,
        verified_upper_bound: Option<u64>,
        threshold: u64,
    ) -> bool {
        if range_proof_verified {
            if let Some(bound) = verified_upper_bound {
                return bound < threshold;
            }
        }
        false
    }

    /// Create privacy-preserving transaction for AML analysis
    pub fn create_privacy_preserving_tx(
        tx_id: Felt252,
        sender_pk: &ECPoint,
        recipient_pk: &ECPoint,
        ciphertext: ElGamalCiphertext,
        range_verified: bool,
        verified_bound: Option<u64>,
        timestamp: u64,
        tx_type: TransactionType,
    ) -> AmlTransaction {
        // Hash the public keys for privacy
        let sender_hash = hash_felts(&[sender_pk.x, sender_pk.y]);
        let recipient_hash = hash_felts(&[recipient_pk.x, recipient_pk.y]);

        AmlTransaction {
            tx_id,
            sender_hash,
            recipient_hash,
            amount: TransactionAmount::Encrypted {
                ciphertext,
                range_verified,
                verified_upper_bound: verified_bound,
            },
            timestamp,
            tx_type,
            jurisdiction: None,
            is_new_counterparty: false, // Would need to track
        }
    }
}

// =============================================================================
// STREAMING MONITOR
// =============================================================================

/// Streaming transaction monitor for real-time processing
pub struct StreamingMonitor {
    /// The AML monitor
    monitor: Arc<AmlMonitor>,
    /// Pending transactions buffer
    pending: Arc<RwLock<VecDeque<AmlTransaction>>>,
    /// Processing statistics
    stats: Arc<RwLock<StreamingStats>>,
}

/// Streaming statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamingStats {
    pub transactions_processed: u64,
    pub transactions_flagged: u64,
    pub transactions_blocked: u64,
    pub avg_processing_time_ms: f64,
    pub max_processing_time_ms: u64,
    pub alerts_generated: u64,
}

impl StreamingMonitor {
    /// Create a new streaming monitor
    pub fn new(config: AmlMonitorConfig) -> Self {
        Self {
            monitor: Arc::new(AmlMonitor::with_config(config)),
            pending: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(StreamingStats::default())),
        }
    }

    /// Submit a transaction for processing
    pub fn submit(&self, tx: AmlTransaction) -> TransactionAnalysisResult {
        let result = self.monitor.process_transaction(&tx);

        // Update stats
        let mut stats = self.stats.write();
        stats.transactions_processed += 1;

        if matches!(result.action, RecommendedAction::Flag | RecommendedAction::Block) {
            stats.transactions_flagged += 1;
        }
        if matches!(result.action, RecommendedAction::Block) {
            stats.transactions_blocked += 1;
        }

        // Update average processing time
        let n = stats.transactions_processed as f64;
        stats.avg_processing_time_ms =
            stats.avg_processing_time_ms * ((n - 1.0) / n)
            + result.analysis_time_ms as f64 / n;

        stats.max_processing_time_ms = stats.max_processing_time_ms.max(result.analysis_time_ms);
        stats.alerts_generated += result.alerts_generated.len() as u64;

        result
    }

    /// Get current statistics
    pub fn get_stats(&self) -> StreamingStats {
        self.stats.read().clone()
    }

    /// Get the underlying monitor
    pub fn monitor(&self) -> &Arc<AmlMonitor> {
        &self.monitor
    }

    /// Get the number of pending transactions
    pub fn pending_count(&self) -> usize {
        self.pending.read().len()
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tx(
        sender: u64,
        recipient: u64,
        amount: u64,
        timestamp: u64,
    ) -> AmlTransaction {
        AmlTransaction {
            tx_id: Felt252::from_u64(timestamp),
            sender_hash: Felt252::from_u64(sender),
            recipient_hash: Felt252::from_u64(recipient),
            amount: TransactionAmount::Plaintext(amount),
            timestamp,
            tx_type: TransactionType::Transfer,
            jurisdiction: None,
            is_new_counterparty: false,
        }
    }

    #[test]
    fn test_aml_monitor_creation() {
        let monitor = AmlMonitor::new();
        assert_eq!(monitor.config().structuring_tx_count, 3);
        assert_eq!(monitor.config().rapid_succession_count, 5);
    }

    #[test]
    fn test_transaction_processing_low_risk() {
        let monitor = AmlMonitor::new();

        let tx = create_test_tx(1, 2, 1000, 1000);
        let result = monitor.process_transaction(&tx);

        assert!(result.patterns_detected.is_empty());
        assert!(result.risk_score.overall < 0.5);
        assert_eq!(result.action, RecommendedAction::Allow);
    }

    #[test]
    fn test_structuring_detection() {
        let mut config = AmlMonitorConfig::default();
        config.ctr_threshold = 10000; // 10,000
        config.structuring_threshold_percent = 80;
        config.structuring_tx_count = 3;

        let monitor = AmlMonitor::with_config(config);

        // Send 3 transactions at 90% of threshold (structuring pattern)
        let tx1 = create_test_tx(1, 2, 9000, 1000);
        let tx2 = create_test_tx(1, 3, 9500, 2000);
        let tx3 = create_test_tx(1, 4, 8500, 3000);

        monitor.process_transaction(&tx1);
        monitor.process_transaction(&tx2);
        let result = monitor.process_transaction(&tx3);

        // Should detect structuring pattern
        assert!(result.patterns_detected.iter()
            .any(|p| matches!(p.pattern, SuspiciousPattern::Structuring)));
    }

    #[test]
    fn test_rapid_succession_detection() {
        let mut config = AmlMonitorConfig::default();
        config.rapid_succession_window_secs = 300; // 5 minutes
        config.rapid_succession_count = 3;

        let monitor = AmlMonitor::with_config(config);

        // Send 5 transactions within 5 minutes
        for i in 0..5 {
            let tx = create_test_tx(1, 2, 100, 1000 + i * 30);
            let result = monitor.process_transaction(&tx);

            if i >= 2 {
                // After 3rd transaction, should detect rapid succession
                assert!(result.patterns_detected.iter()
                    .any(|p| matches!(p.pattern, SuspiciousPattern::RapidSuccession)));
            }
        }
    }

    #[test]
    fn test_velocity_detection() {
        let mut config = AmlMonitorConfig::default();
        config.velocity_window_secs = 86400; // 24 hours
        config.velocity_max_amount = 1000;

        let monitor = AmlMonitor::with_config(config);

        // Send transactions totaling over velocity threshold
        let tx1 = create_test_tx(1, 2, 400, 1000);
        let tx2 = create_test_tx(1, 3, 400, 2000);
        let tx3 = create_test_tx(1, 4, 400, 3000);

        monitor.process_transaction(&tx1);
        monitor.process_transaction(&tx2);
        let result = monitor.process_transaction(&tx3);

        // Total = 1200, threshold = 1000, should trigger velocity alert
        assert!(result.patterns_detected.iter()
            .any(|p| matches!(p.pattern, SuspiciousPattern::VelocityAnomaly)));
    }

    #[test]
    fn test_round_trip_detection() {
        let monitor = AmlMonitor::new();

        // A sends to B
        let tx1 = create_test_tx(1, 2, 1000, 1000);
        // B sends back to A
        let mut tx2 = create_test_tx(2, 1, 1000, 2000);
        tx2.sender_hash = Felt252::from_u64(2);
        tx2.recipient_hash = Felt252::from_u64(1);

        monitor.process_transaction(&tx1);
        let result = monitor.process_transaction(&tx2);

        assert!(result.patterns_detected.iter()
            .any(|p| matches!(p.pattern, SuspiciousPattern::RoundTrip)));
    }

    #[test]
    fn test_high_risk_jurisdiction() {
        let monitor = AmlMonitor::new();

        let mut tx = create_test_tx(1, 2, 1000, 1000);
        tx.jurisdiction = Some(JurisdictionCode(408)); // North Korea

        let result = monitor.process_transaction(&tx);

        assert!(result.patterns_detected.iter()
            .any(|p| matches!(p.pattern, SuspiciousPattern::HighRiskJurisdiction)));
    }

    #[test]
    fn test_behavioral_baseline_update() {
        let monitor = AmlMonitor::new();

        // Process several transactions to build baseline
        for i in 0..10 {
            let tx = create_test_tx(1, 2, 1000, 1000 + i * 3600);
            monitor.process_transaction(&tx);
        }

        let baseline = monitor.get_user_baseline(&Felt252::from_u64(1)).unwrap();
        assert_eq!(baseline.total_tx_count, 10);
        assert!(baseline.avg_amount > 0.0);
    }

    #[test]
    fn test_amount_anomaly() {
        let monitor = AmlMonitor::new();

        // Build baseline with varying small amounts (to get non-zero std dev)
        for i in 0..20 {
            // Amounts vary from 80 to 120
            let amount = 80 + (i % 5) * 10;
            let tx = create_test_tx(1, 2, amount, 1000 + i * 3600);
            monitor.process_transaction(&tx);
        }

        // Check baseline has reasonable std dev
        let baseline = monitor.get_user_baseline(&Felt252::from_u64(1)).unwrap();
        assert!(baseline.amount_std_dev > 1.0, "std_dev should be > 1: {}", baseline.amount_std_dev);

        // Now send a much larger amount (10x+ the average)
        let big_tx = create_test_tx(1, 2, 5000, 100000);
        let result = monitor.process_transaction(&big_tx);

        // Should have elevated behavioral risk due to high z-score
        assert!(result.risk_score.components.behavioral_risk > 0.1,
            "behavioral_risk {} should be > 0.1", result.risk_score.components.behavioral_risk);
    }

    #[test]
    fn test_alert_generation() {
        let mut config = AmlMonitorConfig::default();
        // Lower thresholds for testing
        // Velocity pattern detection with weight ~0.5, but overall risk is weighted average
        // Pattern risk is 25% of overall, so we need threshold low enough
        config.high_risk_threshold = 0.1; // Very low threshold for testing
        config.velocity_max_amount = 500;
        config.velocity_window_secs = 86400;

        let monitor = AmlMonitor::with_config(config);

        // Add the counterparty to high-risk list to boost risk score
        monitor.add_high_risk_counterparty(Felt252::from_u64(2));

        // Trigger velocity anomaly (300 + 300 = 600 > 500)
        let tx1 = create_test_tx(1, 2, 300, 1000);
        let tx2 = create_test_tx(1, 2, 300, 2000);

        monitor.process_transaction(&tx1);
        let result = monitor.process_transaction(&tx2);

        // Should have patterns detected
        assert!(!result.patterns_detected.is_empty(),
            "Should detect velocity pattern, got: {:?}", result.patterns_detected);

        // Should have elevated risk score
        assert!(result.risk_score.overall >= 0.1,
            "Risk score {} should be >= 0.1", result.risk_score.overall);

        // Should generate an alert
        assert!(!result.alerts_generated.is_empty(),
            "Should generate alert for high risk transaction");

        // Check alert was stored
        let alerts = monitor.get_user_alerts(&Felt252::from_u64(1));
        assert!(!alerts.is_empty());
    }

    #[test]
    fn test_alert_status_update() {
        let mut config = AmlMonitorConfig::default();
        config.high_risk_threshold = 0.1; // Low threshold to trigger alerts
        config.velocity_max_amount = 500;

        let monitor = AmlMonitor::with_config(config);

        // Add high-risk counterparty to boost risk score
        monitor.add_high_risk_counterparty(Felt252::from_u64(2));

        // Generate alert
        let tx1 = create_test_tx(1, 2, 300, 1000);
        let tx2 = create_test_tx(1, 2, 300, 2000);
        monitor.process_transaction(&tx1);
        let result = monitor.process_transaction(&tx2);

        if let Some(alert) = result.alerts_generated.first() {
            // Update status
            let note = AlertNote {
                timestamp: 3000,
                author: "analyst".to_string(),
                content: "Reviewed, false positive".to_string(),
            };

            assert!(monitor.update_alert_status(
                &alert.alert_id,
                AlertStatus::ResolvedFalsePositive,
                Some(note),
            ));

            // Check stats updated
            let stats = monitor.get_statistics();
            assert_eq!(stats.false_positives, 1);
            assert_eq!(stats.resolved_alerts, 1);
        }
    }

    #[test]
    fn test_high_risk_counterparty() {
        let monitor = AmlMonitor::new();

        // Add counterparty to high-risk list
        monitor.add_high_risk_counterparty(Felt252::from_u64(999));

        // Transaction to high-risk counterparty
        let tx = create_test_tx(1, 999, 1000, 1000);
        let result = monitor.process_transaction(&tx);

        // Should have elevated counterparty risk
        assert!(result.risk_score.components.counterparty_risk > 0.5);
    }

    #[test]
    fn test_streaming_monitor() {
        let monitor = StreamingMonitor::new(AmlMonitorConfig::default());

        for i in 0..10 {
            let tx = create_test_tx(1, 2, 100, 1000 + i);
            monitor.submit(tx);
        }

        let stats = monitor.get_stats();
        assert_eq!(stats.transactions_processed, 10);
        assert!(stats.avg_processing_time_ms >= 0.0);
    }

    #[test]
    fn test_risk_level_classification() {
        assert_eq!(RiskLevel::from_score(0.1), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(0.4), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(0.6), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(0.8), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(0.95), RiskLevel::Blocked);
    }

    #[test]
    fn test_suspicious_pattern_weights() {
        assert!(SuspiciousPattern::Structuring.base_risk_weight() > 0.5);
        assert!(SuspiciousPattern::KnownPattern.base_risk_weight() > 0.9);
        assert!(SuspiciousPattern::TimingAnomaly.base_risk_weight() < 0.3);
    }

    #[test]
    fn test_transaction_amount_near_threshold() {
        let amount = TransactionAmount::Plaintext(8500);

        // 8500 is 85% of 10000, so should be "near but below" at 80%
        assert!(amount.is_near_but_below(10000, 80).unwrap());

        // But not at 90%
        assert!(!amount.is_near_but_below(10000, 90).unwrap());
    }

    #[test]
    fn test_jurisdiction_risk() {
        assert!(JurisdictionCode(408).is_high_risk()); // North Korea
        assert!(JurisdictionCode(364).is_high_risk()); // Iran
        assert!(!JurisdictionCode(840).is_high_risk()); // US
    }

    #[test]
    fn test_dormant_account_detection() {
        let baseline = UserBehaviorBaseline::new(Felt252::from_u64(1), 1000);

        // 90 days = 7776000 seconds
        assert!(!baseline.is_dormant(1000 + 86400 * 30)); // 30 days - not dormant
        assert!(baseline.is_dormant(1000 + 86400 * 100)); // 100 days - dormant
    }

    #[test]
    fn test_privacy_preserving_transaction() {
        let sender_pk = ECPoint::new(Felt252::from_u64(1), Felt252::from_u64(2));
        let recipient_pk = ECPoint::new(Felt252::from_u64(3), Felt252::from_u64(4));
        let ciphertext = ElGamalCiphertext::zero();

        let tx = ComplianceIntegration::create_privacy_preserving_tx(
            Felt252::from_u64(100),
            &sender_pk,
            &recipient_pk,
            ciphertext,
            true,
            Some(5000),
            1000,
            TransactionType::Transfer,
        );

        // Sender hash should be computed from public key, not the raw value
        assert!(tx.sender_hash != Felt252::from_u64(1));

        // Should have encrypted amount
        match tx.amount {
            TransactionAmount::Encrypted { range_verified, verified_upper_bound, .. } => {
                assert!(range_verified);
                assert_eq!(verified_upper_bound, Some(5000));
            }
            _ => panic!("Expected encrypted amount"),
        }
    }

    #[test]
    fn test_batch_processing() {
        let monitor = AmlMonitor::new();

        let txs: Vec<AmlTransaction> = (0..5)
            .map(|i| create_test_tx(1, 2, 100, 1000 + i))
            .collect();

        let results = monitor.process_batch(&txs);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_export_alerts_for_reporting() {
        let mut config = AmlMonitorConfig::default();
        config.high_risk_threshold = 0.2;
        config.velocity_max_amount = 200;

        let monitor = AmlMonitor::with_config(config);

        // Generate some alerts
        let tx1 = create_test_tx(1, 2, 150, 1000);
        let tx2 = create_test_tx(1, 3, 150, 2000);
        monitor.process_transaction(&tx1);
        monitor.process_transaction(&tx2);

        // Export alerts since timestamp 0
        let exported = monitor.export_alerts_for_reporting(0);

        // Should only include high severity alerts
        for alert in &exported {
            assert!(matches!(alert.severity,
                AlertSeverity::High | AlertSeverity::Critical | AlertSeverity::Emergency
            ));
        }
    }
}
