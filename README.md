# Bridge Safe - Cross-Chain Bridge

Multi-signature cross-chain bridge with fraud proofs and validator consensus.

## Features
- **Multi-Sig Validation**: 3-of-5 validator consensus required
- **Fraud Proofs**: 24-hour challenge period for security
- **Multi-Chain**: Support for Ethereum, Polygon, BSC
- **Emergency Mode**: User fund recovery during emergencies
- **Dynamic Fees**: Chain-specific fee multipliers

## Usage

### Bridge STX Out
```clarity
(contract-call? .bridgesafe lock-for-bridge u10000000 "0x742d35Cc6634C0532925a3b844Bc9e7595f8fA49" "ethereum")
;; Returns: {transfer-id: u0, amount: u9970000, fee: u30000}
```

### Claim Bridged Assets
```clarity
(contract-call? .bridgesafe claim-from-bridge 
  "0xabc123..." 
  'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7 
  u10000000 
  "ethereum"
  (list 'SP_VAL1 'SP_VAL2 'SP_VAL3))
```

### Submit Fraud Proof
```clarity
(contract-call? .bridgesafe submit-fraud-proof u0 "Evidence of double spend...")
```

### Execute After Challenge Period
```clarity
(contract-call? .bridgesafe execute-transfer u0)
```

## Key Parameters
- Min Lock: 1 STX
- Bridge Fee: 0.3%
- Challenge Period: ~24 hours
- Validator Threshold: 3 signatures
- Supported Chains: Ethereum (1x fee), Polygon (0.5x), BSC (0.75x)

## Security
- Validator consensus prevents unauthorized mints
- Challenge period allows fraud detection
- Emergency withdrawals protect user funds
- Slashing mechanism for dishonest validators
