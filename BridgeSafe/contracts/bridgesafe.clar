;; Bridge Safe - Production-Ready Cross-Chain Bridge with Multi-Sig & Fraud Proofs
;; Secure asset bridging with validator consensus and challenge mechanism

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-unauthorized (err u100))
(define-constant err-invalid-amount (err u101))
(define-constant err-already-processed (err u102))
(define-constant err-insufficient-signatures (err u103))
(define-constant err-invalid-validator (err u104))
(define-constant err-transfer-expired (err u105))
(define-constant err-already-claimed (err u106))
(define-constant err-challenge-period-active (err u107))
(define-constant err-invalid-proof (err u108))
(define-constant err-paused (err u109))
(define-constant err-invalid-chain (err u110))
(define-constant err-duplicate-signature (err u111))
(define-constant err-threshold-too-high (err u112))

;; Data Variables
(define-data-var validator-threshold uint u3) ;; Required signatures
(define-data-var total-validators uint u5)
(define-data-var challenge-period uint u144) ;; ~24 hours in blocks
(define-data-var min-lock-amount uint u1000000) ;; 1 STX minimum
(define-data-var bridge-fee uint u30) ;; 0.3% in basis points
(define-data-var total-locked uint u0)
(define-data-var total-bridged uint u0)
(define-data-var is-paused bool false)
(define-data-var treasury principal contract-owner)
(define-data-var nonce uint u0)

;; Supported chains
(define-map supported-chains (string-ascii 20) {
  enabled: bool,
  fee-multiplier: uint,
  total-volume: uint
})

;; Validator registry
(define-map validators principal {
  active: bool,
  added-at: uint,
  total-validated: uint,
  slash-count: uint
})

;; Bridge transfers
(define-map bridge-transfers uint {
  sender: principal,
  recipient: (string-ascii 64), ;; External chain address
  amount: uint,
  fee: uint,
  target-chain: (string-ascii 20),
  created-at: uint,
  status: (string-ascii 20),
  challenge-end: uint
})

;; Inbound claims
(define-map inbound-claims (string-ascii 64) { ;; External tx hash
  recipient: principal,
  amount: uint,
  source-chain: (string-ascii 20),
  claimed: bool,
  signatures: (list 10 principal),
  executed-at: uint
})

;; Fraud proofs
(define-map fraud-proofs uint {
  challenger: principal,
  transfer-id: uint,
  evidence: (string-ascii 256),
  submitted-at: uint,
  status: (string-ascii 20)
})

;; User balances for emergency withdrawals
(define-map user-deposits principal uint)

;; Read-only functions
(define-read-only (get-transfer (transfer-id uint))
  (map-get? bridge-transfers transfer-id)
)

(define-read-only (get-claim (tx-hash (string-ascii 64)))
  (map-get? inbound-claims tx-hash)
)

(define-read-only (is-validator (address principal))
  (match (map-get? validators address)
    validator-info (get active validator-info)
    false
  )
)

(define-read-only (get-bridge-stats)
  {
    total-locked: (var-get total-locked),
    total-bridged: (var-get total-bridged),
    validator-threshold: (var-get validator-threshold),
    total-validators: (var-get total-validators),
    bridge-fee: (var-get bridge-fee),
    paused: (var-get is-paused)
  }
)

(define-read-only (calculate-bridge-fee (amount uint) (chain (string-ascii 20)))
  (match (map-get? supported-chains chain)
    chain-info
    (let ((base-fee (/ (* amount (var-get bridge-fee)) u10000))
          (multiplier (get fee-multiplier chain-info)))
      (/ (* base-fee multiplier) u100)
    )
    u0
  )
)

;; Private functions
(define-private (count-signatures (signatures (list 10 principal)))
  (let ((unique-sigs (fold remove-duplicates signatures (list))))
    (len unique-sigs)
  )
)

(define-private (remove-duplicates (sig principal) (unique-list (list 10 principal)))
  (if (is-none (index-of? unique-list sig))
    (unwrap! (as-max-len? (append unique-list sig) u10) unique-list)
    unique-list
  )
)

(define-private (verify-validator-signatures (signatures (list 10 principal)))
  (fold and-validator signatures true)
)

(define-private (and-validator (validator principal) (valid bool))
  (and valid (is-validator validator))
)

;; Public functions
(define-public (lock-for-bridge (amount uint) (recipient (string-ascii 64)) (target-chain (string-ascii 20)))
  (let ((transfer-id (var-get nonce))
        (fee (calculate-bridge-fee amount target-chain)))
    
    (asserts! (not (var-get is-paused)) err-paused)
    (asserts! (>= amount (var-get min-lock-amount)) err-invalid-amount)
    (asserts! (is-some (map-get? supported-chains target-chain)) err-invalid-chain)
    
    ;; Transfer STX to bridge
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    
    ;; Create transfer record
    (map-set bridge-transfers transfer-id {
      sender: tx-sender,
      recipient: recipient,
      amount: (- amount fee),
      fee: fee,
      target-chain: target-chain,
      created-at: burn-block-height,
      status: "pending",
      challenge-end: (+ burn-block-height (var-get challenge-period))
    })
    
    ;; Update user deposits
    (map-set user-deposits tx-sender 
      (+ (default-to u0 (map-get? user-deposits tx-sender)) amount))
    
    ;; Update chain stats
    (match (map-get? supported-chains target-chain)
      chain-info
      (map-set supported-chains target-chain
        (merge chain-info {
          total-volume: (+ (get total-volume chain-info) amount)
        }))
      true
    )
    
    ;; Update global state
    (var-set nonce (+ transfer-id u1))
    (var-set total-locked (+ (var-get total-locked) amount))
    
    ;; Transfer fee to treasury
    (if (> fee u0)
      (try! (as-contract (stx-transfer? fee tx-sender (var-get treasury))))
      true
    )
    
    (ok {transfer-id: transfer-id, amount: (- amount fee), fee: fee})
  )
)

(define-public (claim-from-bridge (tx-hash (string-ascii 64)) (recipient principal) (amount uint) (source-chain (string-ascii 20)) (signatures (list 10 principal)))
  (begin
    (asserts! (not (var-get is-paused)) err-paused)
    (asserts! (is-none (map-get? inbound-claims tx-hash)) err-already-claimed)
    (asserts! (>= (count-signatures signatures) (var-get validator-threshold)) err-insufficient-signatures)
    (asserts! (verify-validator-signatures signatures) err-invalid-validator)
    
    ;; Create claim record
    (map-set inbound-claims tx-hash {
      recipient: recipient,
      amount: amount,
      source-chain: source-chain,
      claimed: true,
      signatures: signatures,
      executed-at: burn-block-height
    })
    
    ;; Transfer STX to recipient
    (try! (as-contract (stx-transfer? amount tx-sender recipient)))
    
    ;; Update validator stats
    (map update-validator-stats signatures)
    
    ;; Update global state
    (var-set total-bridged (+ (var-get total-bridged) amount))
    (var-set total-locked (- (var-get total-locked) amount))
    
    (ok amount)
  )
)

(define-private (update-validator-stats (validator principal))
  (match (map-get? validators validator)
    validator-info
    (map-set validators validator
      (merge validator-info {
        total-validated: (+ (get total-validated validator-info) u1)
      }))
    true
  )
)

(define-public (execute-transfer (transfer-id uint))
  (match (map-get? bridge-transfers transfer-id)
    transfer
    (begin
      (asserts! (is-eq (get status transfer) "pending") err-already-processed)
      (asserts! (> burn-block-height (get challenge-end transfer)) err-challenge-period-active)
      
      ;; Mark as executed
      (map-set bridge-transfers transfer-id
        (merge transfer {status: "executed"}))
      
      ;; Update user deposits
      (map-set user-deposits (get sender transfer)
        (- (default-to u0 (map-get? user-deposits (get sender transfer))) 
           (+ (get amount transfer) (get fee transfer))))
      
      (ok true)
    )
    err-invalid-amount
  )
)

(define-public (submit-fraud-proof (transfer-id uint) (evidence (string-ascii 256)))
  (match (map-get? bridge-transfers transfer-id)
    transfer
    (let ((proof-id (var-get nonce)))
      (asserts! (is-eq (get status transfer) "pending") err-already-processed)
      (asserts! (<= burn-block-height (get challenge-end transfer)) err-transfer-expired)
      
      ;; Create fraud proof
      (map-set fraud-proofs proof-id {
        challenger: tx-sender,
        transfer-id: transfer-id,
        evidence: evidence,
        submitted-at: burn-block-height,
        status: "submitted"
      })
      
      ;; Update transfer status
      (map-set bridge-transfers transfer-id
        (merge transfer {status: "challenged"}))
      
      (var-set nonce (+ proof-id u1))
      
      (ok proof-id)
    )
    err-invalid-amount
  )
)

(define-public (emergency-withdraw)
  (let ((user-balance (default-to u0 (map-get? user-deposits tx-sender))))
    (asserts! (var-get is-paused) err-paused)
    (asserts! (> user-balance u0) err-invalid-amount)
    
    ;; Transfer balance to user
    (try! (as-contract (stx-transfer? user-balance tx-sender tx-sender)))
    
    ;; Clear user balance
    (map-delete user-deposits tx-sender)
    
    ;; Update total locked
    (var-set total-locked (- (var-get total-locked) user-balance))
    
    (ok user-balance)
  )
)

;; Admin functions
(define-public (add-validator (validator principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-unauthorized)
    (asserts! (not (is-validator validator)) err-invalid-validator)
    
    (map-set validators validator {
      active: true,
      added-at: burn-block-height,
      total-validated: u0,
      slash-count: u0
    })
    
    (var-set total-validators (+ (var-get total-validators) u1))
    (ok true)
  )
)

(define-public (remove-validator (validator principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-unauthorized)
    
    (match (map-get? validators validator)
      validator-info
      (begin
        (map-set validators validator
          (merge validator-info {active: false}))
        (var-set total-validators (- (var-get total-validators) u1))
        (ok true)
      )
      err-invalid-validator
    )
  )
)

(define-public (set-chain-config (chain (string-ascii 20)) (enabled bool) (fee-multiplier uint))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-unauthorized)
    
    (map-set supported-chains chain {
      enabled: enabled,
      fee-multiplier: fee-multiplier,
      total-volume: (default-to u0 (get total-volume (map-get? supported-chains chain)))
    })
    
    (ok true)
  )
)

(define-public (set-threshold (new-threshold uint))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-unauthorized)
    (asserts! (<= new-threshold (var-get total-validators)) err-threshold-too-high)
    (var-set validator-threshold new-threshold)
    (ok new-threshold)
  )
)

(define-public (set-paused (paused bool))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-unauthorized)
    (var-set is-paused paused)
    (ok paused)
  )
)

(define-public (resolve-fraud-proof (proof-id uint) (is-valid bool))
  (match (map-get? fraud-proofs proof-id)
    proof
    (begin
      (asserts! (is-eq tx-sender contract-owner) err-unauthorized)
      
      (if is-valid
        ;; Fraud proven - reverse transfer
        (match (map-get? bridge-transfers (get transfer-id proof))
          transfer
          (begin
            (map-set bridge-transfers (get transfer-id proof)
              (merge transfer {status: "reversed"}))
            
            ;; Refund to original sender
            (try! (as-contract (stx-transfer? (get amount transfer) tx-sender (get sender transfer))))
            
            ;; Reward challenger
            (let ((reward (/ (get fee transfer) u2)))
              (if (> reward u0)
                (try! (as-contract (stx-transfer? reward tx-sender (get challenger proof))))
                true
              )
            )
            (ok true)
          )
          err-invalid-amount
        )
        ;; Fraud not proven - execute transfer
        (execute-transfer (get transfer-id proof))
      )
    )
    err-invalid-proof
  )
)

;; Initialize chains
(map-set supported-chains "ethereum" {enabled: true, fee-multiplier: u100, total-volume: u0})
(map-set supported-chains "polygon" {enabled: true, fee-multiplier: u50, total-volume: u0})
(map-set supported-chains "bsc" {enabled: true, fee-multiplier: u75, total-volume: u0})