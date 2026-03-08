;; ProofDelta - Zero-Knowledge Identity Verification System

;; This contract implements a privacy-preserving KYC compliance system using

;; =========================================================
;; CONSTANTS
;; =========================================================

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-REGISTERED (err u101))
(define-constant ERR-NOT-REGISTERED (err u102))
(define-constant ERR-INVALID-PROOF (err u103))
(define-constant ERR-INSUFFICIENT-STAKE (err u104))
(define-constant ERR-PROOF-EXPIRED (err u105))
(define-constant ERR-INVALID-ATTRIBUTE (err u106))
(define-constant ERR-BOND-LOCKED (err u107))

;; Minimum stake required to register as a verifier (in uSTX)
(define-constant MIN-VERIFIER-STAKE u1000000)

;; Proof validity window in blocks (~7 days at 10 min/block)
(define-constant PROOF-VALIDITY-BLOCKS u1008)

;; Reputation score bounds
(define-constant MAX-REPUTATION-SCORE u1000)
(define-constant INITIAL-REPUTATION-SCORE u100)

;; Reward for successful verification mining (in uSTX)
(define-constant VERIFICATION-MINING-REWARD u500)

;; =========================================================
;; DATA MAPS AND VARS
;; =========================================================

;; Global counters
(define-data-var total-identities uint u0)
(define-data-var total-verifiers uint u0)
(define-data-var total-proofs-issued uint u0)

;; Identity Anchor: binds a verified credential commitment to a principal.
;; commitment   - sha256 hash of the user's identity bundle (off-chain)
;; active       - whether this anchor is currently valid
;; created-at   - block height at registration
(define-map identity-anchors
  principal
  {
    commitment:  (buff 32),
    active:      bool,
    created-at:  uint,
    reputation:  uint
  }
)

;; Verifier Registry: authorized oracles that can issue proofs.
;; stake        - amount of uSTX locked as a verification bond
;; active       - whether the verifier is currently active
;; proofs-issued - lifetime proof count for this verifier
(define-map verifier-registry
  principal
  {
    stake:         uint,
    active:        bool,
    proofs-issued: uint,
    registered-at: uint
  }
)

;; Proof Records: stores issued zero-knowledge proofs.
;; attribute    - the specific attribute proven (e.g., "age-over-18", "accredited-investor")
;; proof-hash   - sha256 hash of the off-chain zk-SNARK proof
;; verifier     - the verifier who attested this proof
;; issued-at    - block height when proof was created
;; expires-at   - block height when proof expires
;; revoked      - whether the proof has been revoked
(define-map proof-records
  { subject: principal, attribute: (string-ascii 64) }
  {
    proof-hash:  (buff 32),
    verifier:    principal,
    issued-at:   uint,
    expires-at:  uint,
    revoked:     bool
  }
)

;; Delta Proof: tracks changes in verification status over time
;; without exposing absolute values. Stores a commitment to the
;; difference between two verification states.
;; delta-commitment - commitment to the delta value (off-chain computation)
;; previous-proof   - hash of the prior proof this delta is derived from
(define-map delta-proofs
  { subject: principal, attribute: (string-ascii 64), sequence: uint }
  {
    delta-commitment: (buff 32),
    previous-proof:   (buff 32),
    issued-at:        uint,
    verifier:         principal
  }
)

;; Tracks the latest delta sequence number per (subject, attribute)
(define-map delta-sequence
  { subject: principal, attribute: (string-ascii 64) }
  uint
)

;; =========================================================
;; PRIVATE HELPERS
;; =========================================================

;; Check that a principal has an active identity anchor
(define-private (has-active-anchor (user principal))
  (match (map-get? identity-anchors user)
    entry (get active entry)
    false
  )
)

;; Check that a principal is an active verifier
(define-private (is-active-verifier (verifier principal))
  (match (map-get? verifier-registry verifier)
    entry (get active entry)
    false
  )
)

;; Returns true if a proof exists, is not revoked, and has not expired
(define-private (proof-is-valid (subject principal) (attribute (string-ascii 64)))
  (match (map-get? proof-records { subject: subject, attribute: attribute })
    record
    (and
      (not (get revoked record))
      (<= block-height (get expires-at record))
    )
    false
  )
)

;; =========================================================
;; IDENTITY ANCHOR FUNCTIONS
;; =========================================================

;; Register a new identity anchor.
;; The commitment is a sha256 hash of the user's identity bundle
;; computed off-chain; no raw personal data is stored on-chain.
(define-public (register-identity (commitment (buff 32)))
  (let ((caller tx-sender))
    (asserts! (is-none (map-get? identity-anchors caller)) ERR-ALREADY-REGISTERED)
    (map-set identity-anchors caller
      {
        commitment:  commitment,
        active:      true,
        created-at:  block-height,
        reputation:  INITIAL-REPUTATION-SCORE
      }
    )
    (var-set total-identities (+ (var-get total-identities) u1))
    (ok true)
  )
)

;; Update the identity commitment (e.g., after re-verification).
;; Only the identity owner may update their own anchor.
(define-public (update-identity-commitment (new-commitment (buff 32)))
  (let ((caller tx-sender))
    (asserts! (has-active-anchor caller) ERR-NOT-REGISTERED)
    (map-set identity-anchors caller
      (merge (unwrap-panic (map-get? identity-anchors caller))
             { commitment: new-commitment })
    )
    (ok true)
  )
)

;; Deactivate an identity anchor (self-revocation).
(define-public (deactivate-identity)
  (let ((caller tx-sender))
    (asserts! (has-active-anchor caller) ERR-NOT-REGISTERED)
    (map-set identity-anchors caller
      (merge (unwrap-panic (map-get? identity-anchors caller))
             { active: false })
    )
    (ok true)
  )
)

;; =========================================================
;; VERIFIER REGISTRY FUNCTIONS
;; =========================================================

;; Register as a verifier by staking the minimum bond.
;; Stake is held in this contract as a verification bond.
(define-public (register-verifier)
  (let (
    (caller tx-sender)
    (stake-amount MIN-VERIFIER-STAKE)
  )
    (asserts! (is-none (map-get? verifier-registry caller)) ERR-ALREADY-REGISTERED)
    (try! (stx-transfer? stake-amount caller (as-contract tx-sender)))
    (map-set verifier-registry caller
      {
        stake:         stake-amount,
        active:        true,
        proofs-issued: u0,
        registered-at: block-height
      }
    )
    (var-set total-verifiers (+ (var-get total-verifiers) u1))
    (ok true)
  )
)

;; Deactivate verifier and reclaim staked bond.
;; Only the verifier themselves can deactivate.
(define-public (deactivate-verifier)
  (let (
    (caller tx-sender)
    (verifier-data (unwrap! (map-get? verifier-registry caller) ERR-NOT-REGISTERED))
  )
    (asserts! (get active verifier-data) ERR-BOND-LOCKED)
    (try! (as-contract (stx-transfer? (get stake verifier-data) tx-sender caller)))
    (map-set verifier-registry caller
      (merge verifier-data { active: false, stake: u0 })
    )
    (ok true)
  )
)

;; =========================================================
;; PROOF CIRCUIT FUNCTIONS
;; =========================================================

;; Issue a new proof for a subject's identity attribute.
;; proof-hash is the sha256 hash of the off-chain zk-SNARK proof.
;; attribute examples: "age-over-18", "accredited-investor", "kyc-tier-1"
(define-public (issue-proof
    (subject    principal)
    (attribute  (string-ascii 64))
    (proof-hash (buff 32)))
  (let (
    (caller tx-sender)
    (expires-at (+ block-height PROOF-VALIDITY-BLOCKS))
  )
    (asserts! (is-active-verifier caller) ERR-NOT-AUTHORIZED)
    (asserts! (has-active-anchor subject) ERR-NOT-REGISTERED)
    (map-set proof-records
      { subject: subject, attribute: attribute }
      {
        proof-hash:  proof-hash,
        verifier:    caller,
        issued-at:   block-height,
        expires-at:  expires-at,
        revoked:     false
      }
    )
    ;; Increment verifier's proof counter
    (map-set verifier-registry caller
      (merge (unwrap-panic (map-get? verifier-registry caller))
             { proofs-issued: (+ (get proofs-issued (unwrap-panic (map-get? verifier-registry caller))) u1) })
    )
    ;; Reward the verifier for mining a verification
    (try! (as-contract (stx-transfer? VERIFICATION-MINING-REWARD tx-sender caller)))
    (var-set total-proofs-issued (+ (var-get total-proofs-issued) u1))
    (ok expires-at)
  )
)

;; Revoke a proof. Only the issuing verifier or contract owner may revoke.
(define-public (revoke-proof (subject principal) (attribute (string-ascii 64)))
  (let (
    (caller tx-sender)
    (record (unwrap! (map-get? proof-records { subject: subject, attribute: attribute }) ERR-INVALID-PROOF))
  )
    (asserts!
      (or (is-eq caller (get verifier record)) (is-eq caller CONTRACT-OWNER))
      ERR-NOT-AUTHORIZED
    )
    (map-set proof-records
      { subject: subject, attribute: attribute }
      (merge record { revoked: true })
    )
    (ok true)
  )
)

;; =========================================================
;; DELTA PROOF FUNCTIONS
;; =========================================================

;; Issue a delta proof capturing a change in verification status.
;; delta-commitment: commitment to the computed delta value (off-chain)
;; previous-proof:   hash of the proof this delta is derived from
(define-public (issue-delta-proof
    (subject          principal)
    (attribute        (string-ascii 64))
    (delta-commitment (buff 32))
    (previous-proof   (buff 32)))
  (let (
    (caller   tx-sender)
    (seq-key  { subject: subject, attribute: attribute })
    (current-seq (default-to u0 (map-get? delta-sequence seq-key)))
    (next-seq (+ current-seq u1))
  )
    (asserts! (is-active-verifier caller) ERR-NOT-AUTHORIZED)
    (asserts! (has-active-anchor subject) ERR-NOT-REGISTERED)
    (map-set delta-proofs
      { subject: subject, attribute: attribute, sequence: next-seq }
      {
        delta-commitment: delta-commitment,
        previous-proof:   previous-proof,
        issued-at:        block-height,
        verifier:         caller
      }
    )
    (map-set delta-sequence seq-key next-seq)
    (ok next-seq)
  )
)

;; =========================================================
;; REPUTATION ORACLE FUNCTIONS
;; =========================================================

;; Update the reputation score for a subject.
;; Only the contract owner (oracle operator) may call this.
;; Scores are bounded between 0 and MAX-REPUTATION-SCORE.
(define-public (update-reputation (subject principal) (new-score uint))
  (let ((caller tx-sender))
    (asserts! (is-eq caller CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (asserts! (has-active-anchor subject) ERR-NOT-REGISTERED)
    (asserts! (<= new-score MAX-REPUTATION-SCORE) ERR-INVALID-ATTRIBUTE)
    (map-set identity-anchors subject
      (merge (unwrap-panic (map-get? identity-anchors subject))
             { reputation: new-score })
    )
    (ok new-score)
  )
)

;; =========================================================
;; READ-ONLY FUNCTIONS
;; =========================================================

;; Verify that a subject has a currently valid proof for an attribute.
;; Returns true if proof exists, is not revoked, and has not expired.
(define-read-only (verify-attribute (subject principal) (attribute (string-ascii 64)))
  (ok (proof-is-valid subject attribute))
)

;; Get full proof record for a (subject, attribute) pair.
(define-read-only (get-proof (subject principal) (attribute (string-ascii 64)))
  (ok (map-get? proof-records { subject: subject, attribute: attribute }))
)

;; Get the identity anchor for a principal.
(define-read-only (get-identity-anchor (user principal))
  (ok (map-get? identity-anchors user))
)

;; Get verifier details.
(define-read-only (get-verifier (verifier principal))
  (ok (map-get? verifier-registry verifier))
)

;; Get reputation score for a subject.
(define-read-only (get-reputation (subject principal))
  (match (map-get? identity-anchors subject)
    entry (ok (get reputation entry))
    (err ERR-NOT-REGISTERED)
  )
)

;; Get the latest delta proof for a (subject, attribute) pair.
(define-read-only (get-latest-delta-proof (subject principal) (attribute (string-ascii 64)))
  (let (
    (seq (default-to u0 (map-get? delta-sequence { subject: subject, attribute: attribute })))
  )
    (ok (map-get? delta-proofs { subject: subject, attribute: attribute, sequence: seq }))
  )
)

;; Get protocol-level statistics.
(define-read-only (get-protocol-stats)
  (ok {
    total-identities:    (var-get total-identities),
    total-verifiers:     (var-get total-verifiers),
    total-proofs-issued: (var-get total-proofs-issued)
  })
)
