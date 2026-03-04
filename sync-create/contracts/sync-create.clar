;; SyncCreate Identity & Reputation System

;; Constants

(define-constant CONTRACT-OWNER tx-sender)

;; Error codes
(define-constant ERR-NOT-AUTHORIZED       (err u100))
(define-constant ERR-IDENTITY-EXISTS      (err u101))
(define-constant ERR-IDENTITY-NOT-FOUND   (err u102))
(define-constant ERR-CREDENTIAL-EXISTS    (err u103))
(define-constant ERR-CREDENTIAL-NOT-FOUND (err u104))
(define-constant ERR-INVALID-PROOF        (err u105))
(define-constant ERR-VALIDATOR-NOT-FOUND  (err u106))
(define-constant ERR-VALIDATOR-EXISTS     (err u107))
(define-constant ERR-IDENTITY-REVOKED     (err u108))
(define-constant ERR-PLATFORM-NOT-FOUND   (err u109))

;; Credential type identifiers
(define-constant CRED-TYPE-AGE        u1)
(define-constant CRED-TYPE-LOCATION   u2)
(define-constant CRED-TYPE-KYC        u3)
(define-constant CRED-TYPE-CREDENTIAL u4)
(define-constant CRED-TYPE-REPUTATION u5)

;; Reputation score bounds
(define-constant MIN-SCORE u0)
(define-constant MAX-SCORE u1000)

;; ----------------------------------------------------------------------------
;; Data Maps and Variables
;; ----------------------------------------------------------------------------

;; Global identity counter
(define-data-var identity-nonce uint u0)

;; Core identity anchor: maps principal -> on-chain identity record
(define-map identity-anchors
  principal
  {
    identity-id    : uint,       ;; unique numeric ID
    anchor-hash    : (buff 32),  ;; SHA-256 commitment to off-chain identity doc
    created-at     : uint,       ;; block height at registration
    active         : bool        ;; false if revoked
  }
)

;; Credential commitments: (principal, credential-type) -> commitment hash
;; The hash is H(credential-value || salt) stored off-chain by the user.
(define-map credential-commitments
  { owner: principal, cred-type: uint }
  {
    commitment  : (buff 32),  ;; H(value || salt)
    issuer      : principal,  ;; validator/issuer that attested this credential
    issued-at   : uint,       ;; block height
    expires-at  : (optional uint) ;; optional expiry block height
  }
)

;; Authorized validator contracts / principals per credential type
(define-map validators
  { cred-type: uint, validator: principal }
  { active: bool }
)

;; Registered platforms that can submit reputation events
(define-map platforms
  principal
  { name: (string-ascii 64), active: bool }
)

;; Reputation scores: principal -> score per platform
(define-map reputation-scores
  { owner: principal, platform: principal }
  {
    score      : uint,   ;; 0 - 1000
    tx-count   : uint,   ;; number of scored interactions
    updated-at : uint    ;; last update block height
  }
)

;; Aggregate reputation per principal (weighted average across platforms)
(define-map aggregate-reputation
  principal
  {
    total-score    : uint,
    platform-count : uint,
    updated-at     : uint
  }
)

;; ----------------------------------------------------------------------------
;; Private Helpers
;; ----------------------------------------------------------------------------

;; Check that a principal has an active (non-revoked) identity
(define-private (is-active-identity (who principal))
  (match (map-get? identity-anchors who)
    entry (get active entry)
    false
  )
)

;; Clamp a uint value between lo and hi
(define-private (clamp (val uint) (lo uint) (hi uint))
  (if (< val lo) lo (if (> val hi) hi val))
)

;; ----------------------------------------------------------------------------
;; Identity Management (Layer 1)
;; ----------------------------------------------------------------------------

;; Register a new identity anchor.
;; anchor-hash: SHA-256 of the user's off-chain identity document.
(define-public (register-identity (anchor-hash (buff 32)))
  (let
    (
      (caller tx-sender)
      (new-id (+ (var-get identity-nonce) u1))
    )
    (asserts! (is-none (map-get? identity-anchors caller)) ERR-IDENTITY-EXISTS)
    (map-set identity-anchors caller
      {
        identity-id : new-id,
        anchor-hash : anchor-hash,
        created-at  : stacks-block-height,
        active      : true
      }
    )
    (var-set identity-nonce new-id)
    (ok new-id)
  )
)

;; Update the anchor hash (e.g., after rotating keys or updating the off-chain doc).
(define-public (update-anchor (new-hash (buff 32)))
  (let ((entry (unwrap! (map-get? identity-anchors tx-sender) ERR-IDENTITY-NOT-FOUND)))
    (asserts! (get active entry) ERR-IDENTITY-REVOKED)
    (map-set identity-anchors tx-sender
      (merge entry { anchor-hash: new-hash })
    )
    (ok true)
  )
)

;; Revoke (deactivate) own identity.
(define-public (revoke-identity)
  (let ((entry (unwrap! (map-get? identity-anchors tx-sender) ERR-IDENTITY-NOT-FOUND)))
    (map-set identity-anchors tx-sender (merge entry { active: false }))
    (ok true)
  )
)

;; Read-only: retrieve identity anchor for any principal.
(define-read-only (get-identity (who principal))
  (map-get? identity-anchors who)
)

;; ----------------------------------------------------------------------------
;; Validator Registry (modular verification layer)
;; ----------------------------------------------------------------------------

;; Contract owner registers a trusted validator for a credential type.
(define-public (register-validator (cred-type uint) (validator principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (asserts! (is-none (map-get? validators { cred-type: cred-type, validator: validator }))
              ERR-VALIDATOR-EXISTS)
    (map-set validators { cred-type: cred-type, validator: validator } { active: true })
    (ok true)
  )
)

;; Contract owner deactivates a validator.
(define-public (deactivate-validator (cred-type uint) (validator principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (let ((v (unwrap! (map-get? validators { cred-type: cred-type, validator: validator })
                      ERR-VALIDATOR-NOT-FOUND)))
      (map-set validators { cred-type: cred-type, validator: validator }
               (merge v { active: false }))
      (ok true)
    )
  )
)

(define-read-only (is-valid-validator (cred-type uint) (validator principal))
  (match (map-get? validators { cred-type: cred-type, validator: validator })
    v (get active v)
    false
  )
)

;; ----------------------------------------------------------------------------
;; Credential Commitments (selective disclosure via hash proofs)
;; ----------------------------------------------------------------------------

;; A trusted validator issues a credential commitment for a user.
;; commitment = H(raw-value || salt), computed off-chain and submitted here.
(define-public (issue-credential
    (owner      principal)
    (cred-type  uint)
    (commitment (buff 32))
    (expires-at (optional uint))
  )
  (begin
    (asserts! (is-valid-validator cred-type tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (is-active-identity owner) ERR-IDENTITY-NOT-FOUND)
    (asserts! (is-none (map-get? credential-commitments { owner: owner, cred-type: cred-type }))
              ERR-CREDENTIAL-EXISTS)
    (map-set credential-commitments
      { owner: owner, cred-type: cred-type }
      {
        commitment : commitment,
        issuer     : tx-sender,
        issued-at  : stacks-block-height,
        expires-at : expires-at
      }
    )
    (ok true)
  )
)

;; Revoke / replace a credential (validator only).
(define-public (revoke-credential (owner principal) (cred-type uint))
  (begin
    (asserts! (is-valid-validator cred-type tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? credential-commitments { owner: owner, cred-type: cred-type }))
              ERR-CREDENTIAL-NOT-FOUND)
    (map-delete credential-commitments { owner: owner, cred-type: cred-type })
    (ok true)
  )
)

;; Verify a credential via selective disclosure proof.
;; The caller supplies H(value || salt); the contract checks it matches the
;; stored commitment without ever seeing the raw value.
(define-read-only (verify-credential
    (owner     principal)
    (cred-type uint)
    (proof     (buff 32))
  )
  (match (map-get? credential-commitments { owner: owner, cred-type: cred-type })
    entry
      (if (is-eq proof (get commitment entry))
        (ok true)
        ERR-INVALID-PROOF
      )
    ERR-CREDENTIAL-NOT-FOUND
  )
)

(define-read-only (get-credential (owner principal) (cred-type uint))
  (map-get? credential-commitments { owner: owner, cred-type: cred-type })
)

;; ----------------------------------------------------------------------------
;; Platform Registry
;; ----------------------------------------------------------------------------

;; Contract owner registers a platform (gig site, financial service, etc.)
(define-public (register-platform (platform principal) (name (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (map-set platforms platform { name: name, active: true })
    (ok true)
  )
)

(define-public (deactivate-platform (platform principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (let ((p (unwrap! (map-get? platforms platform) ERR-PLATFORM-NOT-FOUND)))
      (map-set platforms platform (merge p { active: false }))
      (ok true)
    )
  )
)

(define-read-only (get-platform (platform principal))
  (map-get? platforms platform)
)

;; ----------------------------------------------------------------------------
;; Reputation Scoring (Layer 3)
;; ----------------------------------------------------------------------------

;; A registered platform submits a reputation delta for a user after an
;; interaction. delta is added to (or subtracted from) the current score,
;; clamped to [MIN-SCORE, MAX-SCORE].
(define-public (submit-reputation-event
    (owner    principal)
    (delta-up uint)      ;; positive contribution
    (delta-dn uint)      ;; negative contribution
  )
  (let
    (
      (platform tx-sender)
      (p-entry  (unwrap! (map-get? platforms platform) ERR-PLATFORM-NOT-FOUND))
      (current  (default-to
                  { score: u500, tx-count: u0, updated-at: u0 }
                  (map-get? reputation-scores { owner: owner, platform: platform })
                ))
      (old-score (get score current))
      (new-score (clamp
                   (if (>= (+ old-score delta-up) delta-dn)
                     (- (+ old-score delta-up) delta-dn)
                     MIN-SCORE)
                   MIN-SCORE MAX-SCORE))
    )
    (asserts! (get active p-entry) ERR-NOT-AUTHORIZED)
    (asserts! (is-active-identity owner) ERR-IDENTITY-NOT-FOUND)
    (map-set reputation-scores
      { owner: owner, platform: platform }
      {
        score      : new-score,
        tx-count   : (+ (get tx-count current) u1),
        updated-at : stacks-block-height
      }
    )
    ;; Update aggregate reputation
    (let
      (
        (agg (default-to
               { total-score: u0, platform-count: u0, updated-at: u0 }
               (map-get? aggregate-reputation owner)
             ))
        (count (get platform-count agg))
        ;; Simple running average: new-total = old-total - old-score + new-score
        (new-total
          (if (> (+ (get total-score agg) new-score) old-score)
            (- (+ (get total-score agg) new-score) old-score)
            MIN-SCORE))
        (new-count (if (is-eq (get tx-count current) u0) (+ count u1) count))
      )
      (map-set aggregate-reputation owner
        {
          total-score    : new-total,
          platform-count : new-count,
          updated-at     : stacks-block-height
        }
      )
    )
    (ok new-score)
  )
)

;; Read-only: get per-platform reputation score for a user.
(define-read-only (get-reputation (owner principal) (platform principal))
  (map-get? reputation-scores { owner: owner, platform: platform })
)

;; Read-only: get aggregate reputation record.
(define-read-only (get-aggregate-reputation (owner principal))
  (map-get? aggregate-reputation owner)
)

;; Derived read-only: compute the average reputation score across all platforms.
(define-read-only (get-average-reputation (owner principal))
  (match (map-get? aggregate-reputation owner)
    agg
      (let ((count (get platform-count agg)))
        (if (> count u0)
          (ok (/ (get total-score agg) count))
          (ok u0)
        )
      )
    (ok u0)
  )
)

;; ----------------------------------------------------------------------------
;; Admin / Utility
;; ----------------------------------------------------------------------------

;; Read-only: check whether a principal is the contract owner.
(define-read-only (is-contract-owner (who principal))
  (is-eq who CONTRACT-OWNER)
)

;; Read-only: retrieve the current identity nonce (total identities registered).
(define-read-only (get-identity-count)
  (var-get identity-nonce)
)
