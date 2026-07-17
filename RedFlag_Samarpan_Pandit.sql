-- ==========================================================
-- RedFlag – Fraud Detection Submission
-- Student: Samarpan Pandit
-- Batch: Data Analytics June 2026
-- ==========================================================

USE redflag;

-- ==========================================================
-- PATTERN 1 – VELOCITY FRAUD
--
-- Detect users who perform 30 or more transactions
-- on a single calendar day.
--
-- Expected suspects: Approximately 45–55 user-days.
-- ==========================================================
SELECT
    user_id,
    DATE(txn_time) AS attack_date,
    COUNT(*) AS daily_transaction_count
FROM transactions
GROUP BY
    user_id,
    DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY daily_transaction_count DESC;

-- Findings:
-- Total suspect user-days: 50
-- Highest transaction count: User 14569 performed 60 transactions on 2024-04-03.
-- Example users:
-- User 14569 (60 transactions on 2024-04-03),
-- User 14556 (60 transactions on 2024-05-28),
-- User 14564 (59 transactions on 2024-02-15).

-- ==========================================================
-- PATTERN 2 – ROUND-AMOUNT CLUSTERING
--
-- Detect users who frequently perform transactions with
-- exact round amounts (₹100, ₹200, ₹500, ₹1000, ₹2000,
-- ₹5000, ₹10000). Users with 15 or more such transactions
-- may indicate money laundering or structured transfers.
--
-- Expected suspects: Exactly 25 users.
-- ==========================================================

SELECT
    user_id,
    COUNT(*) AS round_amount_transactions
FROM transactions
WHERE amount IN (100, 200, 500, 1000, 2000, 5000, 10000)
GROUP BY user_id
HAVING COUNT(*) >= 15
ORDER BY round_amount_transactions DESC;

-- Findings:
-- Total suspect users: 25.
-- Highest round-amount transaction count: 30 transactions.
-- Example users: User 14533 (30 round-amount transactions),
-- User 14534 (30 round-amount transactions),
-- User 14535 (30 round-amount transactions).

-- ==========================================================
-- PATTERN 3 – CARD TESTING
--
-- Detect users who perform 30 or more transactions below
-- ₹10 on a single calendar day. Such behaviour is commonly
-- associated with fraudsters testing stolen credit or debit
-- cards before making larger fraudulent purchases.
--
-- Expected suspects: Exactly 20 users.
-- ==========================================================

SELECT
    user_id,
    DATE(txn_time) AS transaction_date,
    COUNT(*) AS small_value_transactions
FROM transactions
WHERE amount < 10
GROUP BY
    user_id,
    DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY small_value_transactions DESC;

-- Findings:
-- Total suspect user-days: 20.
-- Highest small-value transaction count: User 14569 performed 60 transactions under ₹10 on 2024-04-03.
-- Example users: User 14569 (60 transactions on 2024-04-03),
-- User 14556 (60 transactions on 2024-05-28),
-- User 14564 (59 transactions on 2024-02-15).

-- ==========================================================
-- PATTERN 4 – FAILED-THEN-SUCCEEDED (SIMPLIFIED)
--
-- Detect users who have 20 or more FAILED transactions.
-- A high number of failed payment attempts may indicate
-- automated card-testing scripts or repeated attempts to
-- use stolen card credentials.
--
-- Expected suspects: Exactly 25 users.
-- ==========================================================

SELECT
    user_id,
    COUNT(*) AS failed_transactions
FROM transactions
WHERE status = 'FAILED'
GROUP BY user_id
HAVING COUNT(*) >= 20
ORDER BY failed_transactions DESC;

-- Findings:
-- Total suspect users: 25.
-- Highest failed transaction count: User 14595 recorded 35 failed transactions.
-- Example users: User 14595 (35 failed transactions),
-- User 14593 (34 failed transactions),
-- User 14576 (33 failed transactions).

-- ==========================================================
-- PATTERN 5 – ODD-HOUR CONCENTRATION
--
-- Detect users whose transaction activity is heavily
-- concentrated between 2 AM and 4 AM. Users with at least
-- 30 total transactions and 80% or more of their activity
-- during these hours may indicate automated fraud scripts.
--
-- Expected suspects: Exactly 20 users.
-- ==========================================================

SELECT
    user_id,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1
            ELSE 0
        END
    ) AS odd_hour_transactions,
    ROUND(
        SUM(
            CASE
                WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS odd_hour_percentage
FROM transactions
GROUP BY user_id
HAVING
    COUNT(*) >= 30
    AND
    SUM(
        CASE
            WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1
            ELSE 0
        END
    ) * 1.0 / COUNT(*) >= 0.80
ORDER BY odd_hour_percentage DESC,
         odd_hour_transactions DESC;
         
-- Findings:
-- Total suspect users: 20.
-- Highest odd-hour concentration: User 14606 performed 49 out of 52 transactions
-- (94.23%) between 2 AM and 4 AM.
-- Example users: User 14606 (94.23% odd-hour transactions),
-- User 14609 (93.75% odd-hour transactions),
-- User 14608 (92.06% odd-hour transactions).

-- ==========================================================
-- PATTERN 6 – MULE ACCOUNTS (SIMPLIFIED)
--
-- Detect users with 8 or more CREDIT transactions.
-- Accounts receiving frequent CREDIT transactions may
-- indicate mule accounts used to receive fraudulent funds.
--
-- Expected suspects: Approximately 30 users.
-- ==========================================================

SELECT
    user_id,
    COUNT(*) AS credit_transactions
FROM transactions
WHERE txn_type = 'CREDIT'
GROUP BY user_id
HAVING COUNT(*) >= 8
ORDER BY credit_transactions DESC;

-- Findings:
-- Total suspect users: 30.
-- Highest CREDIT transaction count: Users 14630, 14637, 14640,
-- 14643 and 14645 each recorded 15 CREDIT transactions.
-- Example users: User 14630 (15 CREDIT transactions),
-- User 14637 (15 CREDIT transactions),
-- User 14640 (15 CREDIT transactions).

-- ==========================================================
-- PATTERN 7 – REFUND ABUSE
--
-- Detect users with an unusually high proportion of REFUND
-- transactions. Genuine users rarely exceed a 5% refund rate,
-- while fraudsters exploiting chargeback schemes or merchant
-- loopholes often have refund rates above 40%.
--
-- Expected suspects: 24–25 users.
-- ==========================================================

SELECT
    user_id,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN txn_type = 'REFUND' THEN 1
            ELSE 0
        END
    ) AS refund_transactions,
    ROUND(
        SUM(
            CASE
                WHEN txn_type = 'REFUND' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS refund_percentage
FROM transactions
GROUP BY user_id
HAVING
    COUNT(*) >= 20
    AND
    SUM(
        CASE
            WHEN txn_type = 'REFUND' THEN 1
            ELSE 0
        END
    ) * 1.0 / COUNT(*) > 0.40
ORDER BY refund_percentage DESC,
         refund_transactions DESC;

-- Findings:
-- Total suspect users: 24.
-- Highest refund ratio: User 14662 recorded 25 REFUND transactions
-- out of 39 total transactions (64.10% refund rate).
-- Example users: User 14662 (64.10% refund rate),
-- User 14670 (64.00% refund rate),
-- User 14665 (63.89% refund rate).

-- ==========================================================
-- PATTERN 8 – MERCHANT COLLUSION
--
-- Detect merchants where the top 5 users contribute
-- more than 60% of the merchant's total transaction value.
-- Such merchants may be colluding with a small group of
-- users to launder money or generate fake transactions.
--
-- Expected suspects: Exactly 15 merchants.
-- ==========================================================

WITH user_volume AS (
    SELECT
        merchant_id,
        user_id,
        SUM(amount) AS user_total
    FROM transactions
    GROUP BY merchant_id, user_id
),

ranked_users AS (
    SELECT
        merchant_id,
        user_id,
        user_total,
        ROW_NUMBER() OVER (
            PARTITION BY merchant_id
            ORDER BY user_total DESC
        ) AS rn
    FROM user_volume
),

top5_volume AS (
    SELECT
        merchant_id,
        SUM(user_total) AS top5_total
    FROM ranked_users
    WHERE rn <= 5
    GROUP BY merchant_id
),

merchant_volume AS (
    SELECT
        merchant_id,
        SUM(amount) AS merchant_total
    FROM transactions
    GROUP BY merchant_id
)

SELECT
    m.merchant_id,
    m.merchant_total,
    t.top5_total,
    ROUND(
        t.top5_total * 100.0 / m.merchant_total,
        2
    ) AS top5_percentage
FROM merchant_volume m
JOIN top5_volume t
ON m.merchant_id = t.merchant_id
WHERE
    t.top5_total * 1.0 / m.merchant_total > 0.60
ORDER BY top5_percentage DESC;

-- Findings:
-- Total suspect merchants: 15.
-- Highest concentration: Merchant 12 received 99.91% of its
-- transaction value from its top 5 users.
-- Example merchants: Merchant 12 (99.91% top-5 contribution),
-- Merchant 8 (99.87% top-5 contribution),
-- Merchant 13 (99.85% top-5 contribution).

-- ==========================================================
-- PATTERN 9 – JUST-UNDER-THRESHOLD (STRUCTURING)
--
-- Detect users who repeatedly perform transactions of
-- exactly ₹9,999.00 to avoid enhanced KYC verification.
-- Such behaviour is a classic anti-money-laundering
-- technique known as structuring or smurfing.
--
-- Expected suspects: Exactly 20 users.
-- ==========================================================

SELECT
    user_id,
    COUNT(*) AS threshold_transactions
FROM transactions
WHERE amount = 9999.00
GROUP BY user_id
HAVING COUNT(*) >= 10
ORDER BY threshold_transactions DESC;

-- Findings:
-- Total suspect users: 20.
-- Highest threshold transaction count: Users 14680 and 14690
-- each performed 25 transactions of exactly ₹9,999.00.
-- Example users: User 14680 (25 threshold transactions),
-- User 14690 (25 threshold transactions),
-- User 14693 (22 threshold transactions).

-- ==========================================================
-- PATTERN 10 – DORMANT-THEN-ACTIVE
--
-- Detect users who remain inactive for at least 90 days
-- and then suddenly become highly active. Such behaviour
-- is a common indicator of account takeover after a long
-- period of dormancy.
--
-- Expected suspects: 25–27 users.
-- ==========================================================

WITH transaction_history AS (
    SELECT
        user_id,
        txn_time,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_txn_time
    FROM transactions
),

dormant_accounts AS (
    SELECT
        user_id,
        txn_time AS first_txn_after_gap
    FROM transaction_history
    WHERE previous_txn_time IS NOT NULL
      AND TIMESTAMPDIFF(DAY, previous_txn_time, txn_time) >= 90
)

SELECT
    d.user_id,
    COUNT(t.txn_id) AS post_gap_transactions
FROM dormant_accounts d
JOIN transactions t
    ON d.user_id = t.user_id
   AND t.txn_time >= d.first_txn_after_gap
GROUP BY
    d.user_id
HAVING COUNT(t.txn_id) >= 15
ORDER BY post_gap_transactions DESC;

-- Findings:
-- Total suspect users: 26.
-- Highest post-gap activity: User 14526 performed 55 transactions
-- after a dormancy period of at least 90 days.
-- Example users: User 14526 (55 post-gap transactions),
-- User 14701 (28 post-gap transactions),
-- User 14708 (28 post-gap transactions).

-- ==========================================================
-- PATTERN 11 – VELOCITY SPIKE
--
-- Detect users whose transaction activity suddenly spikes
-- to at least 5 times their historical monthly average,
-- with the peak month containing at least 20 transactions.
-- Such sudden behavioural changes are a strong indicator
-- of account takeover or fraudulent activity.
--
-- Expected suspects: 35–45 users.
-- ==========================================================

WITH monthly_transactions AS (
    SELECT
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m') AS transaction_month,
        COUNT(*) AS monthly_transaction_count
    FROM transactions
    GROUP BY
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m')
),

user_statistics AS (
    SELECT
        user_id,
        AVG(monthly_transaction_count) AS average_monthly_transactions,
        MAX(monthly_transaction_count) AS peak_monthly_transactions
    FROM monthly_transactions
    GROUP BY user_id
)

SELECT
    user_id,
    ROUND(average_monthly_transactions, 2) AS average_monthly_transactions,
    peak_monthly_transactions,
    ROUND(
        peak_monthly_transactions / average_monthly_transactions,
        2
    ) AS spike_ratio
FROM user_statistics
WHERE
    peak_monthly_transactions >= 20
    AND
    peak_monthly_transactions >= average_monthly_transactions * 5
ORDER BY
    spike_ratio DESC,
    peak_monthly_transactions DESC;

-- Findings:
-- Total suspect users: 3.
-- Highest velocity spike: User 14517 recorded a peak monthly
-- transaction count of 41 against an average of 8.00
-- transactions per month (spike ratio: 5.13).
-- Example users: User 14517 (41 peak monthly transactions,
-- spike ratio 5.13), User 14504 (45 peak monthly transactions,
-- spike ratio 5.09), User 14528 (39 peak monthly transactions,
-- spike ratio 5.09).

-- ==========================================================
-- PATTERN 12 – GEOGRAPHIC IMPOSSIBILITY
--
-- Detect users who perform two consecutive transactions
-- from different cities within 60 minutes. Such behaviour
-- is physically impossible and is a strong indicator of
-- account takeover or stolen-card usage.
--
-- Expected suspects: Exactly 15 users.
-- ==========================================================

WITH transaction_history AS (
    SELECT
        user_id,
        city,
        txn_time,
        LAG(city) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_city,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_txn_time
    FROM transactions
)

SELECT
    user_id,
    previous_city,
    city AS current_city,
    previous_txn_time,
    txn_time AS current_txn_time,
    TIMESTAMPDIFF(
        MINUTE,
        previous_txn_time,
        txn_time
    ) AS minutes_between_transactions
FROM transaction_history
WHERE
    previous_city IS NOT NULL
    AND previous_city <> city
    AND TIMESTAMPDIFF(
            MINUTE,
            previous_txn_time,
            txn_time
        ) <= 60
ORDER BY
    user_id,
    current_txn_time;

-- Findings:
-- Total suspect users: 15.
-- Multiple geographically impossible transaction pairs were detected,
-- where users performed consecutive transactions from different cities
-- within 60 minutes, indicating possible account takeover or stolen-card usage.
-- Example users: User 14741 (Vadodara → Thiruvananthapuram in 30 minutes),
-- User 14745 (Surat → Thiruvananthapuram in 9 minutes),
-- User 14750 (Visakhapatnam → Delhi in 1 minute).