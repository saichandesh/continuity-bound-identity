# Results summary

## Detection matrix (most common outcome, % of trials)

| scenario | L1_hash_chain | L2_witness_counter | L3_fresh_nonce | L4_short_lived_cred | L5_hardware_key | L6_runtime_binding | L6S_runtime+succession | L7_continuity_bound |
|---|---|---|---|---|---|---|---|---|
| B0_honest | OK 100% | OK 100% | OK 100% | OK 100% | OK 100% | OK 100% | OK 100% | OK 100% |
| B1_authorized_handoff | OK 100% | OK 100% | OK 100% | OK 100% | OK 100% | FALSE ALARM 100% | OK 100% | OK 100% |
| B2_crash_restart | OK 100% | OK 100% | OK 100% | OK 100% | OK 100% | FALSE ALARM 100% | FALSE ALARM 100% | FALSE ALARM 100% |
| A1_simultaneous (same_host) | audit only 100% | detected 100% | detected 100% | detected 100% | detected 100% | detected 100% | detected 100% | detected 100% |
| A1_simultaneous (cross_host) | audit only 100% | detected 100% | detected 100% | detected 100% | blocked 100% | blocked 100% | blocked 100% | blocked 100% |
| A2_dormant_handoff (same_host) | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | detected 100% | detected 100% | detected 100% |
| A2_dormant_handoff (cross_host) | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | blocked 100% | blocked 100% | blocked 100% | blocked 100% |
| A3_alternating (same_host) | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | detected 100% | detected 100% | detected 100% |
| A3_alternating (cross_host) | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | blocked 100% | blocked 100% | blocked 100% | blocked 100% |
| A4_rollback (same_host) | audit only 100% | detected 100% | detected 100% | detected 100% | detected 100% | detected 100% | detected 100% | detected 100% |
| A4_rollback (cross_host) | audit only 100% | detected 100% | detected 100% | detected 100% | blocked 100% | blocked 100% | blocked 100% | blocked 100% |
| A5_funnel | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | detected 100% |
| A6_throttled_funnel | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | UNDETECTED 100% | detected 58% |

## Hidden-copy throughput (A5 funnel) vs detectable parallel copies

| think mean (s) | N | single/h | naive parallel/h | hidden funnel/h | hidden speedup | evasion tax |
|---|---|---|---|---|---|---|
| 0.5 | 1 | 6588 | 6588 | 6359 | 1.0x | 3.5% |
| 0.5 | 2 | 6588 | 13070 | 12519 | 1.9x | 4.2% |
| 0.5 | 4 | 6588 | 26173 | 24534 | 3.7x | 6.3% |
| 0.5 | 8 | 6588 | 52332 | 44327 | 6.7x | 15.3% |
| 0.5 | 16 | 6588 | 104822 | 51426 | 7.8x | 50.9% |
| 0.5 | 32 | 6588 | 209253 | 51427 | 7.8x | 75.4% |
| 0.5 | 64 | 6588 | 418843 | 51427 | 7.8x | 87.7% |
| 0.5 | 128 | 6588 | 837757 | 51427 | 7.8x | 93.9% |
| 2.0 | 1 | 1781 | 1781 | 1765 | 1.0x | 0.9% |
| 2.0 | 2 | 1781 | 3558 | 3520 | 2.0x | 1.1% |
| 2.0 | 4 | 1781 | 7060 | 6977 | 3.9x | 1.2% |
| 2.0 | 8 | 1781 | 14030 | 13818 | 7.8x | 1.5% |
| 2.0 | 16 | 1781 | 28091 | 27394 | 15.4x | 2.5% |
| 2.0 | 32 | 1781 | 56201 | 49330 | 27.7x | 12.2% |
| 2.0 | 64 | 1781 | 112508 | 51424 | 28.9x | 54.3% |
| 2.0 | 128 | 1781 | 224536 | 51425 | 28.9x | 77.1% |
| 8.0 | 1 | 442 | 442 | 441 | 1.0x | 0.4% |
| 8.0 | 2 | 442 | 906 | 904 | 2.0x | 0.2% |
| 8.0 | 4 | 442 | 1813 | 1809 | 4.1x | 0.2% |
| 8.0 | 8 | 442 | 3625 | 3617 | 8.2x | 0.2% |
| 8.0 | 16 | 442 | 7186 | 7166 | 16.2x | 0.3% |
| 8.0 | 32 | 442 | 14293 | 14240 | 32.2x | 0.4% |
| 8.0 | 64 | 442 | 28606 | 28398 | 64.2x | 0.7% |
| 8.0 | 128 | 442 | 57274 | 51181 | 115.7x | 10.6% |
| 30.0 | 1 | 118 | 118 | 118 | 1.0x | 0.0% |
| 30.0 | 2 | 118 | 233 | 232 | 2.0x | 0.6% |
| 30.0 | 4 | 118 | 477 | 478 | 4.0x | -0.2% |
| 30.0 | 8 | 118 | 968 | 967 | 8.2x | 0.1% |
| 30.0 | 16 | 118 | 1940 | 1937 | 16.4x | 0.2% |
| 30.0 | 32 | 118 | 3883 | 3879 | 32.8x | 0.1% |
| 30.0 | 64 | 118 | 7690 | 7683 | 65.0x | 0.1% |
| 30.0 | 128 | 118 | 15324 | 15294 | 129.4x | 0.2% |

## Rate cap per identity

| think mean (s) | margin | cap/min | honest false alarms | max hidden speedup |
|---|---|---|---|---|
| 2.0 | x1.25 | 36 | 98.0% | 1.23x |
| 2.0 | x1.5 | 43 | 9.7% | 1.47x |
| 2.0 | x2 | 58 | 0.0% | 1.98x |
| 2.0 | x3 | 87 | 0.0% | 2.97x |
| 2.0 | x4 | 117 | 0.0% | 4.00x |
| 2.0 | x6 | 175 | 0.0% | 5.98x |
| 8.0 | x1.25 | 9 | 100.0% | 1.21x |
| 8.0 | x1.5 | 11 | 95.7% | 1.48x |
| 8.0 | x2 | 14 | 11.0% | 1.88x |
| 8.0 | x3 | 22 | 0.0% | 2.95x |
| 8.0 | x4 | 29 | 0.0% | 3.89x |
| 8.0 | x6 | 44 | 0.0% | 5.90x |
