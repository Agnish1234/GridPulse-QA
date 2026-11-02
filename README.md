# GridPulse-QA: Enterprise Infrastructure Data Validation & System Reliability Suite

## Project Overview
GridPulse-QA is a lightweight data-governance validation filter engine built to shield public utility infrastructure management systems from application crashes, database corruption, and invalid entries. The software sits directly on incoming data pipelines, intercepting real-time telemetry updates from grid components before they commit to permanent storage.

## Validation Coverage Matrix
The engine contains automated evaluation layers handling 8 distinct operational test criteria:
*   **TC-01 [Normal Baseline Validation]:** Ensures clear inputs parse correctly.
*   **TC-02 [Malformed Structure Check]:** Detects and drops corrupted text strings.
*   **TC-03 [Field Omission Verification]:** Blocks records missing tracking indicators.
*   **TC-04 [Origin Authorization Audit]:** Identifies unauthorized device identifiers.
*   **TC-05 [Data Type Integrity Filtering]:** Drops plain text strings inside number values.
*   **TC-06 [Negative Value Interception]:** Flags impossible negative voltage inputs.
*   **TC-07 [Over-Voltage Spike Isolation]:** Catches input values exceeding upper metrics boundaries.
*   **TC-08 [Extreme Thermal Breach Isolation]:** Alerts supervisors of dangerous overheating fields.

## Deployment Instructions
1. Clone this repository locally.
2. Open terminal and run the automation engine:
   ```bash
   python grid_pulse_qa.py
   ```
3. Open `operational_audit.csv` to review the permanent system logs.
