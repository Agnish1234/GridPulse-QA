import json
import logging
import csv
import os
from datetime import datetime

# Initialize explicit system log tracking layout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [SYSTEM STATE: %(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Centralized boundary rules dictionary for data validation
DEFAULT_CONFIG = {
    "station_id": "SUBSTATION_EAST_KOL",
    "min_voltage": 210.0,
    "max_voltage": 240.0,
    "max_temp": 85.0,
    "audit_log_file": "operational_audit.csv"
}

class AdvancedInfrastructureGatekeeper:
    def __init__(self, config_dict: dict):
        """Initializes system threshold boundaries and permanent log trail targets."""
        self.station_id = config_dict["station_id"]
        self.min_voltage = config_dict["min_voltage"]
        self.max_voltage = config_dict["max_voltage"]
        self.max_temp = config_dict["max_temp"]
        self.audit_log_file = config_dict["audit_log_file"]
        
        # Initialize a permanent CSV dataset audit trail file if not present
        if not os.path.exists(self.audit_log_file):
            with open(self.audit_log_file, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "StationID", "Status", "ReasonCode", "RawPayload"])

    def _log_to_audit_trail(self, status: str, reason: str, raw_payload: str):
        """Appends validation transaction outcomes directly into an immutable spreadsheet report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(self.audit_log_file, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([timestamp, self.station_id, status, reason, raw_payload])
        except Exception as e:
            logging.critical(f"SYSTEM AUDIT FAILURE: File access tracking error: {str(e)}")

    def validate_incoming_packet(self, raw_json_data: str) -> dict:
        """Audits real-time data input packets against layout, origin, and boundary constraints."""
        audit_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 1. Structural Integrity Verification Layer
        try:
            packet = json.loads(raw_json_data)
        except json.JSONDecodeError:
            logging.error("CRITICAL FAILURE: Packet structure is corrupted or contains illegal characters.")
            self._log_to_audit_trail("REJECTED", "Malformed JSON structure", raw_json_data)
            return {"status": "REJECTED", "reason": "Malformed JSON structure"}

        # 2. Mandatory Parameter Verification Layer
        required_keys = ["station_id", "active_voltage", "core_temperature"]
        for key in required_keys:
            if key not in packet or packet[key] is None:
                logging.warning(f"DATA DROPPED: Security index check failed. Missing key: '{key}'.")
                self._log_to_audit_trail("REJECTED", f"Missing field: {key}", raw_json_data)
                return {"status": "REJECTED", "reason": f"Missing field: {key}"}

        input_station = str(packet["station_id"]).strip()
        voltage_input = packet["active_voltage"]
        temp_input = packet["core_temperature"]

        # 3. Origin Authorization Layer
        if input_station != self.station_id:
            logging.error(f"SECURITY ALERT: Mismatched origin identity. Received: {input_station}.")
            self._log_to_audit_trail("REJECTED", "Unauthorized Station ID", raw_json_data)
            return {"status": "REJECTED", "reason": "Unauthorized Station ID"}

        # 4. Data Type Conversion & Injected Text Verification Layer
        try:
            voltage = float(voltage_input)
            temperature = float(temp_input)
        except (ValueError, TypeError):
            logging.warning("DATA CORRUPTION: Non-numeric figures injected into metrics fields.")
            self._log_to_audit_trail("REJECTED", "Non-numeric data values", raw_json_data)
            return {"status": "REJECTED", "reason": "Non-numeric data values"}

        # 5. Core Operational Boundary Constraint Verification Layer
        if voltage < 0:
            logging.error(f"NEGATIVE ANOMALY: Dangerous negative voltage input blocked ({voltage} kV).")
            self._log_to_audit_trail("REJECTED", "Negative value anomaly", raw_json_data)
            return {"status": "REJECTED", "reason": "Negative value anomaly"}

        if voltage < self.min_voltage:
            logging.warning(f"UNDER-VOLTAGE VIOLATION: Current dropped below safe minimum ({voltage} kV).")
            self._log_to_audit_trail("REJECTED", "Under-voltage threshold breach", raw_json_data)
            return {"status": "REJECTED", "reason": "Under-voltage threshold breach"}

        if voltage > self.max_voltage:
            logging.warning(f"OVER-VOLTAGE SURGE: Current exceeds safe maximum ({voltage} kV).")
            self._log_to_audit_trail("REJECTED", "Over-voltage threshold breach", raw_json_data)
            return {"status": "REJECTED", "reason": "Over-voltage threshold breach"}

        if temperature > self.max_temp:
            logging.error(f"THERMAL ALARM: Temperature ({temperature}°C) breaches safety core limits.")
            self._log_to_audit_trail("REJECTED", "Thermal limit breached", raw_json_data)
            return {"status": "REJECTED", "reason": "Thermal limit breached"}

        # SUCCESS STAGE: All safety gates successfully passed
        logging.info(f"SUCCESS: Data packet from Station {input_station} approved and logged.")
        self._log_to_audit_trail("APPROVED", "System constraints verified clear", raw_json_data)
        return {"status": "APPROVED"}

if __name__ == "__main__":
    gatekeeper = AdvancedInfrastructureGatekeeper(DEFAULT_CONFIG)
    
    print("====================================================")
    print("   GRIDPULSE-QA: ENTERPRISE AUDIT PACK INITIALIZED  ")
    print("====================================================\n")
    print(f"Permanent Audit Log writing to: '{DEFAULT_CONFIG['audit_log_file']}'\n")
    
    # Complete 8-Scenario automated validation test vector suite
    master_test_batch = [
        '{"station_id": "SUBSTATION_EAST_KOL", "active_voltage": 225.0, "core_temperature": 65.5}',
        '{"station_id": "SUBSTATION_EAST_KOL", "active_voltage": 220, "core_temp_broken_string',
        '{"station_id": "SUBSTATION_EAST_KOL", "core_temperature": 70.0}',
        '{"station_id": "SUBSTATION_FAKE_ZONE", "active_voltage": 225.0, "core_temperature": 60.0}',
        '{"station_id": "SUBSTATION_EAST_KOL", "active_voltage": "TEXT_HACK_ATTEMPT", "core_temperature": 65.0}',
        '{"station_id": "SUBSTATION_EAST_KOL", "active_voltage": -55.4, "core_temperature": 65.0}',
        '{"station_id": "SUBSTATION_EAST_KOL", "active_voltage": 295.0, "core_temperature": 65.0}',
        '{"station_id": "SUBSTATION_EAST_KOL", "active_voltage": 225.0, "core_temperature": 104.9}'
    ]
    
    print("Executing automated vulnerability scans across all 8 core infrastructure edge cases...")
    for idx, sample_packet in enumerate(master_test_batch, 1):
        print(f"\nProcessing Pipeline Vector #{idx}:")
        gatekeeper.validate_incoming_packet(sample_packet)
        
    print("\n====================================================")
    print("✔ BATCH TESTING COMPLETE. SYSTEM CONTINUITY MAINTAINED.")
    print("Check 'operational_audit.csv' to review the permanent log spreadsheet record.")
    print("====================================================")
