from dataclasses import dataclass


@dataclass
class CpgScanResult:
    executable_name: str
    vulnerability_severity: float
    vulnerable_line_number: int
    vulnerable_function: str
    vulnerability_description: str
