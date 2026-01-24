"""
DSL Interpreter untuk Mini-IDS (2 Pola)
========================================
"""

import re
from typing import List
from dataclasses import dataclass


@dataclass
class Signature:
    """Attack signature."""
    name: str
    pattern: str
    severity: str
    action: str
    message: str


class DSLInterpreter:
    """
    Interpreter untuk signature DSL.
    
    Format DSL:
    SIGNATURE name
        PATTERN: "regex"
        SEVERITY: HIGH/MEDIUM/LOW
        ACTION: BLOCK/ALERT
        MESSAGE: "description"
    """
    
    def __init__(self):
        self.signatures: List[Signature] = []
        self._load_default_signatures()
    
    def _load_default_signatures(self):
        """Load signatures bawaan untuk 2 pola."""
        self.signatures = [
            # Boolean-based
            Signature(
                name="boolean_sqli_1",
                pattern=r"'\s*(OR|AND)\s*'",
                severity="HIGH",
                action="BLOCK",
                message="SQL Injection (Boolean-based) terdeteksi"
            ),
            Signature(
                name="boolean_sqli_2", 
                pattern=r"(OR|AND)\s+1\s*=\s*1",
                severity="HIGH",
                action="BLOCK",
                message="SQL Injection (Boolean-based 1=1) terdeteksi"
            ),
            # Comment-based
            Signature(
                name="comment_sqli_1",
                pattern=r"'--",
                severity="HIGH",
                action="BLOCK",
                message="SQL Injection (Comment --) terdeteksi"
            ),
            Signature(
                name="comment_sqli_2",
                pattern=r"'#",
                severity="HIGH",
                action="BLOCK",
                message="SQL Injection (Comment #) terdeteksi"
            ),
        ]
    
    def check(self, payload: str) -> List[dict]:
        """
        Cek payload terhadap semua signatures.
        
        Returns:
            List of matched signatures
        """
        matches = []
        
        for sig in self.signatures:
            if re.search(sig.pattern, payload, re.IGNORECASE):
                matches.append({
                    'name': sig.name,
                    'severity': sig.severity,
                    'action': sig.action,
                    'message': sig.message
                })
        
        return matches
    
    def get_signatures(self) -> List[dict]:
        """Get semua signatures."""
        return [
            {'name': s.name, 'pattern': s.pattern, 'severity': s.severity}
            for s in self.signatures
        ]


# ============ TEST ============
if __name__ == "__main__":
    print("=" * 50)
    print("DSL INTERPRETER TEST (2 Pola)")
    print("=" * 50)
    
    interp = DSLInterpreter()
    
    # Show signatures
    print("\nLoaded Signatures:")
    for sig in interp.get_signatures():
        print(f"  - {sig['name']}: {sig['pattern']}")
    
    # Test
    payloads = [
        "username=admin",
        "id=1' OR '1'='1",
        "admin'--",
        "user'#",
    ]
    
    print("\nDetection Test:")
    for p in payloads:
        matches = interp.check(p)
        print(f"\n  {p}")
        if matches:
            for m in matches:
                print(f"    🚨 {m['message']}")
        else:
            print("    ✅ Clean")
