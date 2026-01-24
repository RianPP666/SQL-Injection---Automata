"""
Automata (DFA/NFA) untuk Mini-IDS (2 Pola SQL Injection)
========================================================
Simulasi DFA untuk Boolean-based dan Comment-based.
"""

import re
from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class State:
    """Representasi state dalam DFA."""
    name: str
    is_accepting: bool = False
    is_start: bool = False


class DFA:
    """
    Deterministic Finite Automaton.
    
    Komponen DFA:
    - Q: Himpunan state
    - Σ: Alfabet (simbol input)
    - δ: Fungsi transisi
    - q0: State awal
    - F: Himpunan state akhir
    """
    
    def __init__(self, name: str = "DFA"):
        self.name = name
        self.states: Dict[str, State] = {}
        self.transitions: Dict[Tuple[str, str], str] = {}
        self.start_state: str = None
        self.accepting_states: set = set()
        self.current_state: str = None
    
    def add_state(self, name: str, is_accepting: bool = False, is_start: bool = False):
        """Tambah state ke DFA."""
        self.states[name] = State(name, is_accepting, is_start)
        if is_accepting:
            self.accepting_states.add(name)
        if is_start:
            self.start_state = name
            self.current_state = name
    
    def add_transition(self, from_state: str, symbol: str, to_state: str):
        """Tambah transisi: δ(from_state, symbol) = to_state"""
        self.transitions[(from_state, symbol)] = to_state
    
    def reset(self):
        """Reset ke state awal."""
        self.current_state = self.start_state
    
    def step(self, symbol: str) -> bool:
        """Jalankan satu langkah transisi."""
        key = (self.current_state, symbol)
        if key in self.transitions:
            self.current_state = self.transitions[key]
            return True
        return False
    
    def is_accepting(self) -> bool:
        """Cek apakah di state accept."""
        return self.current_state in self.accepting_states


class DFASimulator:
    """
    Simulator DFA untuk deteksi SQL Injection.
    
    Mendeteksi 2 pola:
    1. Boolean-based: ' OR '1'='1
    2. Comment-based: admin'--
    """
    
    # Pattern regex untuk deteksi (NFA behavior)
    SQL_PATTERNS = [
        # Boolean-based patterns
        (r"'\s*(OR|AND)\s*'", 'BOOLEAN_BASED', 'HIGH'),
        (r"(OR|AND)\s+1\s*=\s*1", 'BOOLEAN_BASED', 'HIGH'),
        (r"'1'\s*=\s*'1'", 'BOOLEAN_BASED', 'HIGH'),
        
        # Comment-based patterns
        (r"'--", 'COMMENT_BASED', 'HIGH'),
        (r"'#", 'COMMENT_BASED', 'HIGH'),
    ]
    
    def __init__(self):
        # Build DFA untuk demo
        self.boolean_dfa = self._build_boolean_dfa()
        self.comment_dfa = self._build_comment_dfa()
    
    def _build_boolean_dfa(self) -> DFA:
        """
        DFA untuk Boolean-based: ' OR '1'='1
        
        States: q0 (start) → q1 (') → q2 (OR) → q3 (accept)
        """
        dfa = DFA("Boolean_DFA")
        
        # Tambah states
        dfa.add_state("q0", is_start=True)   # Start
        dfa.add_state("q1")                   # Setelah '
        dfa.add_state("q2")                   # Setelah OR
        dfa.add_state("q3", is_accepting=True) # Accept
        
        # Tambah transisi
        dfa.add_transition("q0", "'", "q1")
        dfa.add_transition("q1", "OR", "q2")
        dfa.add_transition("q2", "'", "q3")
        
        return dfa
    
    def _build_comment_dfa(self) -> DFA:
        """
        DFA untuk Comment-based: '--
        
        States: q0 (start) → q1 (') → q2 (--) → q3 (accept)
        """
        dfa = DFA("Comment_DFA")
        
        # Tambah states
        dfa.add_state("q0", is_start=True)
        dfa.add_state("q1")
        dfa.add_state("q2", is_accepting=True)
        
        # Tambah transisi
        dfa.add_transition("q0", "'", "q1")
        dfa.add_transition("q1", "--", "q2")
        dfa.add_transition("q1", "#", "q2")
        
        return dfa
    
    def check_sql_injection(self, payload: str) -> dict:
        """
        Cek payload untuk SQL Injection menggunakan regex (NFA).
        
        Returns:
            dict dengan detected, type, severity, pattern
        """
        result = {
            'detected': False,
            'type': None,
            'severity': None,
            'pattern': None
        }
        
        for pattern, attack_type, severity in self.SQL_PATTERNS:
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                result['detected'] = True
                result['type'] = attack_type
                result['severity'] = severity
                result['pattern'] = match.group()
                break
        
        return result
    
    def simulate_dfa(self, payload: str, dfa_type: str = 'boolean') -> dict:
        """
        Simulasi DFA step-by-step.
        
        Args:
            payload: Input string
            dfa_type: 'boolean' atau 'comment'
        
        Returns:
            dict dengan trace states
        """
        dfa = self.boolean_dfa if dfa_type == 'boolean' else self.comment_dfa
        dfa.reset()
        
        trace = [dfa.current_state]
        
        for char in payload:
            dfa.step(char)
            trace.append(dfa.current_state)
        
        return {
            'dfa_name': dfa.name,
            'accepted': dfa.is_accepting(),
            'final_state': dfa.current_state,
            'trace': trace
        }
    
    def print_dfa_definition(self):
        """Print definisi formal DFA."""
        for name, dfa in [('Boolean', self.boolean_dfa), ('Comment', self.comment_dfa)]:
            print(f"\n{name} DFA:")
            print(f"  Q = {set(dfa.states.keys())}")
            print(f"  q0 = {dfa.start_state}")
            print(f"  F = {dfa.accepting_states}")
            print(f"  δ (transitions):")
            for (s, sym), t in dfa.transitions.items():
                print(f"    δ({s}, '{sym}') = {t}")


# ============ TEST ============
if __name__ == "__main__":
    sim = DFASimulator()
    
    print("=" * 50)
    print("DFA SIMULATOR TEST (2 Pola)")
    print("=" * 50)
    
    # Print DFA definitions
    sim.print_dfa_definition()
    
    # Test payloads
    payloads = [
        "username=admin",
        "id=1' OR '1'='1",
        "id=1' OR 1=1",
        "admin'--",
        "user'#",
    ]
    
    print("\n" + "=" * 50)
    print("DETECTION TEST")
    print("=" * 50)
    
    for p in payloads:
        result = sim.check_sql_injection(p)
        status = "🚨 DETECTED" if result['detected'] else "✅ CLEAN"
        print(f"\n{p}")
        print(f"  {status}")
        if result['detected']:
            print(f"  Type: {result['type']}, Severity: {result['severity']}")
