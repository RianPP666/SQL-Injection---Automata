"""
Semantic Analyzer untuk Mini-IDS (2 Pola)
==========================================
Analisis semantik untuk Boolean-based dan Comment-based.
"""

from typing import List, Dict, Any
from dataclasses import dataclass, field


@dataclass 
class SemanticIssue:
    """Issue yang ditemukan saat analisis."""
    level: str       # 'INFO', 'WARNING', 'ERROR'
    message: str
    severity: str = 'MEDIUM'


class SymbolTable:
    """Tabel simbol untuk menyimpan informasi."""
    
    def __init__(self):
        self.symbols: Dict[str, Any] = {}
    
    def add(self, name: str, value: Any):
        self.symbols[name] = value
    
    def get(self, name: str) -> Any:
        return self.symbols.get(name)


class SemanticAnalyzer:
    """
    Semantic Analyzer untuk SQL Injection.
    
    Melakukan:
    1. Validasi struktur AST
    2. Klasifikasi severity
    3. Risk assessment
    4. Recommendation generation
    """
    
    def __init__(self):
        self.symbol_table = SymbolTable()
        self.issues: List[SemanticIssue] = []
    
    def analyze(self, ast) -> dict:
        """
        Analisis AST dan hasilkan laporan.
        
        Returns:
            dict dengan issues, risk, recommendations
        """
        self.issues = []
        self.symbol_table = SymbolTable()
        
        # Kunjungi semua node
        self._visit(ast)
        
        return {
            'issues': [{'level': i.level, 'message': i.message, 'severity': i.severity} 
                      for i in self.issues],
            'risk': self._calculate_risk(),
            'recommendations': self._get_recommendations()
        }
    
    def _visit(self, node):
        """Kunjungi node dan children-nya."""
        if node.node_type == 'PAYLOAD':
            self._analyze_payload(node)
        elif node.node_type == 'SQL_INJECTION':
            self._analyze_injection(node)
        elif node.node_type == 'SAFE':
            self._analyze_safe(node)
        
        for child in node.children:
            self._visit(child)
    
    def _analyze_payload(self, node):
        """Analisis payload node."""
        self.symbol_table.add('is_malicious', node.is_malicious)
        
        if node.is_malicious:
            self.issues.append(SemanticIssue(
                'WARNING',
                f'Payload berbahaya terdeteksi: {node.attack_type}',
                'HIGH'
            ))
    
    def _analyze_injection(self, node):
        """Analisis SQL Injection node."""
        inj_type = node.injection_type
        
        self.issues.append(SemanticIssue(
            'ERROR',
            f'SQL Injection ({inj_type}) terdeteksi',
            'HIGH'
        ))
        
        # Tambah ke symbol table
        self.symbol_table.add('attack_type', inj_type)
        self.symbol_table.add('pattern', node.value)
    
    def _analyze_safe(self, node):
        """Analisis safe node."""
        self.issues.append(SemanticIssue(
            'INFO',
            'Input aman, tidak ada serangan terdeteksi',
            'LOW'
        ))
    
    def _calculate_risk(self) -> dict:
        """Hitung level risiko."""
        error_count = sum(1 for i in self.issues if i.level == 'ERROR')
        
        if error_count > 0:
            return {'level': 'HIGH', 'score': 8, 'action': 'BLOCK'}
        return {'level': 'LOW', 'score': 1, 'action': 'ALLOW'}
    
    def _get_recommendations(self) -> List[str]:
        """Generate rekomendasi keamanan."""
        recs = []
        
        if any(i.level == 'ERROR' for i in self.issues):
            recs.append("Gunakan parameterized queries / prepared statements")
            recs.append("Validasi dan sanitasi semua input pengguna")
            recs.append("Terapkan prinsip least privilege pada database")
        
        return recs


# ============ TEST ============
if __name__ == "__main__":
    from lexer import Lexer
    from parser import Parser
    
    print("=" * 50)
    print("SEMANTIC ANALYZER TEST (2 Pola)")
    print("=" * 50)
    
    analyzer = SemanticAnalyzer()
    
    for inp in ["username=admin", "id=1' OR '1'='1", "admin'--"]:
        print(f"\nInput: {inp}")
        tokens = Lexer(inp).tokenize()
        ast = Parser(tokens).parse()
        result = analyzer.analyze(ast)
        
        print(f"  Risk: {result['risk']['level']} (Score: {result['risk']['score']})")
        print(f"  Action: {result['risk']['action']}")
        for issue in result['issues']:
            print(f"  [{issue['level']}] {issue['message']}")
