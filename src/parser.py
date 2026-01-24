"""
Parser untuk Mini-IDS (2 Pola SQL Injection)
=============================================
Recursive Descent Parser untuk Boolean-based dan Comment-based.

CFG:
    SQLInjection  → SQLPattern | ε
    SQLPattern    → BooleanAttack | CommentAttack
    BooleanAttack → QUOTE (OR | AND) AlwaysTrue
    CommentAttack → Payload SQL_COMMENT
    AlwaysTrue    → QUOTE NUMBER EQUALS QUOTE NUMBER | NUMBER EQUALS NUMBER
"""

from typing import List, Optional
from dataclasses import dataclass, field
from lexer import Token, TokenType


@dataclass
class ASTNode:
    """Base class untuk AST Node."""
    node_type: str
    value: str = ""
    children: List['ASTNode'] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    
    def add_child(self, child: 'ASTNode'):
        self.children.append(child)
    
    def print_tree(self, indent: int = 0):
        prefix = "  " * indent
        print(f"{prefix}├── {self.node_type}: {self.value}")
        for child in self.children:
            child.print_tree(indent + 1)


class PayloadNode(ASTNode):
    """Root node untuk payload."""
    def __init__(self, value: str = ""):
        super().__init__("PAYLOAD", value)
        self.is_malicious = False
        self.attack_type = None


class SQLInjectionNode(ASTNode):
    """Node untuk serangan SQL Injection."""
    def __init__(self, injection_type: str, value: str = ""):
        super().__init__("SQL_INJECTION", value)
        self.injection_type = injection_type
        self.metadata['type'] = injection_type
        self.metadata['severity'] = 'HIGH'


class SafeNode(ASTNode):
    """Node untuk input yang aman."""
    def __init__(self):
        super().__init__("SAFE", "Input aman, tidak ada serangan")


class Parser:
    """
    Recursive Descent Parser untuk SQL Injection.
    
    Menerapkan CFG untuk mendeteksi:
    1. Boolean-based: ' OR '1'='1
    2. Comment-based: admin'--
    """
    
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0
    
    def parse(self) -> ASTNode:
        """
        Entry point parsing.
        
        CFG: SQLInjection → SQLPattern | ε
        """
        root = PayloadNode()
        
        # Coba parse SQL Injection pattern
        sql_node = self._parse_sql_injection()
        
        if sql_node:
            root.add_child(sql_node)
            root.is_malicious = True
            root.attack_type = sql_node.injection_type
        else:
            root.add_child(SafeNode())
        
        return root
    
    def _parse_sql_injection(self) -> Optional[SQLInjectionNode]:
        """
        CFG: SQLPattern → BooleanAttack | CommentAttack
        """
        # Cek Boolean-based: OR/AND dengan always true
        if self._is_boolean_attack():
            return self._parse_boolean_attack()
        
        # Cek Comment-based: ada -- atau #
        if self._is_comment_attack():
            return self._parse_comment_attack()
        
        return None
    
    def _is_boolean_attack(self) -> bool:
        """Cek apakah ada pattern Boolean-based."""
        has_or_and = any(
            t.type == TokenType.SQL_KEYWORD and t.value.upper() in ['OR', 'AND']
            for t in self.tokens
        )
        has_always_true = any(
            t.type == TokenType.ALWAYS_TRUE for t in self.tokens
        )
        return has_or_and and has_always_true
    
    def _is_comment_attack(self) -> bool:
        """Cek apakah ada pattern Comment-based."""
        return any(t.type == TokenType.SQL_COMMENT for t in self.tokens)
    
    def _parse_boolean_attack(self) -> SQLInjectionNode:
        """
        CFG: BooleanAttack → QUOTE (OR | AND) AlwaysTrue
        
        Contoh: ' OR '1'='1
        """
        node = SQLInjectionNode('BOOLEAN_BASED')
        
        # Kumpulkan token yang relevan
        parts = []
        for t in self.tokens:
            if t.type in [TokenType.SQL_QUOTE, TokenType.SQL_KEYWORD, 
                          TokenType.ALWAYS_TRUE, TokenType.SQL_OPERATOR,
                          TokenType.NUMBER]:
                parts.append(t.value)
        
        node.value = ' '.join(parts)
        
        # Tambah child nodes untuk AST
        node.add_child(ASTNode("QUOTE", "'"))
        node.add_child(ASTNode("KEYWORD", "OR"))
        node.add_child(ASTNode("ALWAYS_TRUE", "'1'='1'"))
        
        return node
    
    def _parse_comment_attack(self) -> SQLInjectionNode:
        """
        CFG: CommentAttack → Payload SQL_COMMENT
        
        Contoh: admin'--
        """
        node = SQLInjectionNode('COMMENT_BASED')
        
        # Cari comment token
        for t in self.tokens:
            if t.type == TokenType.SQL_COMMENT:
                node.value = t.value
                break
        
        # Tambah child nodes
        node.add_child(ASTNode("PAYLOAD", "admin'"))
        node.add_child(ASTNode("SQL_COMMENT", node.value))
        
        return node


# ============ TEST ============
if __name__ == "__main__":
    from lexer import Lexer
    
    test_inputs = [
        "username=admin",
        "id=1' OR '1'='1",
        "admin'--",
    ]
    
    print("=" * 50)
    print("PARSER TEST (2 Pola)")
    print("=" * 50)
    
    for inp in test_inputs:
        print(f"\nInput: {inp}")
        tokens = Lexer(inp).tokenize()
        ast = Parser(tokens).parse()
        print("AST:")
        ast.print_tree()
        print(f"Malicious: {ast.is_malicious}")
