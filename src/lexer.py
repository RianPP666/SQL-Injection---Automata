"""
Lexer untuk Mini-IDS (2 Pola SQL Injection)
============================================
DFA-based tokenizer untuk Boolean-based dan Comment-based SQL Injection.
"""

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional


class TokenType(Enum):
    """Token types untuk SQL Injection detection."""
    # SQL Tokens
    SQL_KEYWORD = auto()      # OR, AND, SELECT, etc.
    SQL_QUOTE = auto()        # ' atau "
    SQL_COMMENT = auto()      # -- atau #
    SQL_OPERATOR = auto()     # =, <, >, etc.
    ALWAYS_TRUE = auto()      # '1'='1' atau 1=1
    
    # General Tokens
    IDENTIFIER = auto()       # nama variabel
    NUMBER = auto()           # angka
    STRING = auto()           # string dalam quotes
    WHITESPACE = auto()       # spasi
    SPECIAL_CHAR = auto()     # karakter khusus
    UNKNOWN = auto()          # tidak dikenal
    EOF = auto()              # akhir input


@dataclass
class Token:
    """Representasi sebuah token."""
    type: TokenType
    value: str
    position: int
    
    def __repr__(self):
        return f"Token({self.type.name}, '{self.value}')"


class Lexer:
    """
    DFA-based Lexical Analyzer untuk SQL Injection.
    
    Mengubah input string menjadi stream of tokens
    yang akan diproses oleh parser.
    """
    
    # Pattern-pattern token (urutan penting!)
    TOKEN_PATTERNS = [
        # SQL Keywords
        (TokenType.SQL_KEYWORD, r'\b(OR|AND|SELECT|FROM|WHERE)\b'),
        
        # Always True conditions
        (TokenType.ALWAYS_TRUE, r"('1'\s*=\s*'1'|1\s*=\s*1)"),
        
        # SQL Comments (-- atau #)
        (TokenType.SQL_COMMENT, r'(--|#)'),
        
        # SQL Quote
        (TokenType.SQL_QUOTE, r"['\"]"),
        
        # SQL Operator
        (TokenType.SQL_OPERATOR, r'(=|<|>)'),
        
        # Number
        (TokenType.NUMBER, r'\b\d+\b'),
        
        # Identifier
        (TokenType.IDENTIFIER, r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'),
        
        # Whitespace
        (TokenType.WHITESPACE, r'\s+'),
        
        # Special characters
        (TokenType.SPECIAL_CHAR, r'[&?+\-*/%,.]'),
    ]
    
    def __init__(self, input_text: str):
        """Inisialisasi lexer dengan input text."""
        self.input = input_text
        self.position = 0
        self.tokens: List[Token] = []
        
        # Compile regex patterns
        self.compiled_patterns = [
            (tt, re.compile(p, re.IGNORECASE)) 
            for tt, p in self.TOKEN_PATTERNS
        ]
    
    def tokenize(self) -> List[Token]:
        """
        Proses tokenisasi menggunakan DFA.
        
        Returns:
            List of Token
        """
        self.tokens = []
        self.position = 0
        
        while self.position < len(self.input):
            token = self._match_token()
            
            if token:
                # Skip whitespace
                if token.type != TokenType.WHITESPACE:
                    self.tokens.append(token)
            else:
                # Unknown character
                self.tokens.append(Token(
                    TokenType.UNKNOWN, 
                    self.input[self.position], 
                    self.position
                ))
                self.position += 1
        
        # Add EOF
        self.tokens.append(Token(TokenType.EOF, '', self.position))
        return self.tokens
    
    def _match_token(self) -> Optional[Token]:
        """Match satu token dari posisi saat ini."""
        remaining = self.input[self.position:]
        
        for token_type, pattern in self.compiled_patterns:
            match = pattern.match(remaining)
            if match:
                value = match.group(0)
                token = Token(token_type, value, self.position)
                self.position += len(value)
                return token
        
        return None
    
    def get_token_summary(self) -> dict:
        """Ringkasan token yang ditemukan."""
        summary = {}
        for token in self.tokens:
            name = token.type.name
            summary[name] = summary.get(name, 0) + 1
        return summary


# ============ TEST ============
if __name__ == "__main__":
    test_inputs = [
        "username=admin",
        "id=1' OR '1'='1",
        "admin'--",
    ]
    
    print("=" * 50)
    print("LEXER TEST (2 Pola)")
    print("=" * 50)
    
    for inp in test_inputs:
        print(f"\nInput: {inp}")
        lexer = Lexer(inp)
        tokens = lexer.tokenize()
        for t in tokens:
            if t.type != TokenType.EOF:
                print(f"  {t}")
