"""
Mini-IDS: SQL Injection Detection System (2 Pola)
==================================================
Mendeteksi: Boolean-based dan Comment-based SQL Injection

Komponen:
- Lexer: Tokenisasi input
- Parser: Recursive descent parser
- Automata: DFA/NFA simulation
- Semantic: Analisis semantik
- IR: Intermediate representation
- Interpreter: DSL interpreter
"""

from lexer import Lexer
from parser import Parser
from automata import DFASimulator
from semantic import SemanticAnalyzer
from ir import IRGenerator, IRInterpreter
from interpreter import DSLInterpreter
import argparse


def print_banner():
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║              MINI-IDS v2.0 (Simplified)               ║
    ║        SQL Injection Detection System                 ║
    ║                                                        ║
    ║  Pola: Boolean-based | Comment-based                  ║
    ╚════════════════════════════════════════════════════════╝
    """)


def analyze(payload: str, verbose: bool = False) -> dict:
    """
    Analisis payload untuk SQL Injection.
    
    Pipeline: Input → Lexer → Parser → AST → Semantic → Result
    """
    result = {
        'payload': payload,
        'detected': False,
        'type': None,
        'action': 'ALLOW'
    }
    
    # 1. Lexical Analysis
    if verbose:
        print("\n[1] LEXICAL ANALYSIS")
        print("-" * 40)
    
    lexer = Lexer(payload)
    tokens = lexer.tokenize()
    
    if verbose:
        print(f"Tokens: {len(tokens)}")
        for t in tokens:
            if t.type.name != 'EOF':
                print(f"  {t}")
    
    # 2. Syntax Analysis (Parsing)
    if verbose:
        print("\n[2] SYNTAX ANALYSIS")
        print("-" * 40)
    
    parser = Parser(tokens)
    ast = parser.parse()
    
    if verbose:
        print("AST:")
        ast.print_tree()
    
    # 3. DFA Check
    if verbose:
        print("\n[3] DFA SIMULATION")
        print("-" * 40)
    
    dfa = DFASimulator()
    dfa_result = dfa.check_sql_injection(payload)
    
    if verbose:
        print(f"DFA Result: {dfa_result}")
    
    # 4. Result
    if dfa_result['detected']:
        result['detected'] = True
        result['type'] = dfa_result['type']
        result['action'] = 'BLOCK'
    
    return result


def print_result(result: dict):
    """Print hasil analisis."""
    print("\n" + "=" * 50)
    print("HASIL ANALISIS")
    print("=" * 50)
    print(f"Payload: {result['payload']}")
    print("-" * 50)
    
    if result['detected']:
        print("⚠️  STATUS: BERBAHAYA")
        print(f"🔍 TIPE: {result['type']}")
        print(f"🚨 AKSI: {result['action']}")
    else:
        print("✅ STATUS: AMAN")
        print("✅ AKSI: ALLOW")
    
    print("=" * 50)


def run_tests():
    """Jalankan 5 test cases."""
    test_cases = [
        ("username=admin&password=123", "CLEAN"),
        ("id=1' OR '1'='1", "BOOLEAN_BASED"),
        ("id=1' OR 1=1", "BOOLEAN_BASED"),
        ("admin'--", "COMMENT_BASED"),
        ("user'#", "COMMENT_BASED"),
    ]
    
    print("\n" + "=" * 50)
    print("MENJALANKAN 5 TEST CASES")
    print("=" * 50)
    
    passed = 0
    
    for i, (payload, expected) in enumerate(test_cases, 1):
        result = analyze(payload)
        
        actual = result['type'] if result['detected'] else 'CLEAN'
        status = "✅ PASS" if actual == expected else "❌ FAIL"
        
        if actual == expected:
            passed += 1
        
        print(f"\nTest {i}: {payload}")
        print(f"  Expected: {expected}")
        print(f"  Actual: {actual}")
        print(f"  {status}")
    
    print("\n" + "=" * 50)
    print(f"HASIL: {passed}/5 test cases passed")
    print("=" * 50)


def interactive_mode():
    """Mode interaktif."""
    print("\n📝 Mode Interaktif")
    print("Ketik 'exit' untuk keluar\n")
    
    while True:
        try:
            payload = input("> Masukkan payload: ").strip()
            if payload.lower() == 'exit':
                print("Bye!")
                break
            if payload:
                result = analyze(payload, verbose=True)
                print_result(result)
        except KeyboardInterrupt:
            break


def main():
    parser = argparse.ArgumentParser(
        description='Mini-IDS: SQL Injection Detection (2 Pola)'
    )
    parser.add_argument('-t', '--test', action='store_true', 
                       help='Jalankan test cases')
    parser.add_argument('-i', '--interactive', action='store_true',
                       help='Mode interaktif')
    parser.add_argument('-p', '--payload', type=str,
                       help='Analisis satu payload')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Output detail')
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.test:
        run_tests()
    elif args.interactive:
        interactive_mode()
    elif args.payload:
        result = analyze(args.payload, args.verbose)
        print_result(result)
    else:
        run_tests()


if __name__ == "__main__":
    main()
