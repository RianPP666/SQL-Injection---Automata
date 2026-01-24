"""Quick test for SQL Injection detection"""
from lexer import Lexer
from parser import Parser
from automata import DFASimulator

payloads = [
    "username=admin",
    "id=1' OR '1'='1",
    "UNION SELECT * FROM users",
    "admin'--",
    "; DROP TABLE users",
]

print("Mini-IDS Quick Test (SQL Injection)")
print("=" * 40)

dfa = DFASimulator()

for p in payloads:
    print(f"\nPayload: {p}")
    sql = dfa.check_sql_injection(p)
    if sql['detected']:
        print(f"  SQL INJECTION: {sql['type']} ({sql['severity']})")
    else:
        print("  CLEAN")

print("\n" + "=" * 40)
print("TEST COMPLETED!")
