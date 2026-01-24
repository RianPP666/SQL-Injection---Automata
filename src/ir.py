"""
IR (Intermediate Representation) untuk Mini-IDS (2 Pola)
=========================================================
"""

from typing import List, Any
from dataclasses import dataclass
from enum import Enum, auto


class Opcode(Enum):
    """Opcode untuk IR instructions."""
    LOAD = auto()      # Load payload
    CHECK = auto()     # Check pattern
    BLOCK = auto()     # Block request
    ALERT = auto()     # Generate alert
    ALLOW = auto()     # Allow request
    LOG = auto()       # Log event
    HALT = auto()      # End program


@dataclass
class Instruction:
    """Satu instruksi IR."""
    opcode: Opcode
    arg1: Any = None
    arg2: Any = None
    
    def __repr__(self):
        parts = [self.opcode.name]
        if self.arg1: parts.append(str(self.arg1))
        if self.arg2: parts.append(str(self.arg2))
        return ' '.join(parts)


class IRProgram:
    """Program IR (kumpulan instruksi)."""
    
    def __init__(self):
        self.instructions: List[Instruction] = []
    
    def emit(self, opcode: Opcode, arg1=None, arg2=None):
        """Tambah instruksi."""
        self.instructions.append(Instruction(opcode, arg1, arg2))
    
    def __repr__(self):
        lines = ["IR Program:", "-" * 30]
        for i, inst in enumerate(self.instructions):
            lines.append(f"  {i}: {inst}")
        return '\n'.join(lines)


class IRGenerator:
    """Generate IR dari AST."""
    
    def generate(self, ast) -> IRProgram:
        """Generate IR program dari AST."""
        program = IRProgram()
        
        # Load payload
        program.emit(Opcode.LOAD, "payload")
        
        # Generate berdasarkan AST
        self._gen_node(ast, program)
        
        # End
        program.emit(Opcode.HALT)
        
        return program
    
    def _gen_node(self, node, program: IRProgram):
        """Generate IR untuk satu node."""
        if node.node_type == 'SQL_INJECTION':
            program.emit(Opcode.CHECK, node.injection_type, node.value)
            program.emit(Opcode.BLOCK, node.injection_type)
            program.emit(Opcode.LOG, "DETECTED", node.injection_type)
        elif node.node_type == 'SAFE':
            program.emit(Opcode.ALLOW)
        
        for child in node.children:
            self._gen_node(child, program)


class IRInterpreter:
    """Interpreter untuk menjalankan IR."""
    
    def execute(self, program: IRProgram) -> dict:
        """Jalankan IR program."""
        output = []
        action = None
        
        for inst in program.instructions:
            if inst.opcode == Opcode.BLOCK:
                action = 'BLOCK'
                output.append(f"🚨 BLOCK: {inst.arg1}")
            elif inst.opcode == Opcode.ALLOW:
                action = 'ALLOW'
                output.append("✅ ALLOW")
            elif inst.opcode == Opcode.LOG:
                output.append(f"📝 LOG: {inst.arg1} - {inst.arg2}")
            elif inst.opcode == Opcode.HALT:
                break
        
        return {'action': action, 'output': output}


# ============ TEST ============
if __name__ == "__main__":
    from lexer import Lexer
    from parser import Parser
    
    print("=" * 50)
    print("IR TEST (2 Pola)")
    print("=" * 50)
    
    gen = IRGenerator()
    interp = IRInterpreter()
    
    for inp in ["username=admin", "id=1' OR '1'='1"]:
        print(f"\nInput: {inp}")
        ast = Parser(Lexer(inp).tokenize()).parse()
        ir = gen.generate(ast)
        print(ir)
        result = interp.execute(ir)
        print(f"Action: {result['action']}")
