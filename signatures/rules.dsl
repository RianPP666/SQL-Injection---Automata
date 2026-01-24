# SQL Injection Signatures

SIGNATURE sql_union
    PATTERN: "UNION\s+(ALL\s+)?SELECT"
    SEVERITY: CRITICAL
    RESPONSE: BLOCK
    MESSAGE: "SQL Injection (UNION-based)"

SIGNATURE sql_boolean
    PATTERN: "(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?"
    SEVERITY: HIGH
    RESPONSE: BLOCK
    MESSAGE: "SQL Injection (Boolean-based)"

SIGNATURE sql_quote_boolean
    PATTERN: "'\s*(OR|AND)\s*'"
    SEVERITY: HIGH
    RESPONSE: BLOCK
    MESSAGE: "SQL Injection (Quote-based)"

SIGNATURE sql_comment
    PATTERN: "(--|#|/\*)"
    SEVERITY: HIGH
    RESPONSE: ALERT
    MESSAGE: "SQL Comment injection"

SIGNATURE sql_drop
    PATTERN: "DROP\s+(TABLE|DATABASE)"
    SEVERITY: CRITICAL
    RESPONSE: BLOCK
    MESSAGE: "DROP statement detected"

SIGNATURE sql_stacked
    PATTERN: ";\s*(SELECT|INSERT|UPDATE|DELETE|DROP)"
    SEVERITY: CRITICAL
    RESPONSE: BLOCK
    MESSAGE: "Stacked query detected"

SIGNATURE sql_truncate
    PATTERN: "TRUNCATE\s+TABLE"
    SEVERITY: CRITICAL
    RESPONSE: BLOCK
    MESSAGE: "TRUNCATE statement detected"
