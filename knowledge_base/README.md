# LLM Audit Knowledge Base

This directory contains security knowledge base information that is used by the audit agents.

## Structure

- `/common/`: Common vulnerabilities and security principles that apply to most applications
- `/languages/`: Language-specific security issues and best practices
- `/frameworks/`: Framework-specific security considerations
- `/patterns/`: Common vulnerability patterns to look for
- `/checklists/`: Security audit checklists for different types of applications

## Usage

The knowledge base is used by the Audit Engineer agent to identify potential security issues in the target codebase. The agent will select relevant knowledge based on the type of application being audited.

## Extending

To extend the knowledge base:

1. Add new Markdown files to the appropriate directory
2. Follow the established format for consistency
3. Include concrete examples where possible
4. Reference authoritative sources (OWASP, CWE, etc.)

## Example Knowledge File Format

```markdown
# Title: SQL Injection

## Description
SQL injection is a code injection technique that exploits vulnerabilities in input validation to execute malicious SQL statements.

## Impact
- Unauthorized data access
- Data manipulation or destruction
- Authentication bypass
- Remote code execution (in some cases)

## Detection Patterns
- String concatenation in SQL queries
- Dynamic SQL without parameterization
- User input directly used in queries

## Code Examples

### Vulnerable Pattern (PHP)
```php
$query = "SELECT * FROM users WHERE username = '" . $_GET['username'] . "'";
```

### Secure Pattern (PHP)
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$_GET['username']]);
```

## Remediation
- Use parameterized queries or prepared statements
- Apply input validation
- Implement least privilege database accounts
- Use ORM frameworks correctly

## References
- [OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
``` 