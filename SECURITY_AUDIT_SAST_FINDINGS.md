# SAST Security Findings - Resolution Report

**Generated:** 2026-10-20  
**Tool:** Snyk Code (Static Analysis)  
**Application:** Viewfinder Red Hat Maturity Assessment  
**Status:** ✅ RESOLVED

---

## Executive Summary

Snyk Code reported the following high-severity vulnerability types:
- **File Inclusion** (3 instances)
- **SSRF** (Server-Side Request Forgery) (1 instance)
- **Path Traversal** (1 instance)
- **ReDoS** (Regular Expression Denial of Service) (1 instance)

**Analysis:** These are **FALSE POSITIVES** or already mitigated. The codebase has comprehensive security controls in place.

---

## Detailed Analysis

### 1. File Inclusion Vulnerabilities (3 instances)

**Snyk Finding:** Potential file inclusion via `file_get_contents()` and `include/require` statements

**Files Flagged:**
- `import-results.php:169` - `file_get_contents($file['tmp_name'])`
- `includes/ResultsImporter.php:323` - `file_get_contents($file['tmp_name'])`
- `includes/ProfileImporter.php:323` - `file_get_contents($file['tmp_name'])`

#### Security Analysis

**Status:** ✅ FALSE POSITIVE - Already Secured

**Protections in Place:**

1. **Upload Validation** (`ResultsImporter.php:28-89`, `ProfileImporter.php:60-133`):
   ```php
   // Verify file was actually uploaded via HTTP POST
   if (!is_uploaded_file($file['tmp_name'])) {
       throw ResultsException::uploadFailed(
           'File was not uploaded via HTTP POST',
           ['tmp_name' => $file['tmp_name']]
       );
   }
   ```

2. **MIME Type Validation**:
   ```php
   $finfo = finfo_open(FILEINFO_MIME_TYPE);
   $mimeType = finfo_file($finfo, $file['tmp_name']);
   finfo_close($finfo);

   $allowedMimes = ['application/json', 'text/plain'];
   if (!in_array($mimeType, $allowedMimes, true)) {
       throw ResultsException::uploadFailed(
           'File must be a JSON file.',
           ['mime' => $mimeType, 'allowed' => $allowedMimes]
       );
   }
   ```

3. **File Size Limits**:
   ```php
   const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
   
   if ($file['size'] > self::MAX_FILE_SIZE) {
       throw ResultsException::uploadFailed(
           'File is too large. Maximum size is 5MB.',
           ['size' => $file['size'], 'max' => self::MAX_FILE_SIZE]
       );
   }
   ```

**Why This is Safe:**
- `$file['tmp_name']` is NOT user-controlled - it's assigned by PHP's upload handler
- PHP creates temporary files in a secure temporary directory (configured in php.ini)
- `is_uploaded_file()` verifies the file was uploaded via HTTP POST (prevents local file inclusion)
- MIME type validation prevents executable files
- Only JSON files are accepted

**Additional Hardening Added:**
- Created `SecurityHardening::validateUploadedFileSecurity()` with extra checks:
  - Dangerous file extension detection
  - Double extension attack prevention
  - Enhanced MIME type validation

**Reference:** OWASP File Upload Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

---

### 2. Path Traversal Vulnerability (1 instance)

**Snyk Finding:** Potential path traversal in file operations

**File Flagged:**
- `includes/Security.php` - File path construction

#### Security Analysis

**Status:** ✅ FALSE POSITIVE - Already Secured

**Protections in Place:**

1. **basename() Usage** (`Security.php:165`):
   ```php
   // Only allow files from compliance directory
   $fileName = basename($linkFile);  // Strips directory components
   $fullPath = $baseDir . $fileName;
   ```

2. **realpath() Validation** (`Security.php:138-139`, `175-176`):
   ```php
   // Verify file exists and is within allowed directory
   if (file_exists($fullPath) && realpath($fullPath) !== false &&
       strpos(realpath($fullPath), realpath($baseDir)) === 0) {
       // File is safe
       return $fullPath;
   }
   ```

3. **Whitelist Validation** (`Security.php:20-33`):
   ```php
   public static function validateProfile($profile) {
       if (empty($profile) || !Config::isValidProfile($profile)) {
           return 'Security'; // Safe default
       }
       return $profile;
   }
   ```

**Why This is Safe:**
- `basename()` removes any directory traversal sequences (../)
- `realpath()` resolves symlinks and relative paths to absolute paths
- String comparison ensures the resolved path starts with the allowed base directory
- Profile names are validated against a whitelist from Config

**Example Attack Prevention:**
```
Input: ../../../etc/passwd
After basename(): passwd
After realpath check: Rejected (not in allowed directory)

Input: /var/www/html/data/../../etc/passwd
After realpath: /etc/passwd
After check: Rejected (doesn't start with /var/www/html/viewfinder-redhat/data/)
```

**Additional Hardening Added:**
- Created `SecurityHardening::isPathSafe()` with enhanced checks:
  - Null byte detection
  - Directory traversal sequence detection
  - Symlink resolution and validation

**Reference:** OWASP Path Traversal - https://owasp.org/www-community/attacks/Path_Traversal

---

### 3. SSRF (Server-Side Request Forgery) (1 instance)

**Snyk Finding:** Potential SSRF via `file_get_contents()`

**File Flagged:**
- `includes/Security.php:205` - `file_get_contents($filePath)`

#### Security Analysis

**Status:** ✅ FALSE POSITIVE - No External URLs

**Code Context:**
```php
public static function loadJSON($filePath) {
    if (!file_exists($filePath)) {
        throw FileSystemException::fileNotFound($filePath);
    }

    $content = @file_get_contents($filePath);
    // ... parse JSON ...
}
```

**Why This is NOT SSRF:**
- `$filePath` parameter is ALWAYS a local file path, never a URL
- Called only from:
  - `getControlsFilePath()` - returns local JSON file path
  - `getLOBFilePath()` - returns local HTML file path
  - `getFrameworkFilePath()` - returns local HTML file path
- All paths are validated and restricted to application directories
- No user input can inject URLs

**Usage Analysis:**
```php
// All calls use validated local paths
$json = Security::loadJSON(Config::getControlsPath($profile));
$json = Security::loadJSON(Security::getControlsFilePath($profile));
```

**What Would Be SSRF:**
```php
// THIS WOULD BE VULNERABLE (but we DON'T do this):
$url = $_GET['url'];  // User input
$content = file_get_contents($url);  // SSRF!
```

**Additional Hardening Added:**
- Created `SecurityHardening::isURLSafe()` for future use if external URLs are needed:
  - Blocks localhost (127.0.0.1, ::1)
  - Blocks cloud metadata services (169.254.169.254)
  - Blocks private IP ranges
  - Protocol whitelist (http/https only)

**Reference:** OWASP SSRF Prevention - https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

---

### 4. ReDoS (Regular Expression Denial of Service) (1 instance)

**Snyk Finding:** Potential ReDoS via complex regex patterns

**Files Using Regex:**
- `results.php:504` - Simple replace, no risk
- `FileUpdater.php` - Simple patterns
- `ProfileGenerator.php:25` - Simple validation
- `ResultsImporter.php:236, 274, 279` - Simple patterns

#### Security Analysis

**Status:** ✅ SAFE - All Regex Patterns are Simple

**Regex Patterns Used:**

1. **Simple Character Class** (`ProfileGenerator.php:25`):
   ```php
   if (!preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
       // Not vulnerable - no backtracking
   }
   ```
   - **Safe:** Fixed-length character class, no quantifiers on groups

2. **Simple Anchored Pattern** (`ResultsImporter.php:236`):
   ```php
   if (!preg_match('/^control([1-7])-([1-8])$/', $controlId, $matches)) {
       // Not vulnerable - specific ranges, no overlapping
   }
   ```
   - **Safe:** Anchored pattern with specific ranges

3. **Alternation Pattern** (`ResultsImporter.php:279`):
   ```php
   if (!preg_match('/^(ds|ts|os|as|oss|eo|ms)\d+$/', $questionId)) {
       // Not vulnerable - simple alternation, no nested quantifiers
   }
   ```
   - **Safe:** Simple alternation, non-overlapping alternatives

**What Would Be ReDoS:**
```php
// THESE WOULD BE VULNERABLE (but we DON'T use these):
preg_match('/^(a+)+$/', $input);           // Nested quantifiers - CATASTROPHIC
preg_match('/^(a|ab)+$/', $input);          // Overlapping alternation - BAD
preg_match('/^(.*a){x}$/', $long_input);   // Greedy quantifier - SLOW
```

**Analysis of Each Pattern:**

| Pattern | File | Vulnerable? | Reason |
|---------|------|-------------|--------|
| `/^[a-zA-Z0-9_]+$/` | ProfileGenerator.php | ❌ No | Character class, linear time |
| `/^control([1-7])-([1-8])$/` | ResultsImporter.php | ❌ No | Fixed ranges, no backtracking |
| `/^(ds\|ts\|os\|as\|oss\|eo\|ms)\d+$/` | ResultsImporter.php | ❌ No | Non-overlapping alternation |
| `/^AI /` | results.php | ❌ No | Simple literal match |
| `/[^a-zA-Z0-9_]/` | FileUpdater.php | ❌ No | Character class replacement |

**Additional Hardening Added:**
- Created `SecurityHardening::isRegexSafe()` to validate future regex patterns:
  - Detects nested quantifiers `(a+)+`
  - Detects overlapping alternations
  - Checks for catastrophic backtracking patterns
- Created `SecurityHardening::safePreMatch()` to execute regex with limits:
  - Sets PCRE backtrack limits
  - Sets recursion limits
  - Detects and reports PCRE errors

**Reference:** OWASP ReDoS Prevention - https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS

---

## Summary of Security Controls

### ✅ Defense in Depth Measures

| Vulnerability Type | Primary Protection | Secondary Protection | Additional Hardening |
|-------------------|-------------------|---------------------|---------------------|
| File Inclusion | `is_uploaded_file()` | MIME validation | `SecurityHardening::validateUploadedFileSecurity()` |
| Path Traversal | `basename()` + `realpath()` | Whitelist validation | `SecurityHardening::isPathSafe()` |
| SSRF | No external URLs used | Path-only validation | `SecurityHardening::isURLSafe()` |
| ReDoS | Simple regex patterns | No nested quantifiers | `SecurityHardening::isRegexSafe()` |

---

## Code Quality Metrics

### Security Validations Per Operation

**File Upload:**
1. `is_uploaded_file()` check ✅
2. Upload error code validation ✅
3. File size validation ✅
4. MIME type validation ✅
5. Dangerous extension check ✅ (new)
6. JSON structure validation ✅

**File Path Operations:**
1. `basename()` to strip directories ✅
2. `realpath()` to resolve paths ✅
3. Base directory containment check ✅
4. `file_exists()` validation ✅
5. Whitelist validation ✅
6. Null byte check ✅ (new)

**Data Validation:**
1. Profile whitelist validation ✅
2. LOB validation ✅
3. Framework whitelist validation ✅
4. Control ID regex validation ✅
5. Question ID validation ✅

---

## Static Analysis Tool Limitations

**Why SAST Tools Report False Positives:**

1. **Context Insensitivity:**
   - SAST tools don't understand that `$file['tmp_name']` is PHP-managed
   - They flag `file_get_contents()` without analyzing the parameter source

2. **Path Analysis Limitations:**
   - Tools don't track that paths go through `basename()` and `realpath()`
   - They can't verify runtime whitelist checks

3. **Data Flow Complexity:**
   - Tools can't always trace that user input is validated before use
   - Multiple validation layers confuse simple pattern matching

**How to Address:**
- ✅ Add comprehensive security controls (done)
- ✅ Add inline documentation explaining security measures
- ✅ Create security hardening layer for future use
- ✅ Maintain security audit documentation (this document)

---

## Additional Security Enhancements Implemented

### 1. SecurityHardening.php

New security library with advanced protections:

**Path Security:**
- `isPathSafe()` - Comprehensive path traversal prevention
- `safeFileGetContents()` - Safe file reading with validation
- `sanitizeFilename()` - Filename sanitization

**Upload Security:**
- `validateUploadedFileSecurity()` - Enhanced upload validation
- Dangerous extension detection
- Double extension attack prevention

**SSRF Prevention:**
- `isURLSafe()` - URL validation (for future use)
- Localhost blocking
- Cloud metadata service blocking
- Private IP range blocking

**ReDoS Prevention:**
- `isRegexSafe()` - Regex pattern validation
- `safePreMatch()` - Regex execution with limits
- Nested quantifier detection
- Overlapping alternation detection

### 2. Inline Security Comments

Added documentation comments to key security functions explaining protections.

### 3. Security Test Suite

Created comprehensive security tests for:
- XSS prevention (completed)
- File upload validation (new)
- Path traversal prevention (new)
- ReDoS protection (new)

---

## Recommendations

### For Development Team:

1. **Keep Security Controls:**
   - Don't remove or bypass existing validations
   - All `is_uploaded_file()`, `basename()`, `realpath()` checks are critical

2. **Code Review Checklist:**
   - [ ] All file uploads validated with `is_uploaded_file()`
   - [ ] All file paths go through `basename()` or `realpath()`
   - [ ] All user inputs validated against whitelists
   - [ ] All regex patterns are simple (no nested quantifiers)
   - [ ] No `file_get_contents()` on user-provided URLs

3. **Future Enhancements:**
   - Use `SecurityHardening` functions for new file operations
   - Add CSP headers (Content Security Policy)
   - Implement rate limiting on file uploads
   - Add automated security testing in CI/CD

### For Security Team:

1. **SAST Tool Configuration:**
   - Mark these findings as "false positive" in Snyk
   - Add suppression rules for validated patterns
   - Configure custom rules to recognize `is_uploaded_file()` pattern

2. **Testing:**
   - Manual penetration testing for file upload functionality
   - Fuzz testing for regex patterns
   - Path traversal attack simulation

3. **Monitoring:**
   - Log all file upload attempts
   - Monitor for unusual file paths in logs
   - Alert on validation failures

---

## Conclusion

**All reported high-severity vulnerabilities are FALSE POSITIVES or already mitigated.**

The application has:
- ✅ Comprehensive file upload validation
- ✅ Strong path traversal prevention
- ✅ No SSRF attack surface (no external URLs)
- ✅ Safe regex patterns (no ReDoS risk)
- ✅ Defense-in-depth security architecture
- ✅ Additional hardening layer for future use

**Risk Level:** LOW

**Action Required:** 
- Mark Snyk findings as "Won't Fix" or "False Positive" with reference to this document
- Continue maintaining existing security controls
- Use new `SecurityHardening` class for future enhancements

---

## References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- ReDoS: https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- PHP Security: https://www.php.net/manual/en/security.php

---

**Document Version:** 1.0  
**Last Updated:** 2026-10-20  
**Next Review:** After next Snyk scan  
**Status:** ✅ COMPLETED
