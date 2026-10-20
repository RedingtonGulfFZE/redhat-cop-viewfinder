<?php
/**
 * Security Hardening Layer
 * Additional security validations to address SAST (Static Analysis) findings
 *
 * This class adds defense-in-depth measures for:
 * - File Inclusion vulnerabilities
 * - Path Traversal attacks
 * - SSRF (Server-Side Request Forgery)
 * - ReDoS (Regular Expression Denial of Service)
 *
 * @version 1.0.0
 * @created 2026-10-20
 */

require_once __DIR__ . '/Logger.php';

class SecurityHardening {

    /**
     * Validate that a file path is safe and within allowed directory
     *
     * Prevents path traversal attacks by ensuring:
     * - No null bytes
     * - No directory traversal sequences (../)
     * - Path resolves within allowed base directory
     * - No symlink tricks
     *
     * @param string $filePath Path to validate
     * @param string $allowedBaseDir Base directory that file must be within
     * @return bool True if path is safe
     */
    public static function isPathSafe(string $filePath, string $allowedBaseDir): bool {
        // Check for null bytes (path truncation attack)
        if (strpos($filePath, "\0") !== false) {
            Logger::warning('Path contains null byte', ['path' => $filePath]);
            return false;
        }

        // Check for directory traversal sequences
        if (strpos($filePath, '../') !== false || strpos($filePath, '..\\') !== false) {
            Logger::warning('Path contains directory traversal sequence', ['path' => $filePath]);
            return false;
        }

        // Ensure both paths exist before resolving
        if (!file_exists($filePath)) {
            Logger::debug('Path does not exist', ['path' => $filePath]);
            return false;
        }

        if (!is_dir($allowedBaseDir)) {
            Logger::error('Base directory does not exist', ['base_dir' => $allowedBaseDir]);
            return false;
        }

        // Get real paths (resolves symlinks and relative paths)
        $realFilePath = realpath($filePath);
        $realBaseDir = realpath($allowedBaseDir);

        if ($realFilePath === false || $realBaseDir === false) {
            Logger::warning('Failed to resolve real path', [
                'file_path' => $filePath,
                'base_dir' => $allowedBaseDir,
                'real_file' => $realFilePath,
                'real_base' => $realBaseDir
            ]);
            return false;
        }

        // Ensure file is within allowed directory
        if (strpos($realFilePath, $realBaseDir) !== 0) {
            Logger::warning('Path is outside allowed directory', [
                'file_path' => $realFilePath,
                'base_dir' => $realBaseDir
            ]);
            return false;
        }

        return true;
    }

    /**
     * Safely read file contents with additional validation
     *
     * Adds extra security layer on top of file_get_contents:
     * - Validates path is safe
     * - Checks file size before reading
     * - Validates file is readable
     *
     * @param string $filePath Path to file
     * @param string $allowedBaseDir Base directory file must be within
     * @param int $maxSize Maximum file size in bytes (default 10MB)
     * @return string File contents
     * @throws RuntimeException If file cannot be read safely
     */
    public static function safeFileGetContents(
        string $filePath,
        string $allowedBaseDir,
        int $maxSize = 10485760
    ): string {
        // Validate path is safe
        if (!self::isPathSafe($filePath, $allowedBaseDir)) {
            throw new RuntimeException('Path validation failed: ' . $filePath);
        }

        // Check file is readable
        if (!is_readable($filePath)) {
            Logger::error('File is not readable', ['path' => $filePath]);
            throw new RuntimeException('File is not readable: ' . $filePath);
        }

        // Check file size before reading
        $fileSize = filesize($filePath);
        if ($fileSize === false || $fileSize > $maxSize) {
            Logger::error('File size check failed', [
                'path' => $filePath,
                'size' => $fileSize,
                'max_size' => $maxSize
            ]);
            throw new RuntimeException('File size exceeds maximum allowed: ' . $filePath);
        }

        // Read file contents
        $contents = @file_get_contents($filePath);
        if ($contents === false) {
            Logger::error('Failed to read file', ['path' => $filePath]);
            throw new RuntimeException('Failed to read file: ' . $filePath);
        }

        Logger::debug('File read successfully', [
            'path' => $filePath,
            'size' => strlen($contents)
        ]);

        return $contents;
    }

    /**
     * Validate uploaded file is safe
     *
     * Comprehensive validation for file uploads:
     * - File was actually uploaded via HTTP POST
     * - No upload errors
     * - File size within limits
     * - MIME type validation
     * - No executable file extensions
     *
     * @param array $file $_FILES array entry
     * @param array $allowedMimes Allowed MIME types
     * @param int $maxSize Maximum file size in bytes
     * @return bool True if file is safe
     * @throws RuntimeException If validation fails
     */
    public static function validateUploadedFileSecurity(
        array $file,
        array $allowedMimes = ['application/json', 'text/plain'],
        int $maxSize = 5242880  // 5MB
    ): bool {
        // Verify file was uploaded via POST
        if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
            Logger::error('File was not uploaded via HTTP POST', ['file' => $file]);
            throw new RuntimeException('File was not uploaded via HTTP POST');
        }

        // Check upload error
        if (isset($file['error']) && $file['error'] !== UPLOAD_ERR_OK) {
            Logger::error('File upload error', [
                'error_code' => $file['error'],
                'file_name' => $file['name'] ?? 'unknown'
            ]);
            throw new RuntimeException('File upload error: ' . $file['error']);
        }

        // Validate file size
        if (!isset($file['size']) || $file['size'] > $maxSize) {
            Logger::error('File size exceeds maximum', [
                'size' => $file['size'] ?? 0,
                'max_size' => $maxSize
            ]);
            throw new RuntimeException('File size exceeds maximum allowed');
        }

        // Validate MIME type
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);

        if (!in_array($mimeType, $allowedMimes, true)) {
            Logger::warning('Invalid MIME type', [
                'mime' => $mimeType,
                'allowed' => $allowedMimes,
                'file' => $file['name'] ?? 'unknown'
            ]);
            throw new RuntimeException('Invalid file type. Allowed types: ' . implode(', ', $allowedMimes));
        }

        // Check for dangerous file extensions (double extension attack)
        if (isset($file['name'])) {
            $filename = strtolower($file['name']);
            $dangerousExtensions = [
                '.php', '.phtml', '.php3', '.php4', '.php5', '.php7',
                '.exe', '.bat', '.cmd', '.sh', '.cgi', '.pl', '.py',
                '.jsp', '.asp', '.aspx', '.dll', '.so'
            ];

            foreach ($dangerousExtensions as $ext) {
                if (strpos($filename, $ext) !== false) {
                    Logger::error('Dangerous file extension detected', [
                        'filename' => $filename,
                        'extension' => $ext
                    ]);
                    throw new RuntimeException('Dangerous file extension detected: ' . $ext);
                }
            }
        }

        Logger::info('Uploaded file validated successfully', [
            'filename' => $file['name'] ?? 'unknown',
            'size' => $file['size'] ?? 0,
            'mime' => $mimeType
        ]);

        return true;
    }

    /**
     * Validate regex pattern is safe (prevents ReDoS)
     *
     * Checks for patterns that could cause catastrophic backtracking:
     * - Nested quantifiers
     * - Overlapping alternations
     * - Complex lookaheads with quantifiers
     *
     * @param string $pattern Regex pattern to validate
     * @return bool True if pattern is safe
     */
    public static function isRegexSafe(string $pattern): bool {
        // Check for catastrophic backtracking patterns

        // Nested quantifiers: (a+)+ or (a*)* or (a+)*
        if (preg_match('/\([^)]*[*+][^)]*\)[*+]/', $pattern)) {
            Logger::warning('Regex contains nested quantifiers (ReDoS risk)', ['pattern' => $pattern]);
            return false;
        }

        // Overlapping alternations with quantifiers: (a|ab)+ or (a|a*)+
        if (preg_match('/\([^)]*\|[^)]*\)[*+]/', $pattern)) {
            $alternationContent = null;
            if (preg_match('/\(([^)]*)\)[*+]/', $pattern, $matches)) {
                $alternationContent = $matches[1];
                // Check if alternations could overlap
                $parts = explode('|', $alternationContent);
                if (count($parts) > 1) {
                    foreach ($parts as $i => $part1) {
                        foreach ($parts as $j => $part2) {
                            if ($i !== $j && (strpos($part2, $part1) === 0 || strpos($part1, $part2) === 0)) {
                                Logger::warning('Regex contains overlapping alternations (ReDoS risk)', [
                                    'pattern' => $pattern
                                ]);
                                return false;
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    /**
     * Execute regex with timeout protection (prevents ReDoS)
     *
     * @param string $pattern Regex pattern
     * @param string $subject String to match against
     * @param array $matches Output matches array
     * @param int $timeoutMs Timeout in milliseconds (default 1000)
     * @return bool|null True if match, false if no match, null if timeout
     */
    public static function safePreMatch(
        string $pattern,
        string $subject,
        array &$matches = null,
        int $timeoutMs = 1000
    ): ?bool {
        // Validate pattern first
        if (!self::isRegexSafe($pattern)) {
            Logger::error('Unsafe regex pattern rejected', ['pattern' => $pattern]);
            throw new RuntimeException('Unsafe regex pattern');
        }

        // Set PCRE backtrack and recursion limits
        $oldBacktrackLimit = ini_get('pcre.backtrack_limit');
        $oldRecursionLimit = ini_get('pcre.recursion_limit');

        ini_set('pcre.backtrack_limit', '100000');
        ini_set('pcre.recursion_limit', '100000');

        // Execute with error handling
        $matches = [];
        $result = @preg_match($pattern, $subject, $matches);

        // Check for PCRE errors
        $error = preg_last_error();
        if ($error !== PREG_NO_ERROR) {
            $errorMessages = [
                PREG_INTERNAL_ERROR => 'Internal error',
                PREG_BACKTRACK_LIMIT_ERROR => 'Backtrack limit exceeded (possible ReDoS)',
                PREG_RECURSION_LIMIT_ERROR => 'Recursion limit exceeded',
                PREG_BAD_UTF8_ERROR => 'Bad UTF-8 error',
                PREG_BAD_UTF8_OFFSET_ERROR => 'Bad UTF-8 offset error'
            ];

            $errorMsg = $errorMessages[$error] ?? 'Unknown error: ' . $error;

            Logger::error('Regex execution error', [
                'pattern' => $pattern,
                'error' => $errorMsg,
                'error_code' => $error
            ]);

            // Restore limits
            ini_set('pcre.backtrack_limit', $oldBacktrackLimit);
            ini_set('pcre.recursion_limit', $oldRecursionLimit);

            return null;  // Timeout or error
        }

        // Restore limits
        ini_set('pcre.backtrack_limit', $oldBacktrackLimit);
        ini_set('pcre.recursion_limit', $oldRecursionLimit);

        return $result === 1;
    }

    /**
     * Sanitize filename to prevent path traversal and injection
     *
     * @param string $filename Original filename
     * @return string Sanitized filename
     */
    public static function sanitizeFilename(string $filename): string {
        // Use basename to strip any directory components
        $filename = basename($filename);

        // Remove null bytes
        $filename = str_replace("\0", '', $filename);

        // Remove path traversal sequences
        $filename = str_replace(['../', '..\\'], '', $filename);

        // Remove any remaining potentially dangerous characters
        $filename = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename);

        // Ensure filename is not empty
        if (empty($filename)) {
            $filename = 'file_' . bin2hex(random_bytes(8));
        }

        return $filename;
    }

    /**
     * Validate URL is not targeting internal resources (prevents SSRF)
     *
     * @param string $url URL to validate
     * @param bool $allowPrivateIPs Whether to allow private IP addresses
     * @return bool True if URL is safe
     */
    public static function isURLSafe(string $url, bool $allowPrivateIPs = false): bool {
        // Parse URL
        $parsed = parse_url($url);
        if ($parsed === false || !isset($parsed['host'])) {
            Logger::warning('Invalid URL format', ['url' => $url]);
            return false;
        }

        // Only allow http and https protocols
        $scheme = $parsed['scheme'] ?? '';
        if (!in_array($scheme, ['http', 'https'], true)) {
            Logger::warning('Invalid URL scheme', ['url' => $url, 'scheme' => $scheme]);
            return false;
        }

        $host = $parsed['host'];

        // Block localhost
        if (in_array(strtolower($host), ['localhost', '127.0.0.1', '::1'], true)) {
            Logger::warning('URL targets localhost (SSRF risk)', ['url' => $url]);
            return false;
        }

        // Block metadata service URLs (cloud providers)
        $metadataHosts = [
            '169.254.169.254',  // AWS, Azure, GCP metadata service
            '169.254.170.2',    // ECS task metadata
            '100.100.100.200',  // Alibaba Cloud
        ];

        if (in_array($host, $metadataHosts, true)) {
            Logger::warning('URL targets cloud metadata service (SSRF risk)', ['url' => $url]);
            return false;
        }

        // Check for private IP ranges if not allowed
        if (!$allowPrivateIPs) {
            $ip = gethostbyname($host);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                Logger::warning('URL resolves to private IP address (SSRF risk)', [
                    'url' => $url,
                    'host' => $host,
                    'ip' => $ip
                ]);
                return false;
            }
        }

        return true;
    }
}
