/**
 * Security Utility Functions
 * Provides safe HTML handling, input validation, and XSS prevention
 *
 * @version 1.0.0
 * @created 2026-10-20
 * @purpose XSS Vulnerability Remediation
 */

(function(window) {
    'use strict';

    const SecurityUtils = {

        /**
         * Safely decode HTML entities using DOMParser
         * Prevents XSS by using textContent extraction instead of innerHTML
         *
         * @param {string} text - Text with HTML entities to decode
         * @returns {string} Decoded text (safe for display)
         */
        decodeHtmlEntities: function(text) {
            if (!text || typeof text !== 'string') {
                return '';
            }

            // Use DOMParser for safe entity decoding
            const parser = new DOMParser();
            const doc = parser.parseFromString(text, 'text/html');
            // Extract text content (strips any HTML tags)
            return doc.documentElement.textContent || '';
        },

        /**
         * Escape HTML special characters to prevent XSS
         * Converts <, >, &, ", ' to their HTML entity equivalents
         *
         * @param {string} text - Text to escape
         * @returns {string} HTML-escaped text
         */
        escapeHtml: function(text) {
            if (!text || typeof text !== 'string') {
                return '';
            }

            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        /**
         * Sanitize CSS class names
         * Only allows alphanumeric characters, hyphens, and underscores
         *
         * @param {string} className - CSS class name to sanitize
         * @returns {string} Sanitized class name
         */
        sanitizeCssClass: function(className) {
            if (!className || typeof className !== 'string') {
                return '';
            }

            // Remove any characters that aren't alphanumeric, hyphen, or underscore
            return className.replace(/[^a-zA-Z0-9_-]/g, '');
        },

        /**
         * Validate and sanitize CSS color values
         * Accepts: hex colors (#RGB, #RRGGBB), named colors, rgb(), rgba()
         *
         * @param {string} color - Color value to validate
         * @param {string} fallback - Fallback color if invalid (default: '#000000')
         * @returns {string} Valid color or fallback
         */
        sanitizeColor: function(color, fallback) {
            fallback = fallback || '#000000';

            if (!color || typeof color !== 'string') {
                return fallback;
            }

            // Whitelist of common CSS color names
            const namedColors = [
                'black', 'white', 'red', 'green', 'blue', 'yellow', 'orange',
                'purple', 'pink', 'brown', 'gray', 'grey', 'cyan', 'magenta',
                'transparent', 'inherit', 'currentColor'
            ];

            // Check if it's a named color
            const lowerColor = color.toLowerCase().trim();
            if (namedColors.includes(lowerColor)) {
                return lowerColor;
            }

            // Check if it's a valid hex color (#RGB or #RRGGBB)
            if (/^#[0-9a-fA-F]{3}$/.test(color) || /^#[0-9a-fA-F]{6}$/.test(color)) {
                return color;
            }

            // Check if it's a valid rgb() or rgba()
            if (/^rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}(\s*,\s*[0-9.]+)?\s*\)$/.test(color)) {
                return color;
            }

            // Invalid color, return fallback
            console.warn('Invalid color value:', color, '- using fallback:', fallback);
            return fallback;
        },

        /**
         * Validate Font Awesome icon names
         * Only allows whitelisted icon names to prevent injection
         *
         * @param {string} iconName - Font Awesome icon class (without fa- prefix)
         * @param {string} fallback - Fallback icon if invalid (default: 'question')
         * @returns {string} Valid icon name or fallback
         */
        sanitizeIconName: function(iconName, fallback) {
            fallback = fallback || 'question';

            if (!iconName || typeof iconName !== 'string') {
                return fallback;
            }

            // Remove 'fa-' prefix if present
            iconName = iconName.replace(/^fa-/, '');

            // Whitelist of allowed Font Awesome icons
            const allowedIcons = [
                // Common UI icons
                'shield-alt', 'shield', 'cloud', 'code', 'users', 'user',
                'lock', 'unlock', 'server', 'cog', 'cogs', 'database',
                'network-wired', 'globe', 'key', 'certificate', 'file-contract',

                // Status/state icons
                'check', 'check-circle', 'times', 'times-circle', 'exclamation',
                'exclamation-triangle', 'info', 'info-circle', 'question', 'question-circle',

                // Action icons
                'download', 'upload', 'edit', 'trash', 'save', 'plus', 'minus',
                'search', 'filter', 'refresh', 'sync', 'home', 'arrow-left', 'arrow-right',

                // Assessment specific
                'clipboard-list', 'chart-line', 'chart-bar', 'tachometer-alt',
                'sliders', 'puzzle-piece', 'building', 'industry', 'hospital',
                'university', 'landmark', 'store', 'briefcase', 'handshake',

                // Theme icons
                'rocket', 'lightbulb', 'graduation-cap', 'heart', 'star',
                'crown', 'gem', 'fire', 'bolt', 'magic', 'wrench', 'tools'
            ];

            // Validate icon name (only alphanumeric and hyphens)
            if (!/^[a-z0-9-]+$/.test(iconName)) {
                console.warn('Invalid icon name format:', iconName);
                return fallback;
            }

            // Check if icon is in whitelist
            if (!allowedIcons.includes(iconName)) {
                console.warn('Icon not in whitelist:', iconName, '- using fallback:', fallback);
                return fallback;
            }

            return iconName;
        },

        /**
         * Sanitize percentage values
         * Ensures value is numeric and within 0-100 range
         *
         * @param {number|string} value - Percentage value
         * @param {number} fallback - Fallback value if invalid (default: 0)
         * @returns {number} Valid percentage value
         */
        sanitizePercent: function(value, fallback) {
            fallback = (typeof fallback === 'number') ? fallback : 0;

            const num = parseFloat(value);

            if (isNaN(num)) {
                console.warn('Invalid percentage value:', value);
                return fallback;
            }

            // Clamp to 0-100 range
            if (num < 0) return 0;
            if (num > 100) return 100;

            return num;
        },

        /**
         * Sanitize numeric values
         *
         * @param {number|string} value - Numeric value
         * @param {number} min - Minimum allowed value
         * @param {number} max - Maximum allowed value
         * @param {number} fallback - Fallback value if invalid
         * @returns {number} Valid numeric value
         */
        sanitizeNumber: function(value, min, max, fallback) {
            const num = parseFloat(value);

            if (isNaN(num)) {
                return (typeof fallback === 'number') ? fallback : 0;
            }

            if (typeof min === 'number' && num < min) return min;
            if (typeof max === 'number' && num > max) return max;

            return num;
        },

        /**
         * Sanitize domain ID for use in HTML attributes
         * Converts domain names to safe IDs (e.g., "Data Sovereignty" -> "Data-Sovereignty")
         *
         * @param {string} domain - Domain name
         * @returns {string} Sanitized domain ID
         */
        sanitizeDomainId: function(domain) {
            if (!domain || typeof domain !== 'string') {
                return '';
            }

            // Replace spaces with hyphens and remove any other special characters
            return domain
                .trim()
                .replace(/\s+/g, '-')
                .replace(/[^a-zA-Z0-9_-]/g, '');
        },

        /**
         * Create a safe HTML element with text content
         * Prevents XSS by using textContent instead of innerHTML
         *
         * @param {string} tagName - HTML tag name (e.g., 'div', 'span')
         * @param {string} textContent - Text content for the element
         * @param {string} className - Optional CSS class name(s)
         * @returns {HTMLElement} DOM element
         */
        createSafeElement: function(tagName, textContent, className) {
            const element = document.createElement(tagName);

            if (textContent) {
                element.textContent = textContent;
            }

            if (className) {
                element.className = this.sanitizeCssClass(className);
            }

            return element;
        },

        /**
         * Safely set HTML content after sanitization
         * Use this when you absolutely need to set HTML (prefer textContent when possible)
         *
         * @param {HTMLElement} element - Target element
         * @param {string} html - HTML content to sanitize and set
         */
        setSafeHtml: function(element, html) {
            if (!element || !html) return;

            // Basic HTML sanitization - strip script tags and event handlers
            const sanitized = html
                .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
                .replace(/on\w+\s*=\s*[^\s>]*/gi, '')
                .replace(/javascript:/gi, '');

            element.innerHTML = sanitized;
        }
    };

    // Export to global scope
    window.SecurityUtils = SecurityUtils;

    // Also support CommonJS/AMD if needed
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = SecurityUtils;
    }

})(window);
