# XSS Vulnerability Analysis & Remediation Plan

**Generated:** 2026-10-20  
**Analyst:** Claude Code Security Review  
**Application:** Viewfinder Red Hat Maturity Assessment

---

## Executive Summary

Snyk has reported approximately **70-80 XSS vulnerabilities** in the application. After detailed code analysis, these issues stem from **3 core vulnerability patterns** that are repeated across multiple files and contexts:

1. **DOM-based XSS via innerHTML** (6 instances)
2. **jQuery .html() injection** (2 instances)  
3. **Template literal injection** (multiple instances)

**Severity:** Medium to High  
**Remediation Effort:** Low-Medium (2-5 days)  
**Risk Level:** MEDIUM - Most inputs come from JSON config files (controlled), not direct user input

---

## Detailed Vulnerability Analysis

### Pattern 1: DOM-based XSS via innerHTML Decoding ⚠️ HIGH RISK

**Location 1:** `/var/www/html/viewfinder-redhat/index.php:1026-1035`

```javascript
// VULNERABLE CODE
var htmlContent = $(this).attr('data-tooltip');
if (!htmlContent) return;

// Decode HTML entities
var txt = document.createElement("textarea");
txt.innerHTML = htmlContent;  // ❌ VULNERABLE
var decoded = txt.value;

// Set tooltip content and show it
$tooltip.html(decoded).fadeIn(200);  // ❌ VULNERABLE
```

**Issue:**
- Uses `innerHTML` to decode HTML entities from `data-tooltip` attribute
- Then uses jQuery `.html()` to inject decoded content into tooltip
- If JSON config contains malicious HTML/JavaScript, it will execute

**Data Source:**
- Comes from `$json[$area][$summary]` (JSON configuration file)
- IS properly escaped on server-side with `htmlspecialchars()` before insertion
- BUT JavaScript decodes and re-renders as HTML, bypassing the escaping

**Impact:**
- If attacker can modify JSON config files → XSS
- Currently LOW risk (config files are server-controlled)
- Could become HIGH risk if JSON is ever user-editable

---

**Location 2:** `/var/www/html/viewfinder-redhat/results.php:1980-1995`

```javascript
// VULNERABLE CODE
var overviewText = $(this).attr('data-tooltip');
var themeIcon = $(this).attr('data-theme-icon');
var themeColor = $(this).attr('data-theme-color');

// Decode HTML entities
var txt = document.createElement("textarea");
txt.innerHTML = overviewText;  // ❌ VULNERABLE
var decoded = txt.value;

// Update the overview display
$('#themeOverviewIcon').html('<i class="fa-solid fa-' + themeIcon + '" style="color: ' + themeColor + ';"></i>');  // ❌ VULNERABLE
$('#themeOverviewTitle').text(themeName);  // ✅ SAFE
$('#themeOverviewText').text(decoded);     // ✅ SAFE
```

**Issue:**
- Same innerHTML pattern for entity decoding
- Injects `themeIcon` and `themeColor` directly into HTML via `.html()` method
- No validation that `themeIcon` and `themeColor` are safe values

**Impact:** MEDIUM - Icon and color come from data attributes, could inject malicious content

---

### Pattern 2: Direct innerHTML Assignment ⚠️ MEDIUM RISK

**Location:** `/var/www/html/viewfinder-redhat/maturity-assessment-landing.php`

**Instance 1 (Line 649):**
```javascript
// STATIC CONTENT - SAFE
descriptionContainer.innerHTML = '<i class="fa-solid fa-sliders"></i><span id="maturity-profile-description-text">Adjust domain weights below using the sliders. Higher weights indicate greater priority.</span>';
```
✅ **SAFE** - Static HTML string with no user input

**Instance 2 (Lines 695-696):**
```javascript
// VULNERABLE
const icon = lobIcons[selectedLob] || 'fa-building';
descriptionContainer.innerHTML = '<i class="fa-solid ' + icon + '"></i><span id="maturity-profile-description-text">' +
                                 lobData.description + '</span>';
```
⚠️ **VULNERABLE** - `icon` and `lobData.description` not validated

**Instance 3 (Line 752):**
```javascript
// CLEARING CONTENT - SAFE
container.innerHTML = '';
```
✅ **SAFE** - Just clearing content

**Instance 4 (Lines 763-768):**
```javascript
// VULNERABLE - Template Literal
weightItem.innerHTML = `
  <span class="weight-domain">${domain}</span>
  <div class="weight-bar-container">
    <div class="weight-bar ${highWeightClass}" id="maturity-weight-bar-${domainId}" style="width: ${widthPercent}%;"></div>
  </div>
  <span class="weight-value ${highWeightClass}" id="maturity-weight-value-${domainId}">${weight.toFixed(1)}×</span>
`;
```
⚠️ **VULNERABLE** - Multiple variables injected: `domain`, `highWeightClass`, `domainId`, `widthPercent`, `weight`

**Data Source:** Comes from `profileControlsMap` and `lobWeightsData` JavaScript objects
**Impact:** MEDIUM - If attacker can control these data structures → XSS

---

## Why Snyk Reports 70-80 Issues

Snyk's **data flow analysis** traces each variable through the code:
- Each `domain` variable → separate finding
- Each `highWeightClass` → separate finding  
- Each template literal occurrence → separate finding
- Different execution paths → duplicate findings

**Reality:** ~8 actual vulnerable code locations, reported as 70-80 due to:
- Multiple data flow paths
- Multiple variables in same statement
- Similar patterns across different files

---

## Remediation Strategy

### Phase 1: Fix innerHTML Entity Decoding Pattern (Priority: HIGH)

**Current vulnerable pattern:**
```javascript
var txt = document.createElement("textarea");
txt.innerHTML = htmlContent;  // Unsafe
var decoded = txt.value;
$tooltip.html(decoded);  // Unsafe
```

**SOLUTION A:** Use DOMParser (Modern, Secure)
```javascript
function decodeHtmlEntities(text) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(text, 'text/html');
    return doc.documentElement.textContent;
}

var decoded = decodeHtmlEntities(htmlContent);
$tooltip.text(decoded);  // Use .text() not .html()
```

**SOLUTION B:** Use textContent (Simpler, Secure)
```javascript
function decodeHtmlEntities(text) {
    var txt = document.createElement('textarea');
    txt.textContent = text;  // Use textContent, not innerHTML
    return txt.value;
}

var decoded = decodeHtmlEntities(htmlContent);
$tooltip.text(decoded);  // Use .text() not .html()
```

**SOLUTION C:** Don't decode at all (Best if acceptable)
```javascript
// If HTML entities should display as-is, just use the value directly
$tooltip.text(htmlContent);
```

**Files to fix:**
- `/var/www/html/viewfinder-redhat/index.php` (line 1026-1035)
- `/var/www/html/viewfinder-redhat/results.php` (line 1980-1995)

---

### Phase 2: Fix jQuery .html() Injections (Priority: HIGH)

**Location:** `results.php:1993`

**Current:**
```javascript
$('#themeOverviewIcon').html('<i class="fa-solid fa-' + themeIcon + '" style="color: ' + themeColor + ';"></i>');
```

**OPTION 1 - Validate icon names (Recommended):**
```javascript
// Whitelist of allowed Font Awesome icon classes
const ALLOWED_ICONS = [
    'fa-shield-alt', 'fa-cloud', 'fa-code', 'fa-users',
    'fa-lock', 'fa-server', 'fa-cog'
    // ... add all valid icons
];

// Validate icon name
if (!ALLOWED_ICONS.includes(themeIcon)) {
    themeIcon = 'fa-question';  // Fallback icon
}

// Validate color (CSS color or hex)
if (!/^(#[0-9a-f]{3,6}|[a-z\-]+)$/i.test(themeColor)) {
    themeColor = '#000000';  // Fallback color
}

$('#themeOverviewIcon').html('<i class="fa-solid fa-' + themeIcon + '" style="color: ' + themeColor + ';"></i>');
```

**OPTION 2 - Use DOM manipulation (Most Secure):**
```javascript
const iconElement = document.createElement('i');
iconElement.className = 'fa-solid fa-' + sanitizeIconName(themeIcon);
iconElement.style.color = sanitizeColor(themeColor);
$('#themeOverviewIcon').empty().append(iconElement);
```

---

### Phase 3: Fix Template Literal Injections (Priority: MEDIUM)

**Location:** `maturity-assessment-landing.php:763-768`

**Current:**
```javascript
weightItem.innerHTML = `
  <span class="weight-domain">${domain}</span>
  <div class="weight-bar-container">
    <div class="weight-bar ${highWeightClass}" id="maturity-weight-bar-${domainId}" style="width: ${widthPercent}%;"></div>
  </div>
  <span class="weight-value ${highWeightClass}" id="maturity-weight-value-${domainId}">${weight.toFixed(1)}×</span>
`;
```

**SOLUTION - Use textContent for text nodes, validate CSS:**
```javascript
// HTML-escape function
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Validate CSS class (alphanumeric, dash, underscore only)
function sanitizeCssClass(className) {
    return className.replace(/[^a-zA-Z0-9_-]/g, '');
}

// Validate percentage (must be 0-100)
function sanitizePercent(value) {
    const num = parseFloat(value);
    if (isNaN(num) || num < 0 || num > 100) return 0;
    return num;
}

// Build safely
weightItem.innerHTML = `
  <span class="weight-domain">${escapeHtml(domain)}</span>
  <div class="weight-bar-container">
    <div class="weight-bar ${sanitizeCssClass(highWeightClass)}" id="maturity-weight-bar-${sanitizeCssClass(domainId)}" style="width: ${sanitizePercent(widthPercent)}%;"></div>
  </div>
  <span class="weight-value ${sanitizeCssClass(highWeightClass)}" id="maturity-weight-value-${sanitizeCssClass(domainId)}">${weight.toFixed(1)}×</span>
`;
```

**BETTER SOLUTION - Use DOM methods:**
```javascript
// Create elements safely
const domainSpan = document.createElement('span');
domainSpan.className = 'weight-domain';
domainSpan.textContent = domain;

const barContainer = document.createElement('div');
barContainer.className = 'weight-bar-container';

const bar = document.createElement('div');
bar.className = 'weight-bar ' + sanitizeCssClass(highWeightClass);
bar.id = 'maturity-weight-bar-' + sanitizeCssClass(domainId);
bar.style.width = sanitizePercent(widthPercent) + '%';

const valueSpan = document.createElement('span');
valueSpan.className = 'weight-value ' + sanitizeCssClass(highWeightClass);
valueSpan.id = 'maturity-weight-value-' + sanitizeCssClass(domainId);
valueSpan.textContent = weight.toFixed(1) + '×';

// Assemble
barContainer.appendChild(bar);
weightItem.appendChild(domainSpan);
weightItem.appendChild(barContainer);
weightItem.appendChild(valueSpan);
```

---

### Phase 4: Implement Content Security Policy (Priority: HIGH)

Add CSP header to prevent inline script execution:

```php
// Add to all PHP pages
header("Content-Security-Policy: " .
    "default-src 'self'; " .
    "script-src 'self' https://code.jquery.com https://cdnjs.cloudflare.com https://kit.fontawesome.com 'unsafe-inline'; " .
    "style-src 'self' https://code.jquery.com https://unpkg.com 'unsafe-inline'; " .
    "img-src 'self' data:; " .
    "font-src 'self' https://kit.fontawesome.com; " .
    "connect-src 'self'");
```

**Better:** Move all inline JavaScript to external files and remove `'unsafe-inline'`

---

## Implementation Plan

### Week 1: High Priority Fixes

**Day 1-2:**
- [ ] Create utility functions file (`js/security-utils.js`):
  - `decodeHtmlEntities()` - Safe HTML entity decoder
  - `escapeHtml()` - HTML escaping function
  - `sanitizeCssClass()` - CSS class validator
  - `sanitizeColor()` - Color validator
  - `sanitizeIconName()` - Icon name validator

**Day 3:**
- [ ] Fix index.php (lines 1026-1035) - Replace innerHTML pattern
- [ ] Fix results.php (lines 1980-1995) - Replace innerHTML pattern
- [ ] Fix results.php (line 1993) - Validate icon/color injection

**Day 4:**
- [ ] Fix maturity-assessment-landing.php template literals
- [ ] Add input validation for all dynamic content

**Day 5:**
- [ ] Add Content Security Policy headers
- [ ] Test all fixes in development environment

### Week 2: Testing & Validation

**Day 1-2:**
- [ ] Manual testing of all affected pages
- [ ] Test with malicious payloads in JSON configs
- [ ] Verify tooltips still display correctly

**Day 3:**
- [ ] Run Snyk scan again to verify fixes
- [ ] Document any remaining false positives

**Day 4-5:**
- [ ] Deploy to staging environment
- [ ] User acceptance testing
- [ ] Prepare for production deployment

---

## Testing Payloads

Use these in JSON config files to test XSS fixes:

```json
{
  "1-summary": "<script>alert('XSS')</script>",
  "2-summary": "<img src=x onerror=alert('XSS')>",
  "3-summary": "Normal text &lt;b&gt;with entities&lt;/b&gt;",
  "4-summary": "' onclick='alert(1)' data-x='",
  "5-summary": "${alert('XSS')}"
}
```

**Expected after fix:**
- Displays as literal text, no script execution
- HTML entities decode correctly for display
- No JavaScript injection possible

---

## Risk Assessment

### Current Risk Level: **MEDIUM**

**Mitigating Factors:**
✅ Most data comes from server-controlled JSON config files  
✅ No direct user input in vulnerable locations  
✅ Application appears to be internal/admin-facing  
✅ Server-side escaping IS being used (`htmlspecialchars`)

**Concern Factors:**
⚠️ Client-side JavaScript bypasses server escaping  
⚠️ If JSON becomes user-editable → HIGH RISK  
⚠️ DOM-based XSS can bypass WAF/filters  
⚠️ Multiple vulnerable patterns across codebase

### Post-Remediation Risk: **LOW**
- All inputs validated/escaped
- CSP prevents inline script execution
- Defense in depth approach

---

## Estimated Effort

| Phase | Effort | Dependencies |
|-------|--------|--------------|
| Create utility functions | 4 hours | None |
| Fix innerHTML patterns (2 files) | 6 hours | Utilities |
| Fix .html() injections | 4 hours | Utilities |
| Fix template literals | 8 hours | Utilities |
| Add CSP headers | 2 hours | None |
| Testing & validation | 16 hours | All fixes |
| **TOTAL** | **40 hours** | ~5 working days |

---

## Recommended Next Steps

1. ✅ **Approved?** Review this analysis with development team
2. ✅ **Priority?** Confirm remediation priority (High/Medium/Low)
3. ✅ **Timeline?** Schedule 5-day sprint for fixes
4. ✅ **Resources?** Assign developer for implementation
5. ✅ **Testing?** Coordinate with QA for validation

**Would you like me to:**
- [ ] Create the security utility functions now?
- [ ] Start fixing the high-priority issues?
- [ ] Create a pull request with all fixes?
- [ ] Generate specific test cases?

---

**Document Version:** 1.0  
**Last Updated:** 2026-10-20  
**Next Review:** After remediation complete
