/* ==========================================================================
   Password Strength Checker - Application Logic
   ========================================================================== */

(function() {
    'use strict';

    // ==========================================================================
    // Constants & Configuration
    // ==========================================================================

    const COMMON_SEQUENCES = [
        '0123456789', '9876543210',
        'abcdefghijklmnopqrstuvwxyz', 'zyxwvutsrqponmlkjihgfedcba',
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
        'qwerty', 'asdfgh', 'zxcvbn',
        '123456', '654321', '111111', '000000',
        'abcdef', 'fedcba', 'abc123', '123abc',
        'password', 'passwort', 'senha', 'motdepasse',
        'admin', 'root', 'user', 'login',
        'welcome', 'hello', 'master', 'secret'
    ];

    const COMMON_PASSWORDS = new Set([
        'password', '123456', '123456789', '12345678', '12345',
        '1234567', '1234567890', 'qwerty', 'abc123', 'password1',
        'admin', 'welcome', 'login', 'monkey', 'dragon',
        'master', 'hello', 'football', 'baseball', 'superman',
        'batman', 'trustno1', 'sunshine', 'iloveyou', 'princess',
        'starwars', 'whatever', 'freedom', 'computer', 'internet'
    ]);

    const SPECIAL_CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
    const NUMBERS = '0123456789';
    const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
    const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    // Crack time thresholds (in seconds)
    const CRACK_THRESHOLDS = [
        { threshold: 1, label: 'Instantly' },
        { threshold: 60, label: 'Less than a minute' },
        { threshold: 3600, label: 'Less than an hour' },
        { threshold: 86400, label: 'Less than a day' },
        { threshold: 604800, label: 'Less than a week' },
        { threshold: 2592000, label: 'Less than a month' },
        { threshold: 31536000, label: 'Less than a year' },
        { threshold: 315360000, label: 'Less than a decade' },
        { threshold: 3153600000, label: 'Less than a century' },
        { threshold: Infinity, label: 'Centuries+' }
    ];

    // Assumed guesses per second (offline attack, strong hash like bcrypt)
    const GUESSES_PER_SECOND = 1e10; // 10 billion guesses/second

    // ==========================================================================
    // DOM Elements
    // ==========================================================================

    const elements = {
        passwordInput: document.getElementById('password-input'),
        toggleVisibility: document.getElementById('toggle-visibility'),
        meterFill: document.getElementById('meter-fill'),
        strengthValue: document.getElementById('strength-value'),
        entropyInfo: document.getElementById('entropy-info'),
        entropyValue: document.getElementById('entropy-value'),
        crackTime: document.getElementById('crack-time'),
        crackValue: document.getElementById('crack-value'),
        criteriaList: document.getElementById('criteria-list'),
        suggestionsList: document.getElementById('suggestions-list'),
        suggestionsSection: document.getElementById('suggestions-section')
    };

    // ==========================================================================
    // Strength Calculation
    // ==========================================================================

    /**
     * Calculate the character pool size for a password
     */
    function calculatePoolSize(password) {
        let pool = 0;
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecial = new RegExp(`[${escapeRegExp(SPECIAL_CHARS)}]`).test(password);

        if (hasLower) pool += 26;
        if (hasUpper) pool += 26;
        if (hasNumber) pool += 10;
        if (hasSpecial) pool += SPECIAL_CHARS.length;

        // Bonus for using multiple character types
        const typesUsed = [hasLower, hasUpper, hasNumber, hasSpecial].filter(Boolean).length;
        if (typesUsed >= 3) pool += typesUsed * 2;

        return Math.max(pool, 1);
    }

    /**
     * Calculate Shannon entropy in bits
     */
    function calculateEntropy(password) {
        if (!password) return 0;
        const poolSize = calculatePoolSize(password);
        const length = password.length;
        return length * Math.log2(poolSize);
    }

    /**
     * Estimate time to crack based on entropy
     */
    function estimateCrackTime(entropy) {
        if (entropy <= 0) return 0;
        const combinations = Math.pow(2, entropy);
        return combinations / (2 * GUESSES_PER_SECOND); // Average case = half the keyspace
    }

    /**
     * Format crack time into human-readable string
     */
    function formatCrackTime(seconds) {
        if (seconds <= 0) return 'Instantly';
        if (!isFinite(seconds)) return 'Centuries+';

        for (const { threshold, label } of CRACK_THRESHOLDS) {
            if (seconds < threshold) {
                if (threshold === 1) return label;
                if (threshold === 60) return `${Math.ceil(seconds)} seconds`;
                if (threshold === 3600) return `${Math.ceil(seconds / 60)} minutes`;
                if (threshold === 86400) return `${Math.ceil(seconds / 3600)} hours`;
                if (threshold === 604800) return `${Math.ceil(seconds / 86400)} days`;
                if (threshold === 2592000) return `${Math.ceil(seconds / 604800)} weeks`;
                if (threshold === 31536000) return `${Math.ceil(seconds / 2592000)} months`;
                if (threshold === 315360000) return `${Math.ceil(seconds / 31536000)} years`;
                if (threshold === 3153600000) return `${Math.ceil(seconds / 315360000)} decades`;
                return label;
            }
        }
        return 'Centuries+';
    }

    /**
     * Determine strength level from entropy
     */
    function getStrengthLevel(entropy) {
        if (entropy < 28) return 'weak';
        if (entropy < 36) return 'fair';
        if (entropy < 60) return 'good';
        return 'strong';
    }

    // ==========================================================================
    // Criteria Checking
    // ==========================================================================

    function checkCriteria(password) {
        const results = {
            length: password.length >= 12,
            lowercase: /[a-z]/.test(password),
            uppercase: /[A-Z]/.test(password),
            numbers: /[0-9]/.test(password),
            special: new RegExp(`[${escapeRegExp(SPECIAL_CHARS)}]`).test(password),
            'no-sequences': !hasCommonSequence(password),
            'no-repeats': !hasRepeatedChars(password)
        };
        return results;
    }

    function hasCommonSequence(password) {
        const lower = password.toLowerCase();
        const len = lower.length;

        // Check for sequences of 3+ characters
        for (const seq of COMMON_SEQUENCES) {
            for (let i = 0; i <= seq.length - 3; i++) {
                const sub = seq.slice(i, i + 3);
                if (lower.includes(sub)) return true;
                // Also check reversed
                if (lower.includes(sub.split('').reverse().join(''))) return true;
            }
        }

        // Check for keyboard patterns (3+ adjacent keys)
        const keyboardPatterns = [
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '1234567890', '0987654321'
        ];
        for (const pattern of keyboardPatterns) {
            for (let i = 0; i <= pattern.length - 3; i++) {
                const sub = pattern.slice(i, i + 3);
                if (lower.includes(sub)) return true;
            }
        }

        return false;
    }

    function hasRepeatedChars(password) {
        // Check for 3+ same characters in a row
        for (let i = 0; i < password.length - 2; i++) {
            if (password[i] === password[i+1] && password[i] === password[i+2]) {
                return true;
            }
        }
        // Check for 3+ repeating pattern (e.g., "abcabcabc")
        for (let len = 1; len <= 4; len++) {
            for (let i = 0; i <= password.length - len * 3; i++) {
                const pattern = password.slice(i, i + len);
                const repeated = pattern.repeat(3);
                if (password.slice(i, i + len * 3) === repeated) {
                    return true;
                }
            }
        }
        return false;
    }

    // ==========================================================================
    // Suggestions Generation
    // ==========================================================================

    function generateSuggestions(password, criteria) {
        const suggestions = [];

        if (!password) return suggestions;

        if (!criteria.length) {
            suggestions.push({
                title: 'Increase Length',
                description: 'Aim for at least 12 characters. Each additional character exponentially increases strength.',
                icon: createIcon('length')
            });
        } else if (password.length < 16) {
            suggestions.push({
                title: 'Consider Even Longer',
                description: 'Passwords of 16+ characters provide excellent protection against brute-force attacks.',
                icon: createIcon('length')
            });
        }

        if (!criteria.lowercase) {
            suggestions.push({
                title: 'Add Lowercase Letters',
                description: 'Include lowercase letters (a-z) to expand the character pool.',
                icon: createIcon('lowercase')
            });
        }

        if (!criteria.uppercase) {
            suggestions.push({
                title: 'Add Uppercase Letters',
                description: 'Include uppercase letters (A-Z) to expand the character pool.',
                icon: createIcon('uppercase')
            });
        }

        if (!criteria.numbers) {
            suggestions.push({
                title: 'Add Numbers',
                description: 'Include numbers (0-9) to expand the character pool.',
                icon: createIcon('numbers')
            });
        }

        if (!criteria.special) {
            suggestions.push({
                title: 'Add Special Characters',
                description: `Include symbols like ${SPECIAL_CHARS.split('').slice(0, 8).join(' ')} to significantly increase entropy.`,
                icon: createIcon('special')
            });
        }

        if (!criteria['no-sequences']) {
            suggestions.push({
                title: 'Avoid Common Sequences',
                description: 'Remove patterns like "123", "abc", "qwerty", or keyboard patterns.',
                icon: createIcon('sequence')
            });
        }

        if (!criteria['no-repeats']) {
            suggestions.push({
                title: 'Avoid Repeated Characters',
                description: 'Don\'t repeat the same character 3+ times (e.g., "aaa", "111") or patterns like "abcabc".',
                icon: createIcon('repeat')
            });
        }

        // Check for common passwords
        if (COMMON_PASSWORDS.has(password.toLowerCase())) {
            suggestions.unshift({
                title: '⚠️ Very Common Password',
                description: 'This password appears in common password lists. Choose something unique immediately.',
                icon: createIcon('warning')
            });
        }

        // Positive reinforcement suggestions for good passwords
        if (Object.values(criteria).every(v => v) && password.length >= 16) {
            suggestions.push({
                title: 'Excellent! Consider a Passphrase',
                description: 'For even better memorability, try a passphrase like "correct-horse-battery-staple-789".',
                icon: createIcon('passphrase')
            });
        }

        return suggestions;
    }

    function createIcon(type) {
        const icons = {
            length: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="5 6 5 18 19 18"/></svg>',
            lowercase: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><text x="6" y="18" font-size="12">abc</text></svg>',
            uppercase: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><text x="6" y="18" font-size="12">ABC</text></svg>',
            numbers: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><text x="6" y="18" font-size="12">123</text></svg>',
            special: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><text x="6" y="18" font-size="12">!@#</text></svg>',
            sequence: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 16 17"/><line x1="10" y1="11" x2="10" y2="6"/></svg>',
            repeat: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="12" r="3"/><circle cx="16" cy="12" r="3"/></svg>',
            warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            passphrase: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>'
        };
        return icons[type] || icons.length;
    }

    // ==========================================================================
    // UI Update Functions
    // ==========================================================================

    function updateStrengthMeter(entropy, strength) {
        const percentages = { weak: 20, fair: 45, good: 70, strong: 100 };
        const percentage = percentages[strength] || 0;

        elements.meterFill.style.width = `${percentage}%`;
        elements.meterFill.dataset.strength = strength;
        elements.meterFill.style.backgroundColor = getComputedStyle(document.documentElement)
            .getPropertyValue(`--color-${strength}`).trim() || 'var(--color-weak)';

        elements.strengthValue.textContent = strength.charAt(0).toUpperCase() + strength.slice(1);
        elements.strengthValue.style.color = getComputedStyle(document.documentElement)
            .getPropertyValue(`--color-${strength}`).trim() || 'var(--color-weak)';

        // Update meter labels
        document.querySelectorAll('.meter-labels .label').forEach(label => {
            label.style.color = 'var(--color-text-muted)';
        });
        const activeLabel = document.querySelector(`.meter-labels .label.${strength}`);
        if (activeLabel) {
            activeLabel.style.color = getComputedStyle(document.documentElement)
                .getPropertyValue(`--color-${strength}`).trim();
        }

        // Show entropy and crack time for non-empty passwords
        if (entropy > 0) {
            elements.entropyInfo.hidden = false;
            elements.crackTime.hidden = false;
            elements.entropyValue.textContent = entropy.toFixed(1);
            elements.crackValue.textContent = formatCrackTime(estimateCrackTime(entropy));
        } else {
            elements.entropyInfo.hidden = true;
            elements.crackTime.hidden = true;
        }
    }

    function updateCriteria(criteria) {
        const items = elements.criteriaList.querySelectorAll('.criterion');

        items.forEach(item => {
            const criterion = item.dataset.criterion;
            const passed = criteria[criterion];

            if (passed) {
                item.dataset.state = 'pass';
            } else {
                item.dataset.state = 'fail';
            }
        });
    }

    function updateSuggestions(suggestions) {
        if (suggestions.length === 0) {
            elements.suggestionsList.innerHTML = `
                <p class="no-suggestions">Enter a password to see personalized suggestions.</p>
            `;
            return;
        }

        elements.suggestionsList.innerHTML = suggestions.map((suggestion, index) => `
            <div class="suggestion-item" style="animation-delay: ${index * 50}ms">
                <div class="suggestion-icon">${suggestion.icon}</div>
                <div class="suggestion-content">
                    <div class="suggestion-title">${escapeHtml(suggestion.title)}</div>
                    <div class="suggestion-desc">${escapeHtml(suggestion.description)}</div>
                </div>
            </div>
        `).join('');

        // Removed auto-scroll - it was pushing the input field out of view
    }

    // ==========================================================================
    // Utility Functions
    // ==========================================================================

    function escapeRegExp(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // ==========================================================================
    // Main Analysis Function
    // ==========================================================================

    function analyzePassword(password) {
        const entropy = calculateEntropy(password);
        const strength = getStrengthLevel(entropy);
        const criteria = checkCriteria(password);
        const suggestions = generateSuggestions(password, criteria);

        updateStrengthMeter(entropy, strength);
        updateCriteria(criteria);
        updateSuggestions(suggestions);
    }

    // ==========================================================================
    // Event Handlers
    // ==========================================================================

    const debouncedAnalyze = debounce(analyzePassword, 100);

    function handleInput(event) {
        const password = event.target.value;
        debouncedAnalyze(password);
    }

    function toggleVisibility() {
        const input = elements.passwordInput;
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        input.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    }

    // ==========================================================================
    // Initialization
    // ==========================================================================

    function init() {
        // Event listeners
        elements.passwordInput.addEventListener('input', handleInput);
        elements.toggleVisibility.addEventListener('click', toggleVisibility);

        // Keyboard support for toggle button
        elements.toggleVisibility.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                toggleVisibility();
            }
        });

        // Initial analysis (empty)
        analyzePassword('');

        // Announce to screen readers that the tool is ready
        console.log('Password Strength Checker initialized');
    }

    // Start when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();