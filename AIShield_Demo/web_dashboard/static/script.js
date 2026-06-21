/**
 * AIShield Dashboard — Client-Side Logic
 * ========================================
 * Handles PDF upload (drag-and-drop + click), scan API calls,
 * animated result rendering, risk gauge updates, and scan history.
 */

(function () {
    'use strict';

    // ═══════════════════════════════════════════════════════════
    //  DOM References
    // ═══════════════════════════════════════════════════════════

    const uploadZone       = document.getElementById('upload-zone');
    const uploadIdle       = document.getElementById('upload-idle');
    const uploadScanning   = document.getElementById('upload-scanning');
    const scanStatusText   = document.getElementById('scan-status-text');
    const fileInput        = document.getElementById('file-input');
    const statusBadge      = document.getElementById('status-badge');
    const historyList      = document.getElementById('history-list');

    const resultsPlaceholder = document.getElementById('results-placeholder');
    const resultsContent     = document.getElementById('results-content');

    const verdictBanner    = document.getElementById('verdict-banner');
    const verdictIcon      = document.getElementById('verdict-icon');
    const verdictLabel     = document.getElementById('verdict-label');
    const verdictDesc      = document.getElementById('verdict-desc');

    const riskRingFill     = document.getElementById('risk-ring-fill');
    const riskValue        = document.getElementById('risk-value');
    const riskGradStart    = document.getElementById('risk-grad-start');
    const riskGradEnd      = document.getElementById('risk-grad-end');
    const statPages        = document.getElementById('stat-pages');
    const statChars        = document.getElementById('stat-chars');
    const statTime         = document.getElementById('stat-time');

    const threatsTitle     = document.getElementById('threats-title');
    const threatsList      = document.getElementById('threats-list');

    // ═══════════════════════════════════════════════════════════
    //  Scan History
    // ═══════════════════════════════════════════════════════════

    const scanHistory = [];

    function addToHistory(result) {
        scanHistory.unshift(result);
        renderHistory();
    }

    function renderHistory() {
        historyList.innerHTML = '';
        if (scanHistory.length === 0) {
            historyList.innerHTML = '<li class="history-empty">No scans yet</li>';
            return;
        }

        scanHistory.forEach(function (result, idx) {
            const li = document.createElement('li');
            li.className = 'history-item';
            li.style.animationDelay = (idx * 0.05) + 's';

            const isBlocked = result.verdict === 'BLOCKED';
            li.innerHTML =
                '<div class="history-item-left">' +
                    '<span class="history-item-icon">' + (isBlocked ? '🚨' : '✅') + '</span>' +
                    '<span class="history-item-name">' + escapeHtml(result.filename) + '</span>' +
                '</div>' +
                '<span class="history-item-badge ' + (isBlocked ? 'blocked' : 'allowed') + '">' +
                    result.verdict +
                '</span>';

            li.addEventListener('click', function () {
                displayResults(result);
            });

            historyList.appendChild(li);
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  Upload Handling
    // ═══════════════════════════════════════════════════════════

    // Click to open file picker
    uploadZone.addEventListener('click', function () {
        fileInput.click();
    });

    fileInput.addEventListener('change', function () {
        if (fileInput.files.length > 0) {
            handleFile(fileInput.files[0]);
        }
    });

    // Drag & Drop
    uploadZone.addEventListener('dragenter', function (e) {
        e.preventDefault();
        uploadZone.classList.add('drag-over');
    });

    uploadZone.addEventListener('dragover', function (e) {
        e.preventDefault();
        uploadZone.classList.add('drag-over');
    });

    uploadZone.addEventListener('dragleave', function (e) {
        e.preventDefault();
        uploadZone.classList.remove('drag-over');
    });

    uploadZone.addEventListener('drop', function (e) {
        e.preventDefault();
        uploadZone.classList.remove('drag-over');

        var files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });

    // ═══════════════════════════════════════════════════════════
    //  Scan Flow
    // ═══════════════════════════════════════════════════════════

    var scanMessages = [
        'Extracting text layers...',
        'Scanning for injection patterns...',
        'Checking exfiltration URLs...',
        'Detecting zero-width Unicode...',
        'Inspecting PDF metadata...',
        'Running heuristic analysis...',
        'Calculating risk score...',
    ];

    function handleFile(file) {
        if (!file.name.toLowerCase().endsWith('.pdf')) {
            showError('Only PDF files are supported.');
            return;
        }

        startScanAnimation();

        var formData = new FormData();
        formData.append('file', file);

        // Cycle through status messages during scan
        var msgIndex = 0;
        var msgInterval = setInterval(function () {
            msgIndex = (msgIndex + 1) % scanMessages.length;
            scanStatusText.textContent = scanMessages[msgIndex];
        }, 600);

        fetch('/api/scan', {
            method: 'POST',
            body: formData,
        })
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            clearInterval(msgInterval);

            if (data.error) {
                stopScanAnimation();
                showError(data.error);
                return;
            }

            stopScanAnimation();
            addToHistory(data);
            displayResults(data);
        })
        .catch(function (err) {
            clearInterval(msgInterval);
            stopScanAnimation();
            showError('Scan failed: ' + err.message);
        });
    }

    function startScanAnimation() {
        uploadIdle.style.display = 'none';
        uploadScanning.style.display = 'flex';
        uploadZone.style.pointerEvents = 'none';
        scanStatusText.textContent = scanMessages[0];

        statusBadge.className = 'status-badge scanning';
        statusBadge.innerHTML = '<span class="status-dot"></span>Scanning...';
    }

    function stopScanAnimation() {
        uploadIdle.style.display = 'flex';
        uploadScanning.style.display = 'none';
        uploadZone.style.pointerEvents = 'auto';
        fileInput.value = '';
    }

    // ═══════════════════════════════════════════════════════════
    //  Render Results
    // ═══════════════════════════════════════════════════════════

    function displayResults(data) {
        resultsPlaceholder.style.display = 'none';
        resultsContent.style.display = 'block';

        // Force re-trigger animation
        resultsContent.style.animation = 'none';
        void resultsContent.offsetHeight; // reflow
        resultsContent.style.animation = '';

        var isBlocked = data.verdict === 'BLOCKED';

        // Update status badge
        statusBadge.className = 'status-badge ' + (isBlocked ? 'blocked' : 'allowed');
        statusBadge.innerHTML =
            '<span class="status-dot"></span>' +
            (isBlocked ? 'Threat Detected' : 'Clean');

        // Verdict banner
        verdictBanner.className = 'verdict-banner ' + (isBlocked ? 'blocked' : 'allowed');
        verdictBanner.style.animation = 'none';
        void verdictBanner.offsetHeight;
        verdictBanner.style.animation = '';

        verdictIcon.textContent = isBlocked ? '🚨' : '✅';
        verdictLabel.textContent = isBlocked ? 'BLOCKED' : 'ALLOWED';
        verdictDesc.textContent = isBlocked
            ? 'Prompt injection threats detected — do not upload this file to AI'
            : 'No threats detected — safe to upload to AI assistants';

        // Risk score gauge
        animateRiskGauge(data.risk_score);

        // Stats
        statPages.textContent = data.total_pages;
        statChars.textContent = formatNumber(data.text_length);
        statTime.textContent = data.scan_time_ms.toFixed(1);

        // Threats
        renderThreats(data.findings, data.threat_summary);
    }

    function animateRiskGauge(score) {
        var circumference = 2 * Math.PI * 42; // r=42
        var target = (score / 100) * circumference;

        // Color based on score
        var color;
        if (score >= 70) {
            color = '#ef4444';
        } else if (score >= 30) {
            color = '#f59e0b';
        } else {
            color = '#22c55e';
        }

        riskGradStart.setAttribute('stop-color', color);
        riskGradEnd.setAttribute('stop-color', color);
        riskValue.style.color = color;

        // Animate the ring fill
        riskRingFill.style.transition = 'stroke-dasharray 1s cubic-bezier(0.4, 0, 0.2, 1)';
        riskRingFill.setAttribute('stroke-dasharray', '0 ' + circumference);

        // Force reflow before setting final value
        void riskRingFill.getBoundingClientRect();

        requestAnimationFrame(function () {
            riskRingFill.setAttribute('stroke-dasharray', target + ' ' + circumference);
        });

        // Animate the number
        animateNumber(riskValue, 0, score, 800);
    }

    function animateNumber(el, from, to, duration) {
        var start = performance.now();
        function tick(now) {
            var elapsed = now - start;
            var progress = Math.min(elapsed / duration, 1);
            // Ease out cubic
            var eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.round(from + (to - from) * eased);
            if (progress < 1) {
                requestAnimationFrame(tick);
            }
        }
        requestAnimationFrame(tick);
    }

    function renderThreats(findings, summary) {
        threatsList.innerHTML = '';

        if (!findings || findings.length === 0) {
            threatsTitle.textContent = 'Scan Complete';
            threatsList.innerHTML =
                '<div class="no-threats-msg">' +
                    '<span class="check-icon">✅</span>' +
                    '<span>No threats detected. Document is clean.</span>' +
                '</div>';
            return;
        }

        var totalThreats = findings.length;
        threatsTitle.textContent = 'Threats Detected (' + totalThreats + ')';

        var severityIcons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
        };

        findings.forEach(function (finding, idx) {
            var card = document.createElement('div');
            card.className = 'threat-card severity-' + finding.severity;
            card.style.animationDelay = (idx * 0.08) + 's';

            var icon = severityIcons[finding.severity] || '⚪';
            var pageInfo = finding.page ? ('Page ' + finding.page) : 'Document-level';

            card.innerHTML =
                '<div class="threat-header">' +
                    '<span class="threat-severity-badge ' + finding.severity + '">' +
                        icon + ' ' + finding.severity +
                    '</span>' +
                    '<span class="threat-description">' + escapeHtml(finding.description) + '</span>' +
                '</div>' +
                '<div class="threat-meta">' +
                    '<span>📁 ' + escapeHtml(finding.category) + '</span>' +
                    '<span>📄 ' + pageInfo + '</span>' +
                '</div>' +
                '<div class="threat-evidence">' + escapeHtml(finding.evidence) + '</div>';

            threatsList.appendChild(card);
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  Utilities
    // ═══════════════════════════════════════════════════════════

    function escapeHtml(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    function formatNumber(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return String(num);
    }

    function showError(message) {
        // Quick inline error display
        resultsPlaceholder.style.display = 'none';
        resultsContent.style.display = 'block';
        resultsContent.innerHTML =
            '<div class="verdict-banner blocked">' +
                '<span class="verdict-icon">⚠️</span>' +
                '<div class="verdict-text">' +
                    '<span class="verdict-label" style="color: var(--warning);">Error</span>' +
                    '<span class="verdict-desc">' + escapeHtml(message) + '</span>' +
                '</div>' +
            '</div>';

        statusBadge.className = 'status-badge';
        statusBadge.innerHTML = '<span class="status-dot"></span>Ready';
    }

})();
