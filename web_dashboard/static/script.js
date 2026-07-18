/**
 * AIShield V2 — Frontend SPA Script
 * Handles routing, auth, file uploads, history, analytics, and theming.
 */

// ── State ──────────────────────────────────────────────────
let jwtToken = localStorage.getItem('aishield_token') || null;
let currentUser = null;
let currentTab = 'view-scanner';
let charts = {};

// ── Initialization ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initMatrixCanvas();
    bindEvents();
    // Check for OAuth token in URL fragment
    const hash = window.location.hash.substring(1);
    const params = new URLSearchParams(hash);
    if (params.has('token')) {
        jwtToken = params.get('token');
        localStorage.setItem('aishield_token', jwtToken);
        window.location.hash = '';
        showToast('Successfully authenticated via OAuth', 'success');
        fetchUserProfile();
    }
    
    // Check for error in query string
    const queryParams = new URLSearchParams(window.location.search);
    if (queryParams.has('error')) {
        showToast(queryParams.get('error'), 'error');
        window.history.replaceState({}, document.title, window.location.pathname);
    }

    // Check auth on load
    if (jwtToken) {
        fetchUserProfile();
    }
    
    // Load default tab
    switchTab(currentTab);
});

// ── Background Canvas ───────────────────────────────────────
function initMatrixCanvas() {
    const canvas = document.getElementById('bg-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars = '01'.split('');
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = Array.from({length: columns}).fill(1);

    function draw() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        const theme = document.documentElement.getAttribute('data-theme');
        let color = '#3b82f6'; // dark theme primary
        if (theme === 'cyberpunk') color = '#d946ef'; // cyberpunk accent
        if (theme === 'light') color = '#94a3b8'; // light theme muted
        
        ctx.fillStyle = color;
        ctx.font = `${fontSize}px monospace`;

        for (let i = 0; i < drops.length; i++) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }
    setInterval(draw, 33);
    
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}


// ── Tab Routing ─────────────────────────────────────────────
function bindEvents() {
    // Navigation
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const target = e.currentTarget.getAttribute('data-target');
            switchTab(target);
        });
    });

    // Drag & Drop Upload
    const dropZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
    });
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) handleFiles(e.target.files);
    });

    // Keyboard Shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key.toLowerCase() === 'u') {
            e.preventDefault();
            switchTab('view-scanner');
            fileInput.click();
        }
        if (e.key === 'Escape') {
            closeAuthModal();
        }
    });
}

function switchTab(targetId) {
    // Update Nav
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-target') === targetId);
    });
    
    // Update Views
    document.querySelectorAll('.view-section').forEach(sec => {
        sec.classList.remove('active');
    });
    document.getElementById(targetId).classList.add('active');
    currentTab = targetId;

    // Trigger view-specific loads
    if (targetId === 'view-history') loadHistory();
    if (targetId === 'view-analytics') loadAnalytics();
}


// ── Authentication ──────────────────────────────────────────
let authMode = 'login'; // login | register

function openAuthModal(mode = 'login') {
    authMode = mode;
    document.getElementById('auth-modal').classList.remove('hidden');
    switchAuthTab(mode);
}

function closeAuthModal() {
    document.getElementById('auth-modal').classList.add('hidden');
    document.getElementById('auth-error').textContent = '';
}

function switchAuthTab(mode) {
    authMode = mode;
    const loginTab = document.getElementById('tab-login');
    const registerTab = document.getElementById('tab-register');
    const submitBtn = document.getElementById('auth-submit-btn');

    loginTab.classList.toggle('active', mode === 'login');
    registerTab.classList.toggle('active', mode === 'register');
    loginTab.classList.toggle('register-mode', mode === 'register');
    registerTab.classList.toggle('register-mode', mode === 'register');
    submitBtn.textContent = mode === 'login' ? 'Login' : 'Create Account';
    submitBtn.classList.toggle('btn-primary', mode === 'login');
    submitBtn.classList.toggle('btn-success', mode === 'register');
    document.getElementById('auth-error').textContent = '';

    const titleEl = document.getElementById('auth-form-title');
    const subtitleEl = document.getElementById('auth-form-subtitle');
    const confirmEl = document.getElementById('auth-password-confirm');

    if (mode === 'register') {
        titleEl.textContent = 'Create Your Account';
        subtitleEl.textContent = 'Register to save history and access your dashboard.';
        confirmEl.classList.remove('hidden');
        confirmEl.required = true;
    } else {
        titleEl.textContent = 'Welcome Back';
        subtitleEl.textContent = 'Sign in to continue saving your scan history.';
        confirmEl.classList.add('hidden');
        confirmEl.required = false;
        confirmEl.value = '';
    }

    document.getElementById('auth-form').reset();
}

async function handleAuthSubmit(e) {
    e.preventDefault();
    const email = document.getElementById('auth-email').value;
    const password = document.getElementById('auth-password').value;
    const confirmPassword = document.getElementById('auth-password-confirm').value;
    const errorEl = document.getElementById('auth-error');
    
    if (authMode === 'register' && password !== confirmPassword) {
        errorEl.textContent = 'Passwords do not match.';
        return;
    }

    const url = authMode === 'login' ? '/api/auth/login' : '/api/auth/register';
    
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        
        if (!res.ok) throw new Error(data.error || 'Authentication failed');
        
        jwtToken = data.access_token;
        localStorage.setItem('aishield_token', jwtToken);
        currentUser = data.user;
        
        updateUIForUser();
        closeAuthModal();
        showToast(`Welcome back, ${email}`, 'success');
        
    } catch (err) {
        errorEl.textContent = err.message;
    }
}

async function fetchUserProfile() {
    try {
        const res = await fetch('/api/auth/me', {
            headers: { 'Authorization': `Bearer ${jwtToken}` }
        });
        if (res.ok) {
            const data = await res.json();
            currentUser = data.user;
            updateUIForUser();
        } else {
            logout(); // Token expired/invalid
        }
    } catch (err) {
        console.error("Profile fetch error", err);
    }
}

function updateUIForUser() {
    if (currentUser) {
        document.getElementById('login-prompt').classList.add('hidden');
        document.getElementById('user-info').classList.remove('hidden');
        document.getElementById('display-email').textContent = currentUser.email;
        document.querySelector('.avatar').textContent = currentUser.email.charAt(0).toUpperCase();
        
        // Refresh API key field if they have one (would need to fetch it or just indicate they have it)
        // For simplicity, we just enable the features
    }
}

function logout() {
    jwtToken = null;
    currentUser = null;
    localStorage.removeItem('aishield_token');
    
    document.getElementById('user-info').classList.add('hidden');
    document.getElementById('login-prompt').classList.remove('hidden');
    showToast('Logged out successfully', 'info');
    
    if (['view-history', 'view-analytics', 'view-api'].includes(currentTab)) {
        switchTab('view-scanner');
    }
}


// ── Scanning Flow ───────────────────────────────────────────
async function handleFiles(files) {
    if (!files.length) return;
    
    // UI Update to scanning state
    document.getElementById('state-idle').classList.remove('active');
    document.getElementById('state-scanning').classList.add('active');
    document.getElementById('results-placeholder').classList.add('active');
    document.getElementById('results-content').classList.add('hidden');
    
    // Fake progress animation
    const progressBar = document.getElementById('scan-progress-bar');
    const statusText = document.getElementById('scan-status-text');
    let step = 0;
    
    const progressInterval = setInterval(() => {
        step += 1;
        progressBar.style.width = `${step}%`;
        if (step > 20) { document.getElementById('step-1').classList.add('active'); statusText.textContent = "Extracting text and metadata..."; }
        if (step > 40) { document.getElementById('step-2').classList.add('active'); statusText.textContent = "Running pattern detection..."; }
        if (step > 60) { document.getElementById('step-3').classList.add('active'); statusText.textContent = "Analyzing heuristics..."; }
        if (step > 80) { document.getElementById('step-4').classList.add('active'); statusText.textContent = "Checking adversarial bypasses..."; }
        if (step >= 95) clearInterval(progressInterval);
    }, 50);

    // Prepare upload
    const formData = new FormData();
    for (let f of files) formData.append('files[]', f);

    const headers = {};
    if (jwtToken) headers['Authorization'] = `Bearer ${jwtToken}`;

    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: headers,
            body: formData
        });
        const data = await res.json();
        
        clearInterval(progressInterval);
        progressBar.style.width = '100%';
        
        setTimeout(() => {
            // Reset upload zone
            document.getElementById('state-scanning').classList.remove('active');
            document.getElementById('state-idle').classList.add('active');
            progressBar.style.width = '0%';
            document.querySelectorAll('.progress-steps .step').forEach(s => s.classList.remove('active'));
            
            // Render results
            renderScanResult(data.results ? data.results[0] : data);
        }, 500);

    } catch (err) {
        clearInterval(progressInterval);
        showToast(`Scan failed: ${err.message}`, 'error');
        document.getElementById('state-scanning').classList.remove('active');
        document.getElementById('state-idle').classList.add('active');
    }
}

function renderScanResult(data) {
    if (data.error) {
        showToast(data.error, 'error');
        return;
    }
    
    document.getElementById('results-placeholder').classList.remove('active');
    const content = document.getElementById('results-content');
    content.classList.remove('hidden');
    
    // Verdict
    const banner = document.getElementById('verdict-banner');
    const label = document.getElementById('verdict-label');
    const scoreVal = document.getElementById('verdict-score-val');
    
    banner.className = 'verdict-banner ' + (data.verdict === 'BLOCKED' ? 'verdict-blocked' : 'verdict-allowed');
    label.textContent = data.verdict;
    scoreVal.textContent = data.risk_score;
    
    // Stats
    document.getElementById('stat-threats').textContent = data.threat_count || (data.findings ? data.findings.length : 0);
    document.getElementById('stat-time').textContent = data.scan_time_ms + 'ms';
    document.getElementById('stat-pages').textContent = data.total_pages || 1;
    
    // Findings
    const list = document.getElementById('threat-list');
    list.innerHTML = '';
    
    if (!data.findings || data.findings.length === 0) {
        list.innerHTML = '<p class="text-muted text-center p-4">No threats detected.</p>';
    } else {
        data.findings.forEach(f => {
            const card = document.createElement('div');
            card.className = `threat-card severity-${f.severity}`;
            card.innerHTML = `
                <div class="threat-header">
                    <span class="threat-cat">${f.category}</span>
                    <span class="threat-sev">${f.severity}</span>
                </div>
                <p class="threat-desc">${f.description}</p>
                <div class="threat-evidence">${escapeHTML(f.evidence)}</div>
            `;
            list.appendChild(card);
        });
    }
    
    showToast(`Scan complete: ${data.filename}`, 'info');
}


// ── History View ────────────────────────────────────────────
let historyPage = 1;

async function loadHistory() {
    if (!jwtToken) return;
    
    const q = document.getElementById('history-search').value;
    const verdict = document.getElementById('history-filter-verdict').value;
    
    try {
        const res = await fetch(`/api/history?page=${historyPage}&q=${encodeURIComponent(q)}&verdict=${verdict}`, {
            headers: { 'Authorization': `Bearer ${jwtToken}` }
        });
        const data = await res.json();
        
        const tbody = document.getElementById('history-tbody');
        tbody.innerHTML = '';
        
        if (data.scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center p-4">No history found.</td></tr>';
        } else {
            data.scans.forEach(s => {
                const tr = document.createElement('tr');
                const date = new Date(s.created_at).toLocaleString();
                tr.innerHTML = `
                    <td>${date}</td>
                    <td><strong>${s.filename}</strong></td>
                    <td>${s.file_format.toUpperCase()}</td>
                    <td>${s.risk_score}</td>
                    <td><span class="badge-${s.verdict.toLowerCase()}">${s.verdict}</span></td>
                    <td>
                        <button class="btn-secondary btn-small" onclick="downloadReport(${s.id})">JSON</button>
                        <button class="btn-icon" onclick="deleteHistory(${s.id})" title="Delete">🗑️</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
        
        // Pagination
        const pdiv = document.getElementById('history-pagination');
        pdiv.innerHTML = `
            <button class="page-btn" ${!data.has_prev ? 'disabled' : ''} onclick="historyPage--; loadHistory()">Prev</button>
            <span style="line-height: 2rem;">Page ${data.page} of ${data.pages || 1}</span>
            <button class="page-btn" ${!data.has_next ? 'disabled' : ''} onclick="historyPage++; loadHistory()">Next</button>
        `;
        
    } catch (err) {
        showToast('Error loading history', 'error');
    }
}

async function downloadReport(id) {
    window.open(`/api/history/${id}/export?token=${jwtToken}`, '_blank');
}

async function deleteHistory(id) {
    if (!confirm('Delete this scan record?')) return;
    try {
        await fetch(`/api/history/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${jwtToken}` }
        });
        showToast('Record deleted', 'success');
        loadHistory();
    } catch (err) {}
}


// ── Analytics View ──────────────────────────────────────────
async function loadAnalytics() {
    if (!jwtToken) return;
    try {
        // Summary
        const resSum = await fetch('/api/analytics/summary', { headers: { 'Authorization': `Bearer ${jwtToken}` } });
        const summary = await resSum.json();
        
        document.getElementById('analytics-total').textContent = summary.total_scans;
        document.getElementById('analytics-blocked-pct').textContent = summary.blocked_pct + '%';
        document.getElementById('analytics-avg-risk').textContent = summary.avg_risk_score;
        
        // Trends Chart
        const resTrends = await fetch('/api/analytics/trends?days=14', { headers: { 'Authorization': `Bearer ${jwtToken}` } });
        const trends = await resTrends.json();
        
        if (charts.trends) charts.trends.destroy();
        charts.trends = new Chart(document.getElementById('chart-trends'), {
            type: 'bar',
            data: {
                labels: trends.labels,
                datasets: [
                    { label: 'Blocked', data: trends.blocked, backgroundColor: '#ef4444' },
                    { label: 'Allowed', data: trends.allowed, backgroundColor: '#22c55e' }
                ]
            },
            options: { responsive: true, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } } }
        });

        // Categories Chart
        const resCat = await fetch('/api/analytics/categories', { headers: { 'Authorization': `Bearer ${jwtToken}` } });
        const categories = await resCat.json();
        
        if (charts.categories) charts.categories.destroy();
        charts.categories = new Chart(document.getElementById('chart-categories'), {
            type: 'doughnut',
            data: {
                labels: categories.labels,
                datasets: [{
                    data: categories.values,
                    backgroundColor: ['#3b82f6', '#8b5cf6', '#ef4444', '#f59e0b', '#10b981']
                }]
            },
            options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
        });
        
    } catch (err) {
        showToast('Error loading analytics', 'error');
    }
}


// ── API & Playground ────────────────────────────────────────
async function generateApiKey() {
    if (!jwtToken) return openAuthModal();
    try {
        const res = await fetch('/api/auth/apikey', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${jwtToken}` }
        });
        const data = await res.json();
        document.getElementById('api-key-input').value = data.api_key;
        showToast('New API key generated', 'success');
    } catch (err) {}
}

async function revokeApiKey() {
    if (!jwtToken) return;
    try {
        await fetch('/api/auth/apikey', {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${jwtToken}` }
        });
        document.getElementById('api-key-input').value = "***************************";
        showToast('API key revoked', 'info');
    } catch (err) {}
}

async function scanPlaygroundText() {
    const text = document.getElementById('playground-input').value;
    if (!text.trim()) return;
    
    document.getElementById('pg-results-content').innerHTML = '<p class="text-muted">Scanning...</p>';
    
    try {
        const res = await fetch('/api/scan/text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });
        const data = await res.json();
        
        let html = `
            <div class="verdict-banner ${data.verdict === 'BLOCKED' ? 'verdict-blocked' : 'verdict-allowed'} mb-4">
                <span>${data.verdict} (Risk: ${data.risk_score})</span>
            </div>
        `;
        
        if (data.findings && data.findings.length > 0) {
            data.findings.forEach(f => {
                html += `
                    <div class="threat-card severity-${f.severity} mb-2" style="animation:none; opacity:1; transform:none;">
                        <div class="threat-header"><span class="threat-cat">${f.category}</span><span class="threat-sev">${f.severity}</span></div>
                        <p class="threat-desc">${f.description}</p>
                    </div>
                `;
            });
        } else {
            html += '<p class="text-muted">No threats detected.</p>';
        }
        
        document.getElementById('pg-results-content').innerHTML = html;
        
    } catch (err) {
        showToast('Playground error', 'error');
    }
}


// ── Theming & Utils ─────────────────────────────────────────
function initTheme() {
    const saved = localStorage.getItem('aishield_theme') || 'dark';
    setTheme(saved);
}

function setTheme(themeName) {
    document.documentElement.setAttribute('data-theme', themeName);
    localStorage.setItem('aishield_theme', themeName);
    
    document.querySelectorAll('.theme-btn').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-theme') === themeName);
    });
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const icon = type === 'success' ? '✅' : (type === 'error' ? '❌' : 'ℹ️');
    
    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function escapeHTML(str) {
    return str.replace(/[&<>'"]/g, 
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        }[tag] || tag)
    );
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => { clearTimeout(timeout); func(...args); };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
