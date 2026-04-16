/**
 * Cyber Attack Detection Dashboard
 * Main JavaScript file for SOC dashboard functionality
 */

// Global variables
let trafficChart, attackChart, timelineChart, protocolChart;
let map;
let updateInterval;
let isRefreshing = false;

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Initializing SOC Dashboard...');
    
    // Initialize charts
    initializeCharts();
    
    // Initialize map
    initializeMap();
    
    // Load initial data
    refreshDashboard();
    
    // Set up auto-refresh (every 10 seconds)
    updateInterval = setInterval(refreshDashboard, 10000);
    
    // Set up event listeners
    setupEventListeners();
});

/**
 * Initialize all charts
 */
function initializeCharts() {
    // Traffic Chart
    const trafficCtx = document.getElementById('trafficChart')?.getContext('2d');
    if (trafficCtx) {
        trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Normal Traffic',
                        data: [],
                        borderColor: '#00d68f',
                        backgroundColor: 'rgba(0, 214, 143, 0.1)',
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'Attack Traffic',
                        data: [],
                        borderColor: '#ff4757',
                        backgroundColor: 'rgba(255, 71, 87, 0.1)',
                        tension: 0.4,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#b8c0d0' }
                    }
                },
                scales: {
                    y: {
                        grid: { color: '#2a2f42' },
                        ticks: { color: '#b8c0d0' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#b8c0d0' }
                    }
                }
            }
        });
    }
    
    // Attack Distribution Chart
    const attackCtx = document.getElementById('attackChart')?.getContext('2d');
    if (attackCtx) {
        attackChart = new Chart(attackCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#b8c0d0' }
                    }
                },
                cutout: '60%'
            }
        });
    }
    
    // Timeline Chart
    const timelineCtx = document.getElementById('timelineChart')?.getContext('2d');
    if (timelineCtx) {
        timelineChart = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'DoS Attacks',
                        data: [],
                        borderColor: '#ef4444',
                        tension: 0.4
                    },
                    {
                        label: 'Probe Attacks',
                        data: [],
                        borderColor: '#f59e0b',
                        tension: 0.4
                    },
                    {
                        label: 'R2L Attacks',
                        data: [],
                        borderColor: '#8b5cf6',
                        tension: 0.4
                    },
                    {
                        label: 'U2R Attacks',
                        data: [],
                        borderColor: '#ec4899',
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#b8c0d0' }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: '#2a2f42' },
                        ticks: { color: '#b8c0d0' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#b8c0d0' }
                    }
                }
            }
        });
    }
    
    // Protocol Chart
    const protocolCtx = document.getElementById('protocolChart')?.getContext('2d');
    if (protocolCtx) {
        protocolChart = new Chart(protocolCtx, {
            type: 'pie',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: ['#3b82f6', '#f59e0b', '#10b981', '#8b5cf6'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#b8c0d0' }
                    }
                }
            }
        });
    }
}

/**
 * Initialize Leaflet map
 */
function initializeMap() {
    if (document.getElementById('attack-map')) {
        map = L.map('attack-map').setView([20, 0], 2);
        
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
        }).addTo(map);
    }
}

/**
 * Refresh all dashboard data
 */
function refreshDashboard() {
    if (isRefreshing) return;
    isRefreshing = true;
    
    Promise.all([
        fetchStats(),
        fetchTrafficData(),
        fetchAttackDistribution(),
        fetchAlerts(),
        fetchTopAttackers(),
        fetchProtocolAnalysis(),
        fetchAnomalies(),
        fetchSecurityLogs()
    ]).finally(() => {
        isRefreshing = false;
    });
}

/**
 * Fetch and update statistics
 */
function fetchStats() {
    return fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                document.getElementById('total-requests').textContent = data.total_requests.toLocaleString();
                document.getElementById('detected-attacks').textContent = data.detected_attacks;
                document.getElementById('high-risk').textContent = data.active_threats;
                document.getElementById('active-connections').textContent = data.active_connections;
                
                // Update health indicators
                document.querySelector('.progress').style.width = data.network_health + '%';
                document.querySelector('.progress').textContent = data.network_health + '%';
                
                const threatBadge = document.querySelector('.threat-badge');
                threatBadge.textContent = data.threat_level;
                threatBadge.className = 'threat-badge ' + data.threat_level.toLowerCase();
                
                document.querySelector('.risk-value').textContent = data.predicted_risk + '%';
            }
        })
        .catch(error => console.error('Error fetching stats:', error));
}

/**
 * Fetch and update traffic data
 */
function fetchTrafficData() {
    return fetch('/api/traffic')
        .then(response => response.json())
        .then(data => {
            if (trafficChart && data.labels) {
                trafficChart.data.labels = data.labels;
                trafficChart.data.datasets[0].data = data.normal;
                trafficChart.data.datasets[1].data = data.attacks;
                trafficChart.update();
            }
        })
        .catch(error => console.error('Error fetching traffic data:', error));
}

/**
 * Fetch and update attack distribution
 */
function fetchAttackDistribution() {
    return fetch('/api/attack-distribution')
        .then(response => response.json())
        .then(data => {
            if (attackChart) {
                attackChart.data.labels = data.labels;
                attackChart.data.datasets[0].data = data.values;
                attackChart.data.datasets[0].backgroundColor = data.colors;
                attackChart.update();
            }
        })
        .catch(error => console.error('Error fetching attack distribution:', error));
}

/**
 * Fetch and update alerts
 */
function fetchAlerts() {
    return fetch('/api/alerts')
        .then(response => response.json())
        .then(alerts => {
            const alertsList = document.getElementById('alerts-list');
            if (alertsList) {
                alertsList.innerHTML = '';
                alerts.forEach(alert => {
                    const alertEl = document.createElement('div');
                    alertEl.className = `alert-item ${alert.risk_level.toLowerCase()}`;
                    alertEl.innerHTML = `
                        <div class="alert-time">${alert.timestamp}</div>
                        <div class="alert-details">
                            <span class="alert-type">${alert.attack_type.toUpperCase()}</span>
                            <span class="alert-risk" style="background: ${alert.color}20; color: ${alert.color}">
                                ${alert.risk_level}
                            </span>
                        </div>
                        <div style="font-size: 12px; color: #6c7a96; margin-top: 5px;">
                            IP: ${alert.source_ip} | Confidence: ${(alert.confidence * 100).toFixed(1)}%
                        </div>
                    `;
                    alertsList.appendChild(alertEl);
                });
            }
        })
        .catch(error => console.error('Error fetching alerts:', error));
}

/**
 * Fetch and update top attackers
 */
function fetchTopAttackers() {
    return fetch('/api/top-attackers')
        .then(response => response.json())
        .then(attackers => {
            const attackersList = document.querySelector('.attackers-list');
            if (attackersList) {
                attackersList.innerHTML = '';
                attackers.forEach(attacker => {
                    const attackerEl = document.createElement('div');
                    attackerEl.className = 'attacker-item';
                    attackerEl.innerHTML = `
                        <span class="attacker-ip">${attacker.ip}</span>
                        <span class="attacker-count">${attacker.count} attacks</span>
                    `;
                    attackersList.appendChild(attackerEl);
                });
            }
        })
        .catch(error => console.error('Error fetching top attackers:', error));
}

/**
 * Fetch and update protocol analysis
 */
function fetchProtocolAnalysis() {
    return fetch('/api/protocol-analysis')
        .then(response => response.json())
        .then(data => {
            if (protocolChart) {
                protocolChart.data.labels = data.labels;
                protocolChart.data.datasets[0].data = data.values;
                protocolChart.data.datasets[0].backgroundColor = data.colors;
                protocolChart.update();
            }
        })
        .catch(error => console.error('Error fetching protocol analysis:', error));
}

/**
 * Fetch and update anomalies
 */
function fetchAnomalies() {
    return fetch('/api/anomalies')
        .then(response => response.json())
        .then(anomalies => {
            const anomaliesList = document.getElementById('anomalies-list');
            if (anomaliesList) {
                anomaliesList.innerHTML = '';
                anomalies.forEach(anomaly => {
                    const anomalyEl = document.createElement('div');
                    anomalyEl.className = 'anomaly-item';
                    anomalyEl.innerHTML = `
                        <div>
                            <div style="font-weight: 600;">${anomaly.type}</div>
                            <div style="font-size: 12px; color: #6c7a96;">${anomaly.time}</div>
                        </div>
                        <div style="color: ${anomaly.severity === 'HIGH' ? '#ff4757' : '#f59e0b'}">
                            ${anomaly.value}
                        </div>
                    `;
                    anomaliesList.appendChild(anomalyEl);
                });
            }
        })
        .catch(error => console.error('Error fetching anomalies:', error));
}

/**
 * Fetch and update security logs
 */
function fetchSecurityLogs() {
    return fetch('/api/security-logs')
        .then(response => response.json())
        .then(logs => {
            const tbody = document.querySelector('#logs-table tbody');
            if (tbody) {
                tbody.innerHTML = '';
                logs.forEach(log => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${log.timestamp || log.time || ''}</td>
                        <td>${log.src_ip || log.source_ip || ''}</td>
                        <td>${log.protocol || ''}</td>
                        <td>${log.attack_type || ''}</td>
                        <td>${log.confidence || ''}</td>
                        <td><span class="risk-badge ${(log.risk_level || log.risk || '').toLowerCase()}">
                            ${log.risk_level || log.risk || ''}
                        </span></td>
                    `;
                    tbody.appendChild(row);
                });
            }
        })
        .catch(error => console.error('Error fetching security logs:', error));
}

/**
 * Make prediction
 */
function predictAttack() {
    const formData = {
        src_ip: document.getElementById('src-ip').value,
        duration: document.getElementById('duration').value,
        protocol: document.getElementById('protocol').value,
        service: document.getElementById('service').value,
        src_bytes: document.getElementById('src-bytes').value,
        dst_bytes: document.getElementById('dst-bytes').value,
        flag: document.getElementById('flag').value,
        count: document.getElementById('count')?.value || 1,
        srv_count: document.getElementById('srv-count')?.value || 1
    };
    
    // Show loading
    const resultDiv = document.getElementById('prediction-result');
    resultDiv.innerHTML = '<div class="loading"></div> Analyzing...';
    resultDiv.style.display = 'block';
    
    fetch('/api/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const riskClass = data.risk_level.toLowerCase();
            resultDiv.className = `prediction-result ${riskClass}`;
            resultDiv.innerHTML = `
                <h4>Analysis Complete</h4>
                <div class="prediction-details">
                    <div>
                        <div class="label">Attack Type</div>
                        <div class="value">${data.attack_type.toUpperCase()}</div>
                    </div>
                    <div>
                        <div class="label">Confidence</div>
                        <div class="value">${data.confidence}%</div>
                    </div>
                    <div>
                        <div class="label">Risk Level</div>
                        <div class="value">${data.risk_level}</div>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 10px; font-size: 12px; color: #6c7a96;">
                    Detected at ${data.timestamp}
                </div>
            `;
        } else {
            resultDiv.className = 'prediction-result';
            resultDiv.innerHTML = `<div style="color: #ff4757;">Error: ${data.error}</div>`;
        }
    })
    .catch(error => {
        resultDiv.className = 'prediction-result';
        resultDiv.innerHTML = `<div style="color: #ff4757;">Error: ${error.message}</div>`;
    });
}

/**
 * Export report
 */
function exportReport() {
    window.location.href = '/export-report';
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-menu li').forEach(item => {
        item.addEventListener('click', function() {
            document.querySelectorAll('.nav-menu li').forEach(li => li.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // Manual refresh button (if exists)
    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshDashboard);
    }
}

/**
 * Clean up on page unload
 */
window.addEventListener('beforeunload', function() {
    if (updateInterval) {
        clearInterval(updateInterval);
    }
});