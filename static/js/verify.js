// Dashboard JavaScript
class Dashboard {
    constructor() {
        this.charts = {};
        this.init();
    }

    async init() {
        try {
            await this.loadStats();
            this.initCharts();
            this.startAutoRefresh();
        } catch (error) {
            console.error('Dashboard initialization failed:', error);
            this.showError('Failed to load dashboard data');
        }
    }

    async loadStats() {
        try {
            const response = await fetch('/stats');
            if (!response.ok) {
                throw new Error('Failed to fetch stats');
            }
            
            const data = await response.json();
            this.updateStats(data);
            this.hideLoading();
            
        } catch (error) {
            console.error('Error loading stats:', error);
            throw error;
        }
    }

    updateStats(data) {
        // Update device stats
        document.getElementById('totalDevices').textContent = data.devices.total;
        document.getElementById('authenticDevices').textContent = data.devices.authentic;
        document.getElementById('blockchainDevices').textContent = data.devices.blockchain;

        // Update verification stats
        document.getElementById('totalVerifications').textContent = data.verifications.total;
        document.getElementById('successRate').textContent = data.verifications.success_rate + '%';
        document.getElementById('avgResponse').textContent = data.verifications.average_response_time + 'ms';

        // Update ownership stats
        document.getElementById('totalTransfers').textContent = data.ownership.total_transfers;

        // Update manufacturer stats
        document.getElementById('totalManufacturers').textContent = data.manufacturers.total;
        document.getElementById('verifiedManufacturers').textContent = data.manufacturers.verified;
        document.getElementById('verificationRate').textContent = data.manufacturers.verification_rate + '%';

        // Update performance metrics
        document.getElementById('avgResponseTime').textContent = data.verifications.average_response_time + 'ms';
        document.getElementById('authenticityAccuracy').textContent = data.devices.authenticity_rate + '%';

        // Update last updated timestamp
        const lastUpdated = new Date(data.last_updated).toLocaleString();
        document.getElementById('lastUpdated').textContent = lastUpdated;

        // Update performance badge
        this.updatePerformanceBadge(data.verifications.average_response_time);

        // Update chart data
        this.updateChartData(data);
    }

    updatePerformanceBadge(responseTime) {
        const badge = document.getElementById('performanceBadge');
        
        if (responseTime < 100) {
            badge.className = 'performance-badge badge-excellent';
            badge.textContent = 'Excellent';
        } else if (responseTime < 500) {
            badge.className = 'performance-badge badge-good';
            badge.textContent = 'Good';
        } else {
            badge.className = 'performance-badge badge-poor';
            badge.textContent = 'Needs Improvement';
        }
    }

    initCharts() {
        this.initAuthStatusChart();
        this.initVerificationTrendsChart();
    }

    initAuthStatusChart() {
        const ctx = document.getElementById('authStatusChart').getContext('2d');
        
        this.charts.authStatus = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Authentic', 'Counterfeit', 'Pending'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: [
                        '#28a745',
                        '#dc3545',
                        '#ffc107'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    }
                }
            }
        });
    }

    initVerificationTrendsChart() {
        const ctx = document.getElementById('verificationTrendsChart').getContext('2d');
        
        // Generate sample data for the last 7 days
        const labels = [];
        const successData = [];
        const failureData = [];
        
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            labels.push(date.toLocaleDateString('en-US', { weekday: 'short' }));
            successData.push(Math.floor(Math.random() * 50) + 10);
            failureData.push(Math.floor(Math.random() * 10) + 1);
        }

        this.charts.verificationTrends = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Successful Verifications',
                    data: successData,
                    borderColor: '#28a745',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    tension: 0.4,
                    fill: true
                }, {
                    label: 'Failed Verifications',
                    data: failureData,
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    }
                },
                scales: {
                    x: {
                        display: true,
                        title: {
                            display: true,
                            text: 'Days'
                        }
                    },
                    y: {
                        display: true,
                        title: {
                            display: true,
                            text: 'Verifications'
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    updateChartData(data) {
        // Update authentication status chart
        if (this.charts.authStatus) {
            const total = data.devices.total;
            const authentic = data.devices.authentic;
            const counterfeit = total - authentic;
            
            this.charts.authStatus.data.datasets[0].data = [authentic, counterfeit, 0];
            this.charts.authStatus.update('none');
        }

        // Verification trends chart updates with simulated data
        // In a real application, you would fetch historical data from your API
    }

    hideLoading() {
        document.getElementById('loadingState').style.display = 'none';
        document.getElementById('statsContainer').style.display = 'block';
    }

    showError(message) {
        document.getElementById('loadingState').innerHTML = `
            <div class="alert alert-danger" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                ${message}
            </div>
        `;
    }

    startAutoRefresh() {
        // Refresh dashboard every 5 minutes
        setInterval(() => {
            this.loadStats();
        }, 5 * 60 * 1000);
    }

    // Utility methods for number formatting
    formatNumber(num) {
        if (num >= 1000000) {
            return (num / 1000000).toFixed(1) + 'M';
        } else if (num >= 1000) {
            return (num / 1000).toFixed(1) + 'K';
        }
        return num.toString();
    }

    formatResponseTime(time) {
        if (time < 1000) {
            return time.toFixed(0) + 'ms';
        } else {
            return (time / 1000).toFixed(1) + 's';
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    new Dashboard();
});

// Add some interactive features
document.addEventListener('DOMContentLoaded', function() {
    // Add click handlers for stats cards to show more details
    document.querySelectorAll('.stats-card').forEach(card => {
        card.addEventListener('click', function() {
            this.style.transform = 'scale(0.95)';
            setTimeout(() => {
                this.style.transform = 'translateY(-5px)';
            }, 100);
        });
    });

    // Add refresh button functionality
    const refreshButton = document.createElement('button');
    refreshButton.className = 'btn btn-outline-light btn-sm position-fixed';
    refreshButton.style.bottom = '20px';
    refreshButton.style.right = '20px';
    refreshButton.style.zIndex = '1000';
    refreshButton.innerHTML = '<i class="fas fa-sync-alt me-2"></i>Refresh';
    refreshButton.onclick = () => {
        location.reload();
    };
    document.body.appendChild(refreshButton);
});