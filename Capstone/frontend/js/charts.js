/**
 * DarkWatch Chart Utility
 * Renders cybersecurity risk distribution charts.
 * Supports Chart.js with pure HTML5 Canvas fallback for offline resilience.
 */

const Charts = {
  instances: {},

  /**
   * Render or update the Dashboard Risk Distribution Doughnut Chart
   */
  renderDashboardRiskChart(canvasId, high, medium, low) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const total = high + medium + low;
    const data = [high, medium, low];
    const labels = ['High Risk', 'Medium Risk', 'Low Risk'];
    const colors = ['#ef4444', '#f59e0b', '#10b981'];

    // If Chart.js is loaded
    if (typeof Chart !== 'undefined') {
      if (this.instances[canvasId]) {
        this.instances[canvasId].destroy();
      }

      const ctx = canvas.getContext('2d');
      this.instances[canvasId] = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: labels,
          datasets: [{
            data: total > 0 ? data : [0, 0, 1],
            backgroundColor: total > 0 ? colors : ['#334155'],
            borderWidth: 2,
            borderColor: '#151f32'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#94a3b8',
                font: { size: 11, family: 'system-ui' },
                padding: 14,
                boxWidth: 12
              }
            },
            tooltip: {
              callbacks: {
                label: function(context) {
                  const val = context.parsed;
                  const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                  return ` ${context.label}: ${val} (${pct}%)`;
                }
              }
            }
          },
          cutout: '68%'
        }
      });
      return;
    }

    // Native Canvas Fallback (100% Offline Capable)
    this.drawFallbackDoughnut(canvas, high, medium, low);
  },

  /**
   * Render or update the Risk Assessment Bar / Distribution Chart
   */
  renderRiskAssessmentChart(canvasId, high, medium, low, factors = {}) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const labels = ['High Severity', 'Medium Severity', 'Low Severity', 'Privileged Accounts', 'Weak Passwords'];
    const data = [
      high,
      medium,
      low,
      factors.privileged_accounts || 0,
      factors.weak_passwords || 0
    ];
    const colors = ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6'];

    if (typeof Chart !== 'undefined') {
      if (this.instances[canvasId]) {
        this.instances[canvasId].destroy();
      }

      const ctx = canvas.getContext('2d');
      this.instances[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [{
            label: 'Detected Records',
            data: data,
            backgroundColor: colors,
            borderRadius: 4,
            borderSkipped: false
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: '#94a3b8', font: { size: 10 } }
            },
            y: {
              beginAtZero: true,
              grid: { color: '#24324d', borderDash: [2, 2] },
              ticks: { color: '#94a3b8', font: { size: 10 }, precision: 0 }
            }
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: '#111827',
              borderColor: '#24324d',
              borderWidth: 1,
              titleColor: '#f1f5f9',
              bodyColor: '#94a3b8'
            }
          }
        }
      });
      return;
    }

    // Native Canvas Fallback
    this.drawFallbackBar(canvas, labels, data, colors);
  },

  /**
   * Fallback Canvas Doughnut implementation
   */
  drawFallbackDoughnut(canvas, high, medium, low) {
    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.parentElement.clientWidth || 240;
    const height = canvas.height = 200;
    ctx.clearRect(0, 0, width, height);

    const total = high + medium + low;
    const centerX = width / 2;
    const centerY = height / 2 - 10;
    const radius = Math.min(centerX, centerY) - 20;
    const innerRadius = radius * 0.65;

    if (total === 0) {
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
      ctx.fillStyle = '#1e293b';
      ctx.fill();
      ctx.beginPath();
      ctx.arc(centerX, centerY, innerRadius, 0, Math.PI * 2);
      ctx.fillStyle = '#151f32';
      ctx.fill();
      return;
    }

    const segments = [
      { val: high, color: '#ef4444', label: 'High' },
      { val: medium, color: '#f59e0b', label: 'Med' },
      { val: low, color: '#10b981', label: 'Low' }
    ];

    let currentAngle = -Math.PI / 2;

    segments.forEach(seg => {
      if (seg.val <= 0) return;
      const sliceAngle = (seg.val / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
      ctx.arc(centerX, centerY, innerRadius, currentAngle + sliceAngle, currentAngle, true);
      ctx.closePath();
      ctx.fillStyle = seg.color;
      ctx.fill();
      currentAngle += sliceAngle;
    });

    // Inner center circle
    ctx.beginPath();
    ctx.arc(centerX, centerY, innerRadius, 0, Math.PI * 2);
    ctx.fillStyle = '#151f32';
    ctx.fill();

    // Center text
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 16px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(`${total}`, centerX, centerY);
  },

  /**
   * Fallback Canvas Bar implementation
   */
  drawFallbackBar(canvas, labels, data, colors) {
    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.parentElement.clientWidth || 300;
    const height = canvas.height = 220;
    ctx.clearRect(0, 0, width, height);

    const maxVal = Math.max(...data, 10);
    const barWidth = Math.max(14, (width - 60) / data.length - 12);
    const paddingLeft = 30;
    const chartHeight = height - 40;

    data.forEach((val, idx) => {
      const barHeight = (val / maxVal) * (chartHeight - 20);
      const x = paddingLeft + idx * (barWidth + 12);
      const y = chartHeight - barHeight;

      ctx.fillStyle = colors[idx] || '#3b82f6';
      ctx.fillRect(x, y, barWidth, barHeight);

      // Label
      ctx.fillStyle = '#94a3b8';
      ctx.font = '9px system-ui';
      ctx.textAlign = 'center';
      const shortLabel = labels[idx].split(' ')[0];
      ctx.fillText(shortLabel, x + barWidth / 2, chartHeight + 14);

      // Value
      ctx.fillStyle = '#ffffff';
      ctx.fillText(val, x + barWidth / 2, y - 4);
    });
  }
};

window.Charts = Charts;
