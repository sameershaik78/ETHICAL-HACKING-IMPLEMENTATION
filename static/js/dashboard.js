document.addEventListener('DOMContentLoaded', function() {
  fetch('/api/dashboard/stats')
    .then(response => response.json())
    .then(data => {
      // 1. Ingestion Trend Chart
      const trendCtx = document.getElementById('trendChart');
      if (trendCtx) {
        new Chart(trendCtx, {
          type: 'line',
          data: {
            labels: data.trends.labels,
            datasets: [{
              label: 'Alert Volume',
              data: data.trends.data,
              borderColor: '#06b6d4',
              backgroundColor: 'rgba(6, 182, 212, 0.1)',
              borderWidth: 2,
              fill: true,
              tension: 0.35,
              pointBackgroundColor: '#06b6d4',
              pointRadius: 4
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false }
            },
            scales: {
              x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8' } },
              y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8' } }
            }
          }
        });
      }

      // 2. Priority Donut Chart
      const priorityCtx = document.getElementById('priorityChart');
      if (priorityCtx) {
        new Chart(priorityCtx, {
          type: 'doughnut',
          data: {
            labels: data.priority.labels,
            datasets: [{
              data: data.priority.data,
              backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'],
              borderWidth: 2,
              borderColor: '#121b2f'
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'bottom',
                labels: { color: '#94a3b8', font: { size: 11 }, boxWidth: 12 }
              }
            },
            cutout: '70%'
          }
        });
      }

      // 3. Attack Categories Bar Chart
      const catCtx = document.getElementById('categoryChart');
      if (catCtx) {
        new Chart(catCtx, {
          type: 'bar',
          data: {
            labels: data.categories.labels,
            datasets: [{
              label: 'Alerts',
              data: data.categories.data,
              backgroundColor: 'rgba(59, 130, 246, 0.6)',
              borderColor: '#3b82f6',
              borderWidth: 1,
              borderRadius: 4
            }]
          },
          options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8' } },
              y: { grid: { display: false }, ticks: { color: '#f1f5f9' } }
            }
          }
        });
      }

      // 4. MITRE Tactics Radar Chart
      const mitreCtx = document.getElementById('mitreChart');
      if (mitreCtx) {
        new Chart(mitreCtx, {
          type: 'polarArea',
          data: {
            labels: data.mitre.labels,
            datasets: [{
              data: data.mitre.data,
              backgroundColor: [
                'rgba(239, 68, 68, 0.6)',
                'rgba(245, 158, 11, 0.6)',
                'rgba(6, 182, 212, 0.6)',
                'rgba(99, 102, 241, 0.6)',
                'rgba(16, 185, 129, 0.6)',
                'rgba(236, 72, 153, 0.6)'
              ],
              borderColor: '#121b2f',
              borderWidth: 1
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'right',
                labels: { color: '#94a3b8', font: { size: 10 }, boxWidth: 10 }
              }
            },
            scales: {
              r: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { display: false } }
            }
          }
        });
      }
    });
});
