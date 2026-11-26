/**
 * DarkWatch Application Logic
 * Coordinates UI navigation, data fetching, file analysis, visualization,
 * administrator authentication, and notification management.
 */

document.addEventListener('DOMContentLoaded', () => {
  App.init();
});

const App = {
  activeView: 'dashboard',
  selectedFile: null,
  currentUser: null,
  notifPollTimer: null,
  recordsState: {
    page: 1,
    per_page: 15,
    search: '',
    risk: 'all',
    status: 'all',
    duplicates: false,
    totalPages: 1
  },
  pendingDeleteRecordId: null,

  async init() {
    this.bindTheme();
    this.bindAuth();
    this.bindNotifications();
    this.bindNavigation();
    this.bindAnalysisUpload();
    this.bindLeakRecordsControls();
    this.bindSettingsControls();
    this.checkSystemHealth();

    // Verify session authentication on startup
    await this.verifyAuthentication();
  },

  /**
   * ------------------------------------------------------------------------
   * Authentication & Session Management
   * ------------------------------------------------------------------------
   */
  bindAuth() {
    const loginForm = document.getElementById('login-form');
    const btnTogglePw = document.getElementById('btn-toggle-pw');
    const pwInput = document.getElementById('login-password');
    const pwIcon = document.getElementById('pw-icon-eye');
    const btnLogout = document.getElementById('btn-logout');
    const userProfileBtn = document.getElementById('user-profile-btn');
    const userDropdown = document.getElementById('user-profile-dropdown');

    // Show/Hide password toggle
    if (btnTogglePw && pwInput) {
      btnTogglePw.addEventListener('click', () => {
        const isPw = pwInput.type === 'password';
        pwInput.type = isPw ? 'text' : 'password';
        if (isPw) {
          // Eye Off icon
          pwIcon.innerHTML = `
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
            <line x1="1" y1="1" x2="23" y2="23"></line>
          `;
        } else {
          // Eye Open icon
          pwIcon.innerHTML = `
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
            <circle cx="12" cy="12" r="3"></circle>
          `;
        }
      });
    }

    // Login Form Submission
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const usernameInput = document.getElementById('login-username');
        const username = usernameInput.value.trim();
        const password = pwInput.value;
        const alertBox = document.getElementById('login-alert');
        const alertText = document.getElementById('login-alert-text');
        const btnSubmit = document.getElementById('btn-login');
        const btnText = document.getElementById('btn-login-text');

        alertBox.classList.remove('visible');
        btnSubmit.disabled = true;
        btnText.textContent = 'Verifying Credentials...';

        try {
          const res = await Api.login(username, password);
          if (res.success) {
            this.currentUser = res.user;
            this.hideLogin();
            this.updateUserUI(res.user);
            this.showToast('Login successful. Welcome back, Administrator.', 'success');
            
            // Navigate to Dashboard
            this.navigateTo('dashboard');
            this.loadNotifications();
            this.startNotificationPolling();
          }
        } catch (err) {
          alertText.textContent = err.message || 'Invalid username or password.';
          alertBox.classList.add('visible');
          // Refresh notifications in case failed login notification was stored
          this.loadNotifications();
        } finally {
          btnSubmit.disabled = false;
          btnText.textContent = 'Sign In';
        }
      });
    }

    // User Profile Dropdown Toggle
    if (userProfileBtn && userDropdown) {
      userProfileBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        // Close notifications dropdown if open
        const notifDropdown = document.getElementById('notifications-dropdown');
        if (notifDropdown) notifDropdown.classList.remove('open');
        userDropdown.classList.toggle('open');
      });
    }

    // Logout
    if (btnLogout) {
      btnLogout.addEventListener('click', async () => {
        if (userDropdown) userDropdown.classList.remove('open');
        await Api.logout();
        this.currentUser = null;
        this.stopNotificationPolling();
        this.showLogin();
        this.showToast('Logged out successfully.', 'info');
      });
    }

    // Close dropdowns on outside click
    document.addEventListener('click', (e) => {
      if (userDropdown && !userProfileBtn.contains(e.target) && !userDropdown.contains(e.target)) {
        userDropdown.classList.remove('open');
      }
    });
  },

  async verifyAuthentication() {
    try {
      const res = await Api.checkAuth();
      if (res && res.authenticated) {
        this.currentUser = res.user;
        this.hideLogin();
        this.updateUserUI(res.user);
        this.startNotificationPolling();
        
        // Initial view router
        const hash = window.location.hash.replace('#', '');
        if (['dashboard', 'analysis', 'records', 'risk', 'settings'].includes(hash)) {
          this.navigateTo(hash);
        } else {
          this.navigateTo('dashboard');
        }
        this.loadNotifications();
      } else {
        this.showLogin();
      }
    } catch {
      this.showLogin();
    }
  },

  showLogin() {
    const overlay = document.getElementById('login-overlay');
    const appWrapper = document.getElementById('app-wrapper');
    if (overlay) overlay.style.display = 'flex';
    if (appWrapper) appWrapper.classList.add('hidden');
    const pw = document.getElementById('login-password');
    if (pw) pw.value = '';
    const alertBox = document.getElementById('login-alert');
    if (alertBox) alertBox.classList.remove('visible');
  },

  hideLogin() {
    const overlay = document.getElementById('login-overlay');
    const appWrapper = document.getElementById('app-wrapper');
    if (overlay) overlay.style.display = 'none';
    if (appWrapper) appWrapper.classList.remove('hidden');
  },

  updateUserUI(user) {
    if (!user) return;
    const nameLabel = document.getElementById('user-display-name');
    const roleLabel = document.getElementById('user-display-role');
    const avatar = document.getElementById('user-avatar-initials');
    const dropdownName = document.getElementById('user-dropdown-name');

    if (nameLabel) nameLabel.textContent = user.username || 'Admin';
    if (roleLabel) roleLabel.textContent = user.role || 'Administrator';
    if (dropdownName) dropdownName.textContent = user.username ? `${user.username} (${user.role})` : 'Admin (Administrator)';
    if (avatar) avatar.textContent = (user.username || 'AD').substring(0, 2).toUpperCase();
  },

  /**
   * ------------------------------------------------------------------------
   * Notification System Logic
   * ------------------------------------------------------------------------
   */
  bindNotifications() {
    const btnBell = document.getElementById('btn-notifications');
    const dropdown = document.getElementById('notifications-dropdown');
    const btnMarkAll = document.getElementById('btn-mark-all-read');
    const btnClearAll = document.getElementById('btn-clear-notifications');

    if (btnBell && dropdown) {
      btnBell.addEventListener('click', (e) => {
        e.stopPropagation();
        // Close user dropdown if open
        const userDropdown = document.getElementById('user-profile-dropdown');
        if (userDropdown) userDropdown.classList.remove('open');

        const isOpen = dropdown.classList.toggle('open');
        if (isOpen) {
          this.loadNotifications();
        }
      });
    }

    if (btnMarkAll) {
      btnMarkAll.addEventListener('click', async (e) => {
        e.stopPropagation();
        try {
          await Api.markAllNotificationsRead();
          this.loadNotifications();
          this.showToast('All notifications marked as read.', 'info');
        } catch (err) {
          console.error(err);
        }
      });
    }

    if (btnClearAll) {
      btnClearAll.addEventListener('click', async (e) => {
        e.stopPropagation();
        try {
          await Api.clearNotifications();
          this.loadNotifications();
          this.showToast('All notifications cleared.', 'info');
        } catch (err) {
          console.error(err);
        }
      });
    }

    // Close notifications dropdown on outside click
    document.addEventListener('click', (e) => {
      if (dropdown && btnBell && !btnBell.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.classList.remove('open');
      }
    });
  },

  async loadNotifications() {
    try {
      const res = await Api.getNotifications();
      if (!res || !res.success) return;
      const data = res.data;

      const badge = document.getElementById('notif-badge');
      const unreadPill = document.getElementById('notif-unread-pill');
      const notifList = document.getElementById('notif-list');

      const unreadCount = data.unread_count || 0;

      // Update Badge
      if (badge) {
        if (unreadCount > 0) {
          badge.style.display = 'block';
        } else {
          badge.style.display = 'none';
        }
      }

      if (unreadPill) {
        unreadPill.textContent = unreadCount;
      }

      // Render Notification List
      if (notifList) {
        notifList.innerHTML = '';
        const list = data.notifications || [];

        if (list.length === 0) {
          notifList.innerHTML = `<li class="notif-empty">No notifications available</li>`;
          return;
        }

        list.forEach(n => {
          const li = document.createElement('li');
          li.className = `notif-item ${n.is_read ? '' : 'unread'}`;

          let iconSvg = '';
          if (n.type === 'success') {
            iconSvg = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
          } else if (n.type === 'danger') {
            iconSvg = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;
          } else if (n.type === 'warning') {
            iconSvg = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path></svg>`;
          } else {
            iconSvg = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
          }

          li.innerHTML = `
            <div class="notif-icon ${n.type}">
              ${iconSvg}
            </div>
            <div class="notif-content">
              <div class="notif-item-title">${this.escapeHtml(n.title)}</div>
              <div class="notif-item-msg">${this.escapeHtml(n.message)}</div>
              <div class="notif-item-time">${n.created_at}</div>
            </div>
          `;

          // Mark as read on click
          li.addEventListener('click', async () => {
            if (!n.is_read) {
              await Api.markNotificationRead(n.id);
              n.is_read = 1;
              li.classList.remove('unread');
              this.loadNotifications();
            }
          });

          notifList.appendChild(li);
        });
      }
    } catch (err) {
      console.warn('Failed to load notifications:', err);
    }
  },

  startNotificationPolling() {
    this.stopNotificationPolling();
    this.notifPollTimer = setInterval(() => {
      if (this.currentUser) {
        this.loadNotifications();
      }
    }, 15000); // Poll every 15 seconds
  },

  stopNotificationPolling() {
    if (this.notifPollTimer) {
      clearInterval(this.notifPollTimer);
      this.notifPollTimer = null;
    }
  },

  /**
   * Health check for API status indicator
   */
  async checkSystemHealth() {
    const dot = document.getElementById('status-dot');
    const label = document.getElementById('status-text');
    try {
      const res = await Api.checkHealth();
      if (res && res.status === 'online') {
        if (dot) dot.classList.remove('offline');
        if (label) label.textContent = 'API & SQLite: Active';
      } else {
        if (dot) dot.classList.add('offline');
        if (label) label.textContent = 'API: Disconnected';
      }
    } catch {
      if (dot) dot.classList.add('offline');
      if (label) label.textContent = 'API: Disconnected';
    }
  },

  /**
   * Sidebar Navigation Switching
   */
  bindNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const targetView = item.getAttribute('data-view');
        this.navigateTo(targetView);
      });
    });

    window.addEventListener('hashchange', () => {
      const hash = window.location.hash.replace('#', '');
      if (hash && hash !== this.activeView) {
        this.navigateTo(hash);
      }
    });
  },

  navigateTo(viewId) {
    this.activeView = viewId;
    window.location.hash = viewId;

    // Update sidebar active classes
    document.querySelectorAll('.nav-item').forEach(item => {
      if (item.getAttribute('data-view') === viewId) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Update view sections
    document.querySelectorAll('.page-view').forEach(view => {
      view.classList.remove('active');
    });

    const targetSection = document.getElementById(`view-${viewId}`);
    if (targetSection) {
      targetSection.classList.add('active');
    }

    // Trigger page-specific data loads
    if (viewId === 'dashboard') {
      this.loadDashboard();
    } else if (viewId === 'records') {
      this.loadLeakRecords();
    } else if (viewId === 'risk') {
      this.loadRiskAssessment();
    } else if (viewId === 'settings') {
      this.loadSettings();
    }
  },

  /**
   * ------------------------------------------------------------------------
   * 1. Dashboard View Logic
   * ------------------------------------------------------------------------
   */
  async loadDashboard() {
    try {
      const res = await Api.getDashboard();
      if (!res || !res.success) return;
      const data = res.data;

      // Update 4 Stat Cards
      document.getElementById('stat-total-analyzed').textContent = (data.total_records_analyzed || 0).toLocaleString();
      document.getElementById('stat-leaked-credentials').textContent = (data.leaked_credentials || 0).toLocaleString();
      document.getElementById('stat-high-risk').textContent = (data.high_risk_records || 0).toLocaleString();
      document.getElementById('stat-last-scan').textContent = data.last_scan || 'No scans yet';

      // Render Recent Activity Table
      const tbody = document.getElementById('recent-activity-tbody');
      tbody.innerHTML = '';

      if (!data.recent_activity || data.recent_activity.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--text-muted); padding: 24px;">No scan activity recorded yet. Upload a dataset in Credential Analysis.</td></tr>`;
      } else {
        data.recent_activity.forEach(item => {
          const row = document.createElement('tr');
          row.innerHTML = `
            <td class="font-mono">${item.scan_id}</td>
            <td style="font-weight: 500;">${this.escapeHtml(item.filename)}</td>
            <td class="font-mono" style="color: var(--text-muted);">${item.scan_date}</td>
            <td class="font-mono">${item.total_records}</td>
            <td class="font-mono" style="color: var(--accent-blue);">${item.email_records}</td>
            <td><span class="badge badge-high">${item.high_risk_count} High</span></td>
            <td><span class="badge-status ${item.status === 'Completed' ? 'remediated' : 'active-threat'}">${item.status}</span></td>
          `;
          tbody.appendChild(row);
        });
      }

      // Render Simple Risk Distribution Chart
      const dist = data.risk_distribution || { high: 0, medium: 0, low: 0 };
      Charts.renderDashboardRiskChart('dashboard-risk-chart', dist.high, dist.medium, dist.low);

    } catch (err) {
      console.error('Failed to load dashboard:', err);
      if (err.message && err.message.includes('Authentication')) {
        this.showLogin();
      } else {
        this.showToast('Unable to load dashboard data.', 'error');
      }
    }
  },

  /**
   * ------------------------------------------------------------------------
   * 2. Credential Analysis View (File Upload & Analysis)
   * ------------------------------------------------------------------------
   */
  bindAnalysisUpload() {
    const dropArea = document.getElementById('file-drop-area');
    const fileInput = document.getElementById('file-input');
    const btnBrowse = document.getElementById('btn-browse-file');
    const btnAnalyze = document.getElementById('btn-start-analysis');
    const btnSampleDemo = document.getElementById('btn-sample-demo');

    btnBrowse.addEventListener('click', (e) => {
      e.stopPropagation();
      fileInput.click();
    });

    dropArea.addEventListener('click', () => {
      fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        this.handleFileSelected(e.target.files[0]);
      }
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      dropArea.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropArea.classList.add('drag-over');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropArea.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropArea.classList.remove('drag-over');
      });
    });

    dropArea.addEventListener('drop', (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        this.handleFileSelected(e.dataTransfer.files[0]);
      }
    });

    btnAnalyze.addEventListener('click', () => {
      if (!this.selectedFile) return;
      this.executeFileAnalysis();
    });

    if (btnSampleDemo) {
      btnSampleDemo.addEventListener('click', () => {
        this.executeSampleAnalysis();
      });
    }
  },

  handleFileSelected(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['csv', 'txt'].includes(ext)) {
      this.showToast('Invalid file type. Please select a .csv or .txt file.', 'error');
      return;
    }

    this.selectedFile = file;
    document.getElementById('display-file-name').textContent = file.name;
    document.getElementById('display-file-meta').textContent = `${(file.size / 1024).toFixed(1)} KB • Ready for Analysis`;
    document.getElementById('file-status-bar').style.display = 'flex';
    document.getElementById('btn-start-analysis').disabled = false;
  },

  async executeFileAnalysis() {
    if (!this.selectedFile) return;

    const btnAnalyze = document.getElementById('btn-start-analysis');
    btnAnalyze.disabled = true;
    btnAnalyze.textContent = 'Analyzing Threat Intelligence...';

    try {
      const res = await Api.uploadAndAnalyze(this.selectedFile);
      this.showToast('Threat analysis completed successfully!', 'success');
      this.displayAnalysisResults(res.data);
      this.loadNotifications(); // Refresh notifications
    } catch (err) {
      this.showToast(err.message || 'File analysis failed', 'error');
      this.loadNotifications();
    } finally {
      btnAnalyze.disabled = false;
      btnAnalyze.textContent = 'Analyse Records';
    }
  },

  async executeSampleAnalysis() {
    const btnSampleDemo = document.getElementById('btn-sample-demo');
    if (btnSampleDemo) {
      btnSampleDemo.disabled = true;
      btnSampleDemo.textContent = 'Processing Synthetic Sample...';
    }

    try {
      const res = await Api.analyzeSampleFile('synthetic_darkweb_leaks_sample.csv');
      this.showToast('Synthetic breach sample analyzed successfully!', 'success');
      this.displayAnalysisResults(res.data);
      this.loadNotifications();
    } catch (err) {
      this.showToast(err.message || 'Sample analysis failed', 'error');
      this.loadNotifications();
    } finally {
      if (btnSampleDemo) {
        btnSampleDemo.disabled = false;
        btnSampleDemo.textContent = 'Load Synthetic Sample';
      }
    }
  },

  displayAnalysisResults(data) {
    const resultsPanel = document.getElementById('analysis-results-panel');
    resultsPanel.classList.add('visible');

    document.getElementById('res-total-analyzed').textContent = (data.total_records || 0).toLocaleString();
    document.getElementById('res-emails-detected').textContent = (data.email_records || 0).toLocaleString();
    document.getElementById('res-duplicates').textContent = (data.duplicate_records || 0).toLocaleString();
    document.getElementById('res-high-risk').textContent = (data.high_risk_count || 0).toLocaleString();

    // Toggle analysis duplicate deletion button if duplicates were detected
    const btnAnalysisDups = document.getElementById('btn-analysis-delete-duplicates');
    if (btnAnalysisDups) {
      if ((data.duplicate_records || 0) > 0) {
        btnAnalysisDups.style.display = 'inline-flex';
        btnAnalysisDups.onclick = (e) => {
          e.stopPropagation();
          this.promptDeleteDuplicates();
        };
      } else {
        btnAnalysisDups.style.display = 'none';
      }
    }

    const total = (data.high_risk_count || 0) + (data.medium_risk_count || 0) + (data.low_risk_count || 0);
    const highPct = total > 0 ? ((data.high_risk_count / total) * 100).toFixed(1) : 0;
    const medPct = total > 0 ? ((data.medium_risk_count / total) * 100).toFixed(1) : 0;
    const lowPct = total > 0 ? ((data.low_risk_count / total) * 100).toFixed(1) : 0;

    document.getElementById('risk-bar-high').style.width = `${highPct}%`;
    document.getElementById('risk-bar-med').style.width = `${medPct}%`;
    document.getElementById('risk-bar-low').style.width = `${lowPct}%`;

    document.getElementById('label-risk-high').textContent = `High: ${data.high_risk_count} (${highPct}%)`;
    document.getElementById('label-risk-med').textContent = `Medium: ${data.medium_risk_count} (${medPct}%)`;
    document.getElementById('label-risk-low').textContent = `Low: ${data.low_risk_count} (${lowPct}%)`;

    const tbody = document.getElementById('analysis-preview-tbody');
    tbody.innerHTML = '';

    if (data.preview_records && data.preview_records.length > 0) {
      data.preview_records.forEach(rec => {
        const row = document.createElement('tr');
        const badgeClass = rec.risk_level === 'High' ? 'badge-high' : (rec.risk_level === 'Medium' ? 'badge-medium' : 'badge-low');
        row.innerHTML = `
          <td class="font-mono">${rec.record_id}</td>
          <td class="font-mono" style="color: #60a5fa;">${this.escapeHtml(rec.email_masked)}</td>
          <td>${this.escapeHtml(rec.source)}</td>
          <td><span class="badge ${badgeClass}">${rec.risk_level}</span></td>
          <td style="color: var(--text-muted); font-size: 11px;">${this.escapeHtml(rec.risk_factors || '')}</td>
        `;
        tbody.appendChild(row);
      });
    }

    resultsPanel.scrollIntoView({ behavior: 'smooth' });
  },

  /**
   * ------------------------------------------------------------------------
   * 3. Leak Records View
   * ------------------------------------------------------------------------
   */
  bindLeakRecordsControls() {
    const searchInput = document.getElementById('records-search');
    const riskFilter = document.getElementById('records-filter-risk');
    const statusFilter = document.getElementById('records-filter-status');
    const dupFilter = document.getElementById('records-filter-duplicates');
    const btnDeleteDups = document.getElementById('btn-delete-duplicates');
    const btnPrev = document.getElementById('records-btn-prev');
    const btnNext = document.getElementById('records-btn-next');

    let debounceTimer = null;
    searchInput.addEventListener('input', (e) => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        this.recordsState.search = e.target.value.trim();
        this.recordsState.page = 1;
        this.loadLeakRecords();
      }, 300);
    });

    riskFilter.addEventListener('change', (e) => {
      this.recordsState.risk = e.target.value;
      this.recordsState.page = 1;
      this.loadLeakRecords();
    });

    statusFilter.addEventListener('change', (e) => {
      this.recordsState.status = e.target.value;
      this.recordsState.page = 1;
      this.loadLeakRecords();
    });

    if (dupFilter) {
      dupFilter.addEventListener('change', (e) => {
        this.recordsState.duplicates = (e.target.value === 'duplicates');
        this.recordsState.page = 1;
        this.loadLeakRecords();
      });
    }

    if (btnDeleteDups) {
      btnDeleteDups.addEventListener('click', () => {
        this.promptDeleteDuplicates();
      });
    }

    btnPrev.addEventListener('click', () => {
      if (this.recordsState.page > 1) {
        this.recordsState.page--;
        this.loadLeakRecords();
      }
    });

    btnNext.addEventListener('click', () => {
      if (this.recordsState.page < this.recordsState.totalPages) {
        this.recordsState.page++;
        this.loadLeakRecords();
      }
    });
  },

  async loadLeakRecords() {
    const tbody = document.getElementById('leak-records-tbody');
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">Loading leak records...</td></tr>`;

    try {
      const res = await Api.getLeakRecords({
        search: this.recordsState.search,
        risk: this.recordsState.risk,
        status: this.recordsState.status,
        duplicates: this.recordsState.duplicates,
        page: this.recordsState.page,
        per_page: this.recordsState.per_page
      });

      if (!res || !res.success) throw new Error('Failed to load records');
      const data = res.data;

      this.recordsState.totalPages = data.total_pages || 1;
      document.getElementById('records-page-info').textContent = `Page ${data.page} of ${data.total_pages} (${data.total} records)`;

      document.getElementById('records-btn-prev').disabled = data.page <= 1;
      document.getElementById('records-btn-next').disabled = data.page >= data.total_pages;

      tbody.innerHTML = '';
      if (!data.records || data.records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No leak records found matching criteria.</td></tr>`;
        return;
      }

      data.records.forEach(rec => {
        const row = document.createElement('tr');
        const badgeClass = rec.risk_level === 'High' ? 'badge-high' : (rec.risk_level === 'Medium' ? 'badge-medium' : 'badge-low');
        const statusClass = rec.status.toLowerCase().replace(/\s+/g, '-');

        row.innerHTML = `
          <td class="font-mono">${rec.record_id}</td>
          <td class="font-mono" style="color: #60a5fa; font-weight: 500;">${this.escapeHtml(rec.email_masked)}</td>
          <td>${this.escapeHtml(rec.source)}</td>
          <td class="font-mono" style="color: var(--text-muted); font-size: 11px;">${rec.detection_date}</td>
          <td><span class="badge ${badgeClass}">${rec.risk_level}</span></td>
          <td><span class="badge-status ${statusClass}">${rec.status}</span></td>
          <td style="text-align: center;">
            <button class="btn-action-delete" title="Delete record ${rec.record_id}" onclick="App.promptDeleteSingleRecord('${rec.record_id}')">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"></polyline>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
              </svg>
            </button>
          </td>
        `;
        tbody.appendChild(row);
      });

    } catch (err) {
      console.error(err);
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--risk-high); padding: 24px;">Error fetching records: ${err.message}</td></tr>`;
    }
  },

  /**
   * ------------------------------------------------------------------------
   * 4. Risk Assessment View Logic
   * ------------------------------------------------------------------------
   */
  async loadRiskAssessment() {
    try {
      const res = await Api.getRiskAssessment();
      if (!res || !res.success) return;
      const data = res.data;

      document.getElementById('risk-score-value').textContent = data.overall_risk_score;
      const gradeBadge = document.getElementById('risk-score-grade');
      gradeBadge.textContent = data.risk_grade;
      gradeBadge.style.color = data.risk_color;
      gradeBadge.style.border = `1px solid ${data.risk_color}`;
      gradeBadge.style.backgroundColor = `${data.risk_color}18`;

      document.getElementById('risk-count-high').textContent = (data.high_risk || 0).toLocaleString();
      document.getElementById('risk-count-med').textContent = (data.medium_risk || 0).toLocaleString();
      document.getElementById('risk-count-low').textContent = (data.low_risk || 0).toLocaleString();

      Charts.renderRiskAssessmentChart(
        'risk-assessment-chart',
        data.high_risk || 0,
        data.medium_risk || 0,
        data.low_risk || 0,
        data.factors || {}
      );

      const summaryList = document.getElementById('risk-summary-list');
      summaryList.innerHTML = '';
      if (data.summary && data.summary.length > 0) {
        data.summary.forEach(point => {
          const li = document.createElement('li');
          li.textContent = point;
          summaryList.appendChild(li);
        });
      }

    } catch (err) {
      console.error('Failed to load risk assessment:', err);
      this.showToast('Unable to calculate risk assessment.', 'error');
    }
  },

  /**
   * ------------------------------------------------------------------------
   * 5. Settings View Logic
   * ------------------------------------------------------------------------
   */
  bindSettingsControls() {
    // 1. Account Settings: Password Change
    const btnSavePassword = document.getElementById('btn-save-password');
    if (btnSavePassword) {
      btnSavePassword.addEventListener('click', async () => {
        const newPw = document.getElementById('setting-new-password').value;
        const confirmPw = document.getElementById('setting-confirm-password').value;

        if (!newPw || !confirmPw) {
          this.showToast('Please enter both password fields.', 'error');
          return;
        }

        if (newPw.length < 6) {
          this.showToast('Password must be at least 6 characters long.', 'error');
          return;
        }

        if (newPw !== confirmPw) {
          this.showToast('Passwords do not match.', 'error');
          return;
        }

        btnSavePassword.disabled = true;
        btnSavePassword.textContent = 'Updating...';

        try {
          const res = await Api.updatePassword(newPw, confirmPw);
          this.showToast(res.message || 'Password updated successfully.', 'success');
          document.getElementById('setting-new-password').value = '';
          document.getElementById('setting-confirm-password').value = '';
        } catch (err) {
          this.showToast(err.message || 'Failed to update password.', 'error');
        } finally {
          btnSavePassword.disabled = false;
          btnSavePassword.textContent = 'Save Changes';
        }
      });
    }

    // 2. Notification Settings
    const btnSaveNotifications = document.getElementById('btn-save-notifications');
    if (btnSaveNotifications) {
      btnSaveNotifications.addEventListener('click', async () => {
        const payload = {
          notifications_enabled: document.getElementById('setting-notif-global').checked,
          notify_high_risk: document.getElementById('setting-notif-high-risk').checked,
          notify_analysis_complete: document.getElementById('setting-notif-analysis').checked,
          notify_login_activity: document.getElementById('setting-notif-login').checked
        };

        btnSaveNotifications.disabled = true;
        btnSaveNotifications.textContent = 'Saving...';

        try {
          await Api.updateSettings(payload);
          this.showToast('Notification preferences saved successfully.', 'success');
        } catch (err) {
          this.showToast('Failed to save notification preferences.', 'error');
        } finally {
          btnSaveNotifications.disabled = false;
          btnSaveNotifications.textContent = 'Save Changes';
        }
      });
    }

    // 3. Security Settings
    const btnSaveSecurity = document.getElementById('btn-save-security');
    if (btnSaveSecurity) {
      btnSaveSecurity.addEventListener('click', async () => {
        const timeout = document.getElementById('setting-session-timeout').value;

        btnSaveSecurity.disabled = true;
        btnSaveSecurity.textContent = 'Saving...';

        try {
          await Api.updateSettings({ session_timeout: timeout });
          this.showToast('Security settings saved successfully.', 'success');
        } catch (err) {
          this.showToast('Failed to save security settings.', 'error');
        } finally {
          btnSaveSecurity.disabled = false;
          btnSaveSecurity.textContent = 'Save Changes';
        }
      });
    }

    // 4. Appearance Settings: Dark / Light Themes
    const cardDark = document.getElementById('theme-card-dark');
    const cardLight = document.getElementById('theme-card-light');

    if (cardDark) {
      cardDark.addEventListener('click', () => {
        this.applyTheme('dark');
        Api.updateSettings({ theme: 'dark' }).catch(() => {});
        this.showToast('Theme set to Dark.', 'info');
      });
    }

    if (cardLight) {
      cardLight.addEventListener('click', () => {
        this.applyTheme('light');
        Api.updateSettings({ theme: 'light' }).catch(() => {});
        this.showToast('Theme set to Light.', 'info');
      });
    }

    // 5. Duplicate Clean-Up Controls (Settings)
    const btnSettingsDups = document.getElementById('btn-settings-delete-duplicates');
    if (btnSettingsDups) {
      btnSettingsDups.addEventListener('click', () => {
        this.promptDeleteDuplicates();
      });
    }

    // Duplicate Deletion Modal Controls
    const modalDup = document.getElementById('modal-duplicate-confirm');
    const btnCancelDup = document.getElementById('btn-modal-dup-cancel');
    const btnConfirmDup = document.getElementById('btn-modal-dup-confirm');

    if (btnCancelDup && modalDup) {
      btnCancelDup.addEventListener('click', () => {
        modalDup.classList.remove('open');
      });
    }

    if (btnConfirmDup && modalDup) {
      btnConfirmDup.addEventListener('click', () => {
        this.executeDeleteDuplicates();
      });
    }

    // Single Record Deletion Modal Controls
    const modalSingle = document.getElementById('modal-single-delete-confirm');
    const btnCancelSingle = document.getElementById('btn-modal-single-cancel');
    const btnConfirmSingle = document.getElementById('btn-modal-single-confirm');

    if (btnCancelSingle && modalSingle) {
      btnCancelSingle.addEventListener('click', () => {
        modalSingle.classList.remove('open');
        this.pendingDeleteRecordId = null;
      });
    }

    if (btnConfirmSingle && modalSingle) {
      btnConfirmSingle.addEventListener('click', () => {
        this.executeDeleteSingleRecord();
      });
    }

    // 6. Data Reset Modal Controls
    const btnOpenReset = document.getElementById('btn-open-reset-modal');
    const modalReset = document.getElementById('modal-reset-confirm');
    const btnCancelReset = document.getElementById('btn-modal-cancel');
    const btnConfirmReset = document.getElementById('btn-modal-confirm');

    if (btnOpenReset && modalReset) {
      btnOpenReset.addEventListener('click', () => {
        modalReset.classList.add('open');
      });
    }

    if (btnCancelReset && modalReset) {
      btnCancelReset.addEventListener('click', () => {
        modalReset.classList.remove('open');
      });
    }

    if (btnConfirmReset && modalReset) {
      btnConfirmReset.addEventListener('click', async () => {
        btnConfirmReset.disabled = true;
        btnConfirmReset.textContent = 'Resetting Data...';

        try {
          const res = await Api.resetData();
          modalReset.classList.remove('open');
          this.showToast(res.message || 'Application data has been reset successfully.', 'success');
          this.resetAllViewStates();
        } catch (err) {
          this.showToast(err.message || 'Data reset failed.', 'error');
        } finally {
          btnConfirmReset.disabled = false;
          btnConfirmReset.textContent = 'Confirm Reset';
        }
      });
    }
  },

  /**
   * Reset all view UI states after data reset
   */
  resetAllViewStates() {
    // 1. Reset Credential Analysis View
    this.selectedFile = null;
    const resultsPanel = document.getElementById('analysis-results-panel');
    if (resultsPanel) resultsPanel.classList.remove('visible');
    const statusBar = document.getElementById('file-status-bar');
    if (statusBar) statusBar.style.display = 'none';
    const fileInput = document.getElementById('file-input');
    if (fileInput) fileInput.value = '';
    const btnAnalyze = document.getElementById('btn-start-analysis');
    if (btnAnalyze) {
      btnAnalyze.disabled = true;
      btnAnalyze.textContent = 'Analyse Records';
    }

    // 2. Refresh Dashboard (Stat cards to 0, empty recent activity, chart to 0)
    this.loadDashboard();

    // 3. Reset Leak Records (Page 1, empty state)
    this.recordsState.page = 1;
    this.loadLeakRecords();

    // 4. Refresh Risk Assessment (0 score, empty summary)
    this.loadRiskAssessment();

    // 5. Refresh Notifications
    this.loadNotifications();
  },

  async loadSettings() {
    try {
      const res = await Api.getSettings();
      if (res && res.success && res.settings) {
        const s = res.settings;

        // Account
        const usernameEl = document.getElementById('setting-account-username');
        if (usernameEl) usernameEl.value = s.username || 'Admin';

        // Security
        const lastLoginEl = document.getElementById('setting-last-login-display');
        if (lastLoginEl) lastLoginEl.textContent = s.last_login || 'Never';

        const timeoutEl = document.getElementById('setting-session-timeout');
        if (timeoutEl && s.session_timeout) timeoutEl.value = s.session_timeout;

        // Notifications
        const notifGlobal = document.getElementById('setting-notif-global');
        if (notifGlobal) notifGlobal.checked = s.notifications_enabled !== false;

        const notifHighRisk = document.getElementById('setting-notif-high-risk');
        if (notifHighRisk) notifHighRisk.checked = s.notify_high_risk !== false;

        const notifAnalysis = document.getElementById('setting-notif-analysis');
        if (notifAnalysis) notifAnalysis.checked = s.notify_analysis_complete !== false;

        const notifLogin = document.getElementById('setting-notif-login');
        if (notifLogin) notifLogin.checked = s.notify_login_activity !== false;

        // Appearance
        if (s.theme) {
          this.applyTheme(s.theme);
        }

        // Duplicate records count in settings
        this.updateSettingsDuplicateCount();
      }
    } catch (err) {
      console.warn('Could not load settings:', err);
    }
  },

  async updateSettingsDuplicateCount() {
    const label = document.getElementById('settings-dup-count-label');
    if (!label) return;
    try {
      const res = await Api.getDuplicateCount();
      const count = res.count || 0;
      label.textContent = count === 1 ? '1 duplicate record detected' : `${count} duplicate records detected`;
      label.style.color = count > 0 ? 'var(--risk-med)' : 'var(--text-muted)';
    } catch {
      label.textContent = 'Unable to check duplicates';
    }
  },

  /**
   * ------------------------------------------------------------------------
   * Duplicate Deletion & Single Record Deletion Management
   * ------------------------------------------------------------------------
   */
  async promptDeleteDuplicates() {
    try {
      const res = await Api.getDuplicateCount();
      const count = res.count || 0;

      if (count === 0) {
        this.showToast('No duplicate records detected. All repository credentials are unique.', 'info');
        this.updateSettingsDuplicateCount();
        return;
      }

      const modal = document.getElementById('modal-duplicate-confirm');
      const body = document.getElementById('modal-duplicate-body');
      if (body) {
        body.textContent = `Detected ${count} duplicate credential records across the intelligence repository. Are you sure you want to remove all redundant records? The earliest entry for each unique credential identity will be preserved.`;
      }
      if (modal) modal.classList.add('open');
    } catch (err) {
      this.showToast('Error checking duplicates: ' + err.message, 'error');
    }
  },

  async executeDeleteDuplicates() {
    const btnConfirm = document.getElementById('btn-modal-dup-confirm');
    const modal = document.getElementById('modal-duplicate-confirm');
    if (btnConfirm) {
      btnConfirm.disabled = true;
      btnConfirm.textContent = 'Deleting Duplicates...';
    }

    try {
      const res = await Api.deleteDuplicates();
      if (modal) modal.classList.remove('open');
      this.showToast(res.message || 'Duplicate records removed successfully.', 'success');

      // Hide analysis duplicate button if currently displayed
      const btnAnalysisDups = document.getElementById('btn-analysis-delete-duplicates');
      if (btnAnalysisDups) btnAnalysisDups.style.display = 'none';

      // Refresh data on current active view
      if (this.activeView === 'records') {
        this.recordsState.page = 1;
        this.loadLeakRecords();
      } else if (this.activeView === 'dashboard') {
        this.loadDashboard();
      } else if (this.activeView === 'risk') {
        this.loadRiskAssessment();
      }

      this.updateSettingsDuplicateCount();
      this.loadNotifications();
    } catch (err) {
      this.showToast(err.message || 'Failed to delete duplicates.', 'error');
    } finally {
      if (btnConfirm) {
        btnConfirm.disabled = false;
        btnConfirm.textContent = 'Confirm Delete';
      }
    }
  },

  promptDeleteSingleRecord(recordId) {
    this.pendingDeleteRecordId = recordId;
    const modal = document.getElementById('modal-single-delete-confirm');
    const body = document.getElementById('modal-single-delete-body');
    if (body) {
      body.textContent = `Are you sure you want to permanently delete credential record "${recordId}"?`;
    }
    if (modal) modal.classList.add('open');
  },

  async executeDeleteSingleRecord() {
    if (!this.pendingDeleteRecordId) return;
    const btnConfirm = document.getElementById('btn-modal-single-confirm');
    const modal = document.getElementById('modal-single-delete-confirm');
    const targetId = this.pendingDeleteRecordId;

    if (btnConfirm) {
      btnConfirm.disabled = true;
      btnConfirm.textContent = 'Deleting...';
    }

    try {
      const res = await Api.deleteRecord(targetId);
      if (modal) modal.classList.remove('open');
      this.showToast(res.message || `Record ${targetId} deleted successfully.`, 'success');

      // Refresh leak records table
      this.loadLeakRecords();
      this.updateSettingsDuplicateCount();
      this.loadNotifications();
    } catch (err) {
      this.showToast(err.message || 'Failed to delete record.', 'error');
    } finally {
      this.pendingDeleteRecordId = null;
      if (btnConfirm) {
        btnConfirm.disabled = false;
        btnConfirm.textContent = 'Delete';
      }
    }
  },

  bindTheme() {
    const savedTheme = localStorage.getItem('darkwatch_theme') || 'dark';
    this.applyTheme(savedTheme);
  },

  applyTheme(theme) {
    document.body.classList.remove('theme-light', 'theme-charcoal', 'theme-slate');
    if (theme === 'light') {
      document.body.classList.add('theme-light');
    }
    localStorage.setItem('darkwatch_theme', theme);

    // Update Appearance option card selection
    const cardDark = document.getElementById('theme-card-dark');
    const cardLight = document.getElementById('theme-card-light');
    if (cardDark && cardLight) {
      if (theme === 'light') {
        cardDark.classList.remove('selected');
        cardLight.classList.add('selected');
      } else {
        cardLight.classList.remove('selected');
        cardDark.classList.add('selected');
      }
    }
  },

  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${this.escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  },

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
};
