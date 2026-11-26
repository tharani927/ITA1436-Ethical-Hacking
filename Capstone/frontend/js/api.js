/**
 * DarkWatch API Client
 * Connects frontend to Python Flask REST API with Session & Token Authentication
 */

const API_BASE = 'http://127.0.0.1:5000/api';

const Api = {
  getToken() {
    return localStorage.getItem('darkwatch_token') || sessionStorage.getItem('darkwatch_token') || '';
  },

  setToken(token, remember = true) {
    if (remember) {
      localStorage.setItem('darkwatch_token', token);
    } else {
      sessionStorage.setItem('darkwatch_token', token);
    }
  },

  clearToken() {
    localStorage.removeItem('darkwatch_token');
    sessionStorage.removeItem('darkwatch_token');
  },

  /**
   * Internal fetch wrapper ensuring session credentials and Bearer token headers
   */
  async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = options.headers || {};

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
      headers['X-Session-Token'] = token;
    }

    const config = {
      ...options,
      headers,
      credentials: 'include' // include session cookies for cross-origin Flask sessions
    };

    const res = await fetch(url, config);

    // If unauthorized, notify caller
    if (res.status === 401 && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/check')) {
      this.clearToken();
      if (window.App && typeof window.App.showLogin === 'function') {
        window.App.showLogin();
      }
      throw new Error('Session expired or unauthorized. Please log in.');
    }

    return res;
  },

  /**
   * Health check
   */
  async checkHealth() {
    try {
      const res = await fetch(`${API_BASE}/health`);
      return await res.json();
    } catch (err) {
      console.warn('[DarkWatch] API offline or unreachable:', err);
      return { status: 'offline', error: err.message };
    }
  },

  /**
   * Authentication Endpoints
   */
  async login(username, password) {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Login failed.');
    }

    if (data.token) {
      this.setToken(data.token, true);
    }
    return data;
  },

  async logout() {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } catch (e) {
      console.warn('Logout request error:', e);
    } finally {
      this.clearToken();
    }
    return { success: true };
  },

  async checkAuth() {
    try {
      const res = await this.request('/auth/check', { method: 'GET' });
      if (!res.ok) return { authenticated: false };
      return await res.json();
    } catch {
      return { authenticated: false };
    }
  },

  /**
   * Notification Endpoints
   */
  async getNotifications() {
    const res = await this.request('/notifications');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  },

  async markNotificationRead(notifId) {
    const res = await this.request(`/notifications/mark-read/${notifId}`, { method: 'POST' });
    return await res.json();
  },

  async markAllNotificationsRead() {
    const res = await this.request('/notifications/mark-all-read', { method: 'POST' });
    return await res.json();
  },

  async clearNotifications() {
    const res = await this.request('/notifications/clear', { method: 'POST' });
    return await res.json();
  },

  /**
   * Dashboard
   */
  async getDashboard() {
    const res = await this.request('/dashboard');
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  },

  /**
   * Ingestion & Analysis
   */
  async uploadAndAnalyze(file) {
    const formData = new FormData();
    formData.append('file', file);

    const res = await this.request('/upload-and-analyze', {
      method: 'POST',
      body: formData
    });

    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || `Upload failed with status ${res.status}`);
    }
    return data;
  },

  async analyzeSampleFile(sampleName) {
    const res = await this.request('/analyze-sample-file', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sample_name: sampleName })
    });

    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Failed to analyze sample dataset');
    }
    return data;
  },

  /**
   * Leak records
   */
  async getLeakRecords({ search = '', risk = '', status = '', duplicates = false, page = 1, per_page = 15 } = {}) {
    const params = new URLSearchParams({
      search,
      risk,
      status,
      duplicates: duplicates ? 'true' : 'false',
      page: page.toString(),
      per_page: per_page.toString()
    });

    const res = await this.request(`/leak-records?${params.toString()}`);
    if (!res.ok) throw new Error(`Failed to fetch records (${res.status})`);
    return await res.json();
  },

  /**
   * Duplicate Management
   */
  async getDuplicateCount() {
    const res = await this.request('/leak-records/duplicates');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  },

  async deleteDuplicates() {
    const res = await this.request('/leak-records/delete-duplicates', {
      method: 'POST'
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Failed to delete duplicate records');
    }
    return data;
  },

  async deleteRecord(recordId) {
    const res = await this.request(`/leak-records/${encodeURIComponent(recordId)}`, {
      method: 'DELETE'
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Failed to delete record');
    }
    return data;
  },

  /**
   * Risk assessment
   */
  async getRiskAssessment() {
    const res = await this.request('/risk-assessment');
    if (!res.ok) throw new Error(`Failed to fetch risk assessment (${res.status})`);
    return await res.json();
  },

  /**
   * Reset data
   */
  async resetData() {
    const res = await this.request('/settings/reset-data', { method: 'POST' });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Reset operation failed');
    }
    return data;
  },

  /**
   * Seed sample data
   */
  async seedSample() {
    const res = await this.request('/seed-sample', { method: 'POST' });
    return await res.json();
  },

  /**
   * Settings
   */
  async getSettings() {
    const res = await this.request('/settings');
    return await res.json();
  },

  async updateSettings(settings) {
    const res = await this.request('/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    return await res.json();
  },

  async updatePassword(new_password, confirm_password) {
    const res = await this.request('/settings/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ new_password, confirm_password })
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Failed to update password');
    }
    return data;
  }
};

window.Api = Api;
