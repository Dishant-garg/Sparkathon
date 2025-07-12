const axios = require('axios');

// Django backend URL - adjust port if needed
const DJANGO_BASE_URL = process.env.DJANGO_BASE_URL || 'http://localhost:8000';

class DjangoScanService {
  constructor() {
    this.baseURL = DJANGO_BASE_URL;
    this.timeout = 120000; // 2 minutes timeout for scans
  }

  /**
   * Perform Nmap port scan
   * @param {string} target - Target URL or IP
   * @param {string} scanArgs - Nmap scan arguments (default: -F for fast scan)
   * @returns {Promise<Object>} Scan results
   */
  async nmapScan(target, scanArgs = '-F') {
    try {
      console.log(`Starting Nmap scan for target: ${target} with arguments: ${scanArgs}`);
      
      const response = await axios.post(`${this.baseURL}/api/nmap/scan/`, {
        target,
        arguments: scanArgs
      }, {
        timeout: this.timeout,
        headers: {
          'Content-Type': 'application/json'
        }
      });

      return {
        success: true,
        data: response.data,
        scanType: 'nmap',
        target,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Nmap scan failed:', error.message);
      return {
        success: false,
        error: error.response?.data?.error || error.message,
        scanType: 'nmap',
        target,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Get available Nmap scan arguments
   * @returns {Promise<Object>} Available Nmap arguments
   */
  async getNmapArguments() {
    try {
      const response = await axios.get(`${this.baseURL}/api/nmap/arguments/`, {
        timeout: 10000
      });

      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error('Failed to get Nmap arguments:', error.message);
      return {
        success: false,
        error: error.response?.data?.error || error.message
      };
    }
  }

  /**
   * Perform Gobuster directory/file scan
   * @param {string} url - Target URL
   * @returns {Promise<Object>} Scan results
   */
  async gobusterScan(url) {
    try {
      console.log(`Starting Gobuster scan for URL: ${url}`);
      
      const response = await axios.post(`${this.baseURL}/api/gobuster/scan/`, {
        url
      }, {
        timeout: this.timeout,
        headers: {
          'Content-Type': 'application/json'
        }
      });

      return {
        success: true,
        data: response.data,
        scanType: 'gobuster',
        target: url,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Gobuster scan failed:', error.message);
      return {
        success: false,
        error: error.response?.data?.error || error.message,
        scanType: 'gobuster',
        target: url,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Health check for Django backend
   * @returns {Promise<boolean>} Django backend status
   */
  async healthCheck() {
    try {
      const response = await axios.get(`${this.baseURL}/admin/`, {
        timeout: 5000
      });
      return response.status === 200;
    } catch (error) {
      console.error('Django backend health check failed:', error.message);
      return false;
    }
  }
}

module.exports = new DjangoScanService();
