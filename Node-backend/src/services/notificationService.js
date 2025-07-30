const nodemailer = require('nodemailer');
const axios = require('axios');

class NotificationService {
  constructor() {
    this.emailTransporter = null;
    this.emailEnabled = true;
    this.initializeEmailTransporter();
  }

  /**
   * Initialize email transporter
   */
  initializeEmailTransporter() {
    try {
      // Check if email is enabled and credentials are provided
      const emailEnabled = process.env.ENABLE_EMAIL_NOTIFICATIONS === 'true';
      const emailUser = process.env.EMAIL_USER;
      const emailPassword = process.env.EMAIL_PASSWORD;
      console.log(emailUser)
      console.log(emailPassword)

      if (!emailEnabled) {
        console.log('Email notifications are disabled in configuration');
        return;
      }

      if (!emailUser || !emailPassword || emailUser === 'test@gmail.com') {
        console.log('Email credentials not configured properly. Email notifications will be disabled.');
        return;
      }

      this.emailTransporter = nodemailer.createTransport({
        service: 'gmail', // or your preferred email service
        auth: {
          user: emailUser,
          pass: emailPassword // Use app password for Gmail
        }
      });

      this.emailEnabled = true;
      console.log('Email transporter initialized successfully');
    } catch (error) {
      console.error('Failed to initialize email transporter:', error.message);
      // this.emailEnabled = false;
    }
  }

  /**
   * Send email notification
   * @param {Object} config - Email configuration
   * @param {string} subject - Email subject
   * @param {Object} scanResults - Scan results to include
   * @returns {Promise<Object>} Send result
   */
  async sendEmail(config, subject, scanResults) {
    try {
      // Check if email is enabled and configured
      if (!this.emailEnabled) {
        console.log('Email notifications are disabled or not configured. Skipping email notification.');
        return {
          success: true,
          message: 'Email notifications disabled',
          skipped: true
        };
      }

      if (!this.emailTransporter) {
        throw new Error('Email transporter not initialized');
      }

      const { to, from = process.env.EMAIL_USER } = config;

      if (!to) {
        throw new Error('Email recipient is required');
      }

      // Format scan results for email
      const emailBody = this.formatScanResultsForEmail(scanResults);

      const mailOptions = {
        from,
        to,
        subject,
        html: emailBody
      };

      const result = await this.emailTransporter.sendMail(mailOptions);
      
      console.log('Email sent successfully:', result.messageId);
      return {
        success: true,
        messageId: result.messageId,
        recipient: to
      };
    } catch (error) {
      console.error('Failed to send email:', error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send Slack notification
   * @param {Object} config - Slack configuration
   * @param {string} title - Notification title
   * @param {Object} scanResults - Scan results to include
   * @returns {Promise<Object>} Send result
   */
  async sendSlackNotification(config, title, scanResults) {
    try {
      const { webhookUrl, channel } = config;

      if (!webhookUrl) {
        throw new Error('Slack webhook URL is required');
      }

      // Format scan results for Slack
      const slackMessage = this.formatScanResultsForSlack(title, scanResults);

      const response = await axios.post(webhookUrl, slackMessage, {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 10000
      });

      console.log('Slack notification sent successfully');
      return {
        success: true,
        channel: channel || 'default',
        response: response.data
      };
    } catch (error) {
      console.error('Failed to send Slack notification:', error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Create GitHub issue
   * @param {Object} config - GitHub configuration
   * @param {string} title - Issue title
   * @param {Object} scanResults - Scan results to include
   * @returns {Promise<Object>} Creation result
   */
  async createGitHubIssue(config, title, scanResults) {
    try {
      const { repository, token } = config;

      if (!repository || !token) {
        throw new Error('GitHub repository and token are required');
      }

      const [owner, repo] = repository.split('/');
      if (!owner || !repo) {
        throw new Error('Repository must be in format "owner/repo"');
      }

      // Format scan results for GitHub issue
      const issueBody = this.formatScanResultsForGitHub(scanResults);

      const response = await axios.post(
        `https://api.github.com/repos/${owner}/${repo}/issues`,
        {
          title,
          body: issueBody,
          labels: ['security-scan', 'vulnerability']
        },
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'AaaS-Labs-Workflow'
          },
          timeout: 10000
        }
      );

      console.log('GitHub issue created successfully:', response.data.html_url);
      return {
        success: true,
        issueUrl: response.data.html_url,
        issueNumber: response.data.number
      };
    } catch (error) {
      console.error('Failed to create GitHub issue:', error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Format scan results for email
   * @param {Object|Array} scanResults - Scan results (single or array)
   * @returns {string} HTML formatted email body
   */
  formatScanResultsForEmail(scanResults) {
    // If it's an array, format each result
    const resultsArray = Array.isArray(scanResults) ? scanResults : [scanResults];

    let html = `
      <html>
        <body>
          <h2>Security Scan Results</h2>
    `;

    resultsArray.forEach((result, idx) => {
      if (!result) return;
      const { scanType, target, data, success, error, timestamp } = result;

      html += `<hr/><h3>Result #${idx + 1}</h3>`;
      html += `<p><strong>Scan Type:</strong> ${scanType ? scanType.toUpperCase() : 'N/A'}</p>`;
      html += `<p><strong>Target:</strong> ${target || 'N/A'}</p>`;
      html += `<p><strong>Timestamp:</strong> ${timestamp || 'N/A'}</p>`;
      html += `<p><strong>Status:</strong> ${success ? '✅ Success' : '❌ Failed'}</p>`;

      if (success && data) {
        if (scanType === 'nmap' && data.scan) {
          html += '<h4>Port Scan Results:</h4><ul>';
          Object.keys(data.scan).forEach(host => {
            const hostData = data.scan[host];
            if (hostData.tcp) {
              Object.keys(hostData.tcp).forEach(port => {
                const portData = hostData.tcp[port];
                html += `<li>Port ${port}: ${portData.state} (${portData.name})</li>`;
              });
            }
          });
          html += '</ul>';
        } else if (scanType === 'gobuster') {
          html += `<h4>Directory/File Scan Results:</h4>`;
          html += `<p>Total findings: ${data.total_findings}</p>`;
          if (data.directories_found && data.directories_found.length > 0) {
            html += '<h5>Directories:</h5><ul>';
            data.directories_found.forEach(dir => {
              html += `<li>${dir}</li>`;
            });
            html += '</ul>';
          }
          if (data.files_found && data.files_found.length > 0) {
            html += '<h5>Files:</h5><ul>';
            data.files_found.forEach(file => {
              html += `<li>${file}</li>`;
            });
            html += '</ul>';
          }
        }
      } else if (error) {
        html += `<p><strong>Error:</strong> ${error}</p>`;
      }
    });

    html += `
        </body>
      </html>
    `;

    return html;
  }

  /**
   * Format scan results for Slack
   * @param {string} title - Message title
   * @param {Object} scanResults - Scan results
   * @returns {Object} Slack message payload
   */
  formatScanResultsForSlack(title, scanResults) {
    const { scanType, target, data, success, error, timestamp } = scanResults;

    const message = {
      text: title,
      blocks: [
        {
          type: "header",
          text: {
            type: "plain_text",
            text: title
          }
        },
        {
          type: "section",
          fields: [
            {
              type: "mrkdwn",
              text: `*Scan Type:* ${scanType.toUpperCase()}`
            },
            {
              type: "mrkdwn",
              text: `*Target:* ${target}`
            },
            {
              type: "mrkdwn",
              text: `*Status:* ${success ? ':white_check_mark: Success' : ':x: Failed'}`
            },
            {
              type: "mrkdwn",
              text: `*Time:* ${new Date(timestamp).toLocaleString()}`
            }
          ]
        }
      ]
    };

    if (success && data) {
      let resultsText = '';
      
      if (scanType === 'nmap' && data.scan) {
        resultsText = 'Open ports found:\n';
        Object.keys(data.scan).forEach(host => {
          const hostData = data.scan[host];
          if (hostData.tcp) {
            Object.keys(hostData.tcp).forEach(port => {
              const portData = hostData.tcp[port];
              if (portData.state === 'open') {
                resultsText += `• Port ${port}: ${portData.name}\n`;
              }
            });
          }
        });
      } else if (scanType === 'gobuster') {
        resultsText = `Found ${data.total_findings} directories/files`;
      }

      if (resultsText) {
        message.blocks.push({
          type: "section",
          text: {
            type: "mrkdwn",
            text: resultsText
          }
        });
      }
    } else if (error) {
      message.blocks.push({
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Error:* ${error}`
        }
      });
    }

    return message;
  }

  /**
   * Format scan results for GitHub issue
   * @param {Object} scanResults - Scan results
   * @returns {string} Markdown formatted issue body
   */
  formatScanResultsForGitHub(scanResults) {
    const { scanType, target, data, success, error, timestamp } = scanResults;

    let markdown = `
## Security Scan Results

**Scan Type:** ${scanType.toUpperCase()}
**Target:** ${target}
**Timestamp:** ${timestamp}
**Status:** ${success ? '✅ Success' : '❌ Failed'}

`;

    if (success && data) {
      if (scanType === 'nmap' && data.scan) {
        markdown += '### Port Scan Results\n\n';
        Object.keys(data.scan).forEach(host => {
          const hostData = data.scan[host];
          if (hostData.tcp) {
            markdown += `**Host:** ${host}\n\n`;
            markdown += '| Port | State | Service |\n|------|-------|----------|\n';
            Object.keys(hostData.tcp).forEach(port => {
              const portData = hostData.tcp[port];
              markdown += `| ${port} | ${portData.state} | ${portData.name} |\n`;
            });
            markdown += '\n';
          }
        });
      } else if (scanType === 'gobuster') {
        markdown += '### Directory/File Scan Results\n\n';
        markdown += `**Total findings:** ${data.total_findings}\n\n`;
        
        if (data.directories_found && data.directories_found.length > 0) {
          markdown += '#### Directories Found\n';
          data.directories_found.forEach(dir => {
            markdown += `- ${dir}\n`;
          });
          markdown += '\n';
        }
        
        if (data.files_found && data.files_found.length > 0) {
          markdown += '#### Files Found\n';
          data.files_found.forEach(file => {
            markdown += `- ${file}\n`;
          });
          markdown += '\n';
        }
      }
    } else if (error) {
      markdown += `### Error\n\n\`\`\`\n${error}\n\`\`\`\n`;
    }

    return markdown;
  }
}

module.exports = new NotificationService();
