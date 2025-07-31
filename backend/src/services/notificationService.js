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

      console.log('Email configuration check:');
      console.log('- Email enabled:', emailEnabled);
      console.log('- Email user:', emailUser ? 'Configured' : 'Not configured');
      console.log('- Email password:', emailPassword ? 'Configured' : 'Not configured');

      if (!emailEnabled) {
        console.log('Email notifications are disabled in configuration');
        this.emailEnabled = false;
        return;
      }

      if (!emailUser || !emailPassword || emailUser === 'test@gmail.com') {
        console.log('Email credentials not configured properly. Email notifications will be disabled.');
        this.emailEnabled = false;
        return;
      }

      this.emailTransporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: emailUser,
          pass: emailPassword
        },
        tls: {
          rejectUnauthorized: false
        }
      });

      // Test the connection
      this.emailTransporter.verify((error, success) => {
        if (error) {
          console.error('Email transporter verification failed:', error.message);
          this.emailEnabled = false;
        } else {
          console.log('Email transporter initialized and verified successfully');
          this.emailEnabled = true;
        }
      });

    } catch (error) {
      console.error('Failed to initialize email transporter:', error.message);
      this.emailEnabled = false;
    }
  }

  /**
   * Send email notification with enhanced AI report support
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
        console.log('Email transporter not initialized, attempting to reinitialize...');
        this.initializeEmailTransporter();
        
        // Wait a bit for initialization
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        if (!this.emailTransporter) {
          return {
            success: false,
            error: 'Email transporter not initialized',
            skipped: true
          };
        }
      }

      const { to, from = process.env.EMAIL_USER } = config;
      
      if (!to) {
        const defaultRecipient = process.env.DEFAULT_EMAIL_RECIPIENT;
        if (!defaultRecipient || defaultRecipient === 'your_email@gmail.com') {
          console.error('No valid email recipient found');
          return {
            success: false,
            error: 'No email recipient configured. Please set an email address in the email node.',
            skipped: true
          };
        }
        config.to = defaultRecipient;
      }

      // Enhanced email formatting with AI report support
      const emailBody = this.formatEnhancedEmailWithAI(scanResults, subject);

      const mailOptions = {
        from: from || process.env.EMAIL_USER,
        to: config.to,
        subject: subject || 'VulnPilot Security Scan Results',
        html: emailBody,
        // Ensure proper HTML email headers
        headers: {
          'Content-Type': 'text/html; charset=UTF-8',
          'MIME-Version': '1.0',
          'X-Mailer': 'VulnPilot Security Scanner'
        },
        // Explicitly set the encoding
        encoding: 'utf-8'
      };

      console.log(`Sending email to: ${config.to}`);
      const result = await this.emailTransporter.sendMail(mailOptions);
      
      console.log('Email sent successfully:', result.messageId);
      return {
        success: true,
        messageId: result.messageId,
        recipient: config.to
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
            'User-Agent': 'Vulnpilot-Workflow'
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

  /**
   * Format enhanced email with AI report support
   * @param {Object} scanResults - All scan results including AI report
   * @param {string} subject - Email subject
   * @returns {string} HTML email body
   */
  formatEnhancedEmailWithAI(scanResults, subject) {
    const timestamp = new Date().toLocaleString();
    
    // Check if we have AI report data
    const hasAIReport = scanResults && scanResults.ai_report && scanResults.ai_report.ai_report;
    
    let html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>VulnPilot Security Report</title>
          <style>
            body { 
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
              line-height: 1.6; 
              color: #333; 
              max-width: 800px; 
              margin: 0 auto; 
              padding: 20px; 
              background-color: #f8f9fa;
            }
            .header { 
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
              color: white; 
              padding: 30px; 
              border-radius: 10px 10px 0 0; 
              text-align: center;
            }
            .content { 
              background: white; 
              padding: 30px; 
              border-radius: 0 0 10px 10px; 
              box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            .grade-badge { 
              display: inline-block; 
              padding: 10px 20px; 
              border-radius: 50px; 
              font-size: 24px; 
              font-weight: bold; 
              margin: 20px 0;
            }
            .grade-a { background: #d4edda; color: #155724; }
            .grade-b { background: #cce6ff; color: #004085; }
            .grade-c { background: #fff3cd; color: #856404; }
            .grade-d { background: #f8d7da; color: #721c24; }
            .grade-f { background: #f5c6cb; color: #721c24; }
            .alert { 
              padding: 15px; 
              border-radius: 8px; 
              margin: 15px 0; 
              border-left: 4px solid;
            }
            .alert-critical { background: #f8d7da; border-color: #dc3545; color: #721c24; }
            .alert-warning { background: #fff3cd; border-color: #ffc107; color: #856404; }
            .alert-info { background: #d1ecf1; border-color: #17a2b8; color: #0c5460; }
            .alert-success { background: #d4edda; border-color: #28a745; color: #155724; }
            .tech-details { 
              background: #f8f9fa; 
              border: 1px solid #dee2e6; 
              border-radius: 8px; 
              padding: 20px; 
              margin: 20px 0;
            }
            .footer { 
              text-align: center; 
              margin-top: 30px; 
              padding: 20px; 
              color: #6c757d; 
              font-size: 14px;
            }
            h1, h2, h3 { color: #333; }
            h2 { border-bottom: 2px solid #667eea; padding-bottom: 10px; }
            ul { padding-left: 20px; }
            li { margin: 8px 0; }
            .scan-summary { 
              background: #e3f2fd; 
              padding: 20px; 
              border-radius: 8px; 
              margin: 20px 0;
            }
          </style>
        </head>
        <body>
          <div class="header">
            <h1>🛡️ VulnPilot Security Report</h1>
            <p>Website Security Assessment Complete</p>
            <p><strong>Scan Date:</strong> ${timestamp}</p>
          </div>
          
          <div class="content">
    `;

    if (hasAIReport) {
      // Extract security grade and critical info
      const aiData = scanResults.ai_report;
      const grade = aiData.security_grade || 'N/A';
      const totalIssues = aiData.total_issues || 0;
      const criticalIssues = aiData.critical_issues || 0;
      
      // Add security grade section
      const gradeClass = `grade-${grade.toLowerCase()}`;
      html += `
        <div class="scan-summary">
          <h2>🎯 Executive Summary</h2>
          <div style="text-align: center;">
            <div class="grade-badge ${gradeClass}">Security Grade: ${grade}</div>
            <p><strong>${totalIssues}</strong> total security issues found</p>
            ${criticalIssues > 0 ? `<div class="alert alert-critical">⚠️ <strong>${criticalIssues}</strong> critical issues require immediate attention!</div>` : ''}
          </div>
        </div>
      `;

      // Convert AI report markdown to HTML for email
      const aiReportHtml = this.convertMarkdownToHTML(aiData.ai_report);
      html += `
        <div>
          <h2>📋 Security Analysis Report</h2>
          ${aiReportHtml}
        </div>
      `;
    } else {
      // Fallback to basic scan results if no AI report
      html += `
        <div class="scan-summary">
          <h2>📊 Scan Results Summary</h2>
          <p>A security scan was completed, but detailed analysis is not available.</p>
        </div>
      `;
      
      // Add basic scan results
      html += this.formatBasicScanResults(scanResults);
    }

    // Add technical details section
    html += `
      <div class="tech-details">
        <h3>🔧 Technical Details</h3>
        <p><strong>Report generated by:</strong> ${hasAIReport ? (scanResults.ai_report.generated_by || 'VulnPilot AI') : 'VulnPilot Scanner'}</p>
        <p><strong>Scan timestamp:</strong> ${timestamp}</p>
        <p><strong>Target:</strong> ${scanResults.ai_report?.target_url || 'Multiple targets'}</p>
      </div>
    `;

    html += `
          </div>
          
          <div class="footer">
            <p>📧 This report was automatically generated by VulnPilot Security Scanner</p>
            <p>For questions or support, please contact your security team.</p>
            <p><em>Keep your digital assets secure! 🔒</em></p>
          </div>
        </body>
      </html>
    `;

    return html;
  }

  /**
   * Convert markdown-style text to HTML for email
   * @param {string} markdownText - Text with markdown formatting
   * @returns {string} HTML formatted text
   */
  convertMarkdownToHTML(markdownText) {
    if (!markdownText) return '<p>No report content available.</p>';
    
    // Split content into paragraphs first, then process each paragraph
    const paragraphs = markdownText.split('\n\n').filter(p => p.trim() !== '');
    let htmlParts = [];
    
    for (let paragraph of paragraphs) {
      paragraph = paragraph.trim();
      if (!paragraph) continue;
      
      // Handle headers
      if (paragraph.startsWith('# ')) {
        const title = paragraph.substring(2).trim();
        htmlParts.push(`<h1 style="color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 8px; margin-top: 20px; margin-bottom: 15px;">${title}</h1>`);
        continue;
      }
      
      if (paragraph.startsWith('## ')) {
        const title = paragraph.substring(3).trim();
        htmlParts.push(`<h2 style="color: #495057; margin-top: 25px; margin-bottom: 15px; border-bottom: 1px solid #dee2e6; padding-bottom: 5px;">${title}</h2>`);
        continue;
      }
      
      if (paragraph.startsWith('### ')) {
        const title = paragraph.substring(4).trim();
        htmlParts.push(`<h3 style="color: #6c757d; margin-top: 20px; margin-bottom: 10px;">${title}</h3>`);
        continue;
      }
      
      // Handle horizontal rules
      if (paragraph === '---') {
        htmlParts.push('<hr style="border: none; border-top: 2px solid #dee2e6; margin: 25px 0;">');
        continue;
      }
      
      // Handle lists
      const lines = paragraph.split('\n');
      if (lines.some(line => line.match(/^[0-9]+\.\s/) || line.match(/^-\s/))) {
        let listItems = [];
        let isOrderedList = lines[0].match(/^[0-9]+\.\s/);
        
        for (let line of lines) {
          if (line.match(/^[0-9]+\.\s/) || line.match(/^-\s/)) {
            const content = line.replace(/^[0-9]+\.\s/, '').replace(/^-\s/, '').trim();
            const processedContent = this.processInlineMarkdown(content);
            listItems.push(`<li style="margin: 8px 0; line-height: 1.5;">${processedContent}</li>`);
          }
        }
        
        if (listItems.length > 0) {
          const listTag = isOrderedList ? 'ol' : 'ul';
          htmlParts.push(`<${listTag} style="margin: 15px 0; padding-left: 25px;">${listItems.join('')}</${listTag}>`);
        }
        continue;
      }
      
      // Handle special alert boxes
      if (paragraph.includes('🚨 **URGENT**') || paragraph.includes('⚠️ **Important**') || 
          paragraph.includes('📝 **Good to Fix**') || paragraph.includes('✅ **')) {
        
        let alertClass = 'background: #f8f9fa; border: 1px solid #dee2e6;';
        
        if (paragraph.includes('🚨 **URGENT**')) {
          alertClass = 'background: #f8d7da; border: 1px solid #f5c6cb; border-left: 4px solid #dc3545; color: #721c24;';
        } else if (paragraph.includes('⚠️ **Important**')) {
          alertClass = 'background: #fff3cd; border: 1px solid #ffeaa7; border-left: 4px solid #ffc107; color: #856404;';
        } else if (paragraph.includes('📝 **Good to Fix**')) {
          alertClass = 'background: #d1ecf1; border: 1px solid #bee5eb; border-left: 4px solid #17a2b8; color: #0c5460;';
        } else if (paragraph.includes('✅ **')) {
          alertClass = 'background: #d4edda; border: 1px solid #c3e6cb; border-left: 4px solid #28a745; color: #155724;';
        }
        
        const processedContent = this.processInlineMarkdown(paragraph);
        htmlParts.push(`<div style="${alertClass} padding: 15px; margin: 15px 0; border-radius: 5px;">${processedContent}</div>`);
        continue;
      }
      
      // Regular paragraph
      const processedContent = this.processInlineMarkdown(paragraph);
      htmlParts.push(`<p style="margin: 10px 0; line-height: 1.6;">${processedContent}</p>`);
    }
    
    const html = htmlParts.join('\n');
    return html;
  }

  /**
   * Process inline markdown formatting (bold, italic, line breaks)
   * @param {string} text - Text to process
   * @returns {string} Processed text with HTML formatting
   */
  processInlineMarkdown(text) {
    return text
      // Convert line breaks within paragraphs
      .replace(/\n/g, '<br>')
      // Convert emphasis (order matters - triple before double)
      .replace(/\*\*\*(.*?)\*\*\*/g, '<strong style="color: #dc3545; font-weight: bold;">$1</strong>')
      .replace(/\*\*(.*?)\*\*/g, '<strong style="font-weight: bold;">$1</strong>')
      .replace(/\*(.*?)\*/g, '<em style="font-style: italic;">$1</em>');
  }

  /**
   * Format basic scan results when AI report is not available
   * @param {Object} scanResults - Raw scan results
   * @returns {string} HTML formatted scan results
   */
  formatBasicScanResults(scanResults) {
    if (!scanResults || typeof scanResults !== 'object') {
      return '<p>No scan results available.</p>';
    }

    let html = '<div class="tech-details"><h3>Raw Scan Results</h3>';
    
    // If it's an array of results
    if (Array.isArray(scanResults)) {
      scanResults.forEach((result, index) => {
        html += `<h4>Scan ${index + 1}</h4>`;
        html += this.formatSingleScanResult(result);
      });
    } else {
      // Single result or object with multiple scan types
      Object.entries(scanResults).forEach(([key, value]) => {
        if (key !== 'ai_report' && value && typeof value === 'object') {
          html += `<h4>${key.replace('_', ' ').toUpperCase()}</h4>`;
          html += this.formatSingleScanResult(value);
        }
      });
    }
    
    html += '</div>';
    return html;
  }

  /**
   * Format a single scan result
   * @param {Object} result - Single scan result
   * @returns {string} HTML formatted result
   */
  formatSingleScanResult(result) {
    if (!result || typeof result !== 'object') {
      return '<p>Invalid scan result.</p>';
    }
    
    const { scanType, target, data, success, error, timestamp } = result;
    
    let html = '<div style="margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 5px;">';
    html += `<p><strong>Type:</strong> ${scanType || 'Unknown'}</p>`;
    html += `<p><strong>Target:</strong> ${target || 'N/A'}</p>`;
    html += `<p><strong>Status:</strong> ${success ? '✅ Success' : '❌ Failed'}</p>`;
    
    if (error) {
      html += `<p><strong>Error:</strong> <span style="color: #dc3545;">${error}</span></p>`;
    }
    
    if (data && success) {
      html += '<p><strong>Results:</strong> Scan completed successfully</p>';
    }
    
    html += '</div>';
    return html;
  }
}

module.exports = new NotificationService();
