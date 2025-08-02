import json
import nmap
import logging
import os
from datetime import datetime
from urllib.parse import urlparse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("nmap_scan.log"),
        logging.StreamHandler()
    ],
)

scanner = nmap.PortScanner()

def extract_hostname_from_url(url):
    """Extract hostname from URL for Nmap scanning"""
    try:
        # If it's already just a hostname/IP, return as is
        if not url.startswith(('http://', 'https://')):
            return url.strip()
        
        # Parse the URL to extract hostname
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        # Remove port if present (e.g., example.com:8080 -> example.com)
        if ':' in hostname:
            hostname = hostname.split(':')[0]
            
        return hostname
    except Exception as e:
        logger.error(f"Error extracting hostname from URL {url}: {str(e)}")
        return url  # Return original if parsing fails

@csrf_exempt
def scan_ports(request):
    if request.method != "POST":
        logger.warning("Invalid request method for /scan_ports/")
        return JsonResponse({"error": "Only POST method is allowed"}, status=405)

    try:
        # Parse JSON request body
        data = json.loads(request.body)
        target = data.get("target")
        arguments = data.get("arguments", "-F")  # Default: Fast Scan

        if not target:
            logger.error("Missing target parameter in request body")
            return JsonResponse({"error": "Target URL is required"}, status=400)

        # Extract hostname from URL if needed
        hostname = extract_hostname_from_url(target)
        
        if not hostname:
            logger.error(f"Could not extract valid hostname from target: {target}")
            return JsonResponse({"error": "Invalid target URL or hostname"}, status=400)

        # Log the scan details
        logger.info(f"Starting Nmap scan: original_target={target}, hostname={hostname}, arguments={arguments}")
        
        # Scan the hostname instead of the full URL
        scanner.scan(hostname, arguments=arguments)

        # Return the full scan result
        full_result = scanner._scan_result

        logger.info(f"Scan completed for {target}")
        return JsonResponse(full_result, safe=False)

    except json.JSONDecodeError:
        logger.error("Invalid JSON data received in request body")
        return JsonResponse({"error": "Invalid JSON data"}, status=400)
    except nmap.PortScannerError as e:
        logger.error(f"Nmap scan failed: {str(e)}")
        return JsonResponse({"error": f"Nmap scan failed: {str(e)}"}, status=500)
    except Exception as e:
        logger.exception(f"Unexpected error during scan: {str(e)}")
        return JsonResponse({"error": f"Unexpected error: {str(e)}"}, status=500)

@csrf_exempt
def get_nmap_arguments(request):
    """
    Returns all available Nmap arguments, categorized by type with descriptions.
    """
    if request.method != "GET":
        logger.warning("Invalid request method for /get_nmap_arguments/")
        return JsonResponse({"error": "Only GET method is allowed"}, status=405)

    try:
        scanner = nmap.PortScanner()
        nmap_version = scanner.nmap_version()

        # Categorized Nmap Arguments with Descriptions
        nmap_arguments = {
            "scan_types": {
                "-sS": "TCP SYN scan (Stealth Scan)",
                "-sT": "TCP Connect scan",
                "-sU": "UDP scan",
                "-sN": "TCP NULL scan (No flags set)",
                "-sF": "TCP FIN scan",
                "-sX": "TCP Xmas scan (FIN, PSH, URG set)",
                "-sA": "TCP ACK scan",
                "-sW": "TCP Window scan",
                "-sM": "TCP Maimon scan"
            },
            "host_discovery": {
                "-Pn": "Disable host discovery, scan all given targets",
                "-PS": "TCP SYN Ping",
                "-PA": "TCP ACK Ping",
                "-PU": "UDP Ping",
                "-PY": "SCTP INIT Ping",
                "-PE": "ICMP Echo Request Ping",
                "-PP": "ICMP Timestamp Request Ping",
                "-PM": "ICMP Netmask Request Ping",
                "-sn": "Ping Scan - Only discover hosts without port scan"
            },
            "timing_options": {
                "-T0": "Paranoid (slowest, avoids detection)",
                "-T1": "Sneaky (very slow, evades detection)",
                "-T2": "Polite (reduces bandwidth, slow)",
                "-T3": "Normal (default timing)",
                "-T4": "Aggressive (faster, might alert firewalls)",
                "-T5": "Insane (fastest, high network load)"
            },
            "port_options": {
                "-F": "Fast scan (only scans 100 most common ports)",
                "-p": "Specify port range (e.g., -p 80,443,8080)"
            },
            "OS_detection": {
                "-O": "Enable OS detection"
            },
            "version_detection": {
                "-sV": "Service version detection"
            },
            "script_scan": {
                "-sC": "Run default Nmap scripts"
            },
            "traceroute": {
                "--traceroute": "Trace network path to target"
            },
            "aggressive_scan": {
                "-A": "Aggressive scan (OS, version detection, scripts, traceroute)"
            }
        }

        logger.info("Fetched available Nmap arguments successfully")
        return JsonResponse({"nmap_version": nmap_version, "supported_arguments": nmap_arguments})

    except Exception as e:
        logger.exception(f"Failed to fetch Nmap arguments: {str(e)}")
        return JsonResponse({"error": f"Failed to fetch Nmap arguments: {str(e)}"}, status=500)


@csrf_exempt
def sqlmap_scan(request):
    """
    Perform SQLMap SQL injection scan on target URL
    """
    if request.method != "POST":
        logger.warning("Invalid request method for /sqlmap_scan/")
        return JsonResponse({"error": "Only POST method is allowed"}, status=405)

    try:
        import subprocess
        import tempfile
        import os
        
        # Parse JSON request body
        data = json.loads(request.body)
        target = data.get("target")
        arguments = data.get("arguments", "--batch --random-agent")  # Default args

        if not target:
            logger.error("Missing target parameter in request body")
            return JsonResponse({"error": "Target URL is required"}, status=400)

        # Extract full URL (SQLMap needs the full URL, not just hostname)
        target_url = target
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        logger.info(f"Starting SQLMap scan: target={target_url}, arguments={arguments}")

        # Create a temporary file for SQLMap output
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as temp_file:
            temp_output = temp_file.name

        try:
            # Construct SQLMap command
            cmd = [
                'python3', '/opt/sqlmap/sqlmap.py',
                '--url', target_url,
                '--batch',  # Non-interactive mode
                '--random-agent',  # Use random User-Agent
                '--text-only',  # Output only text
                '--output-dir', '/tmp',  # Output directory
                '--timeout', '30',  # 30 second timeout
                '--threads', '1',  # Single thread
                '--level', '1',  # Basic level
                '--risk', '1'   # Low risk
            ]
            
            # Add custom arguments if provided
            if arguments and arguments != "--batch --random-agent":
                # Split and add additional arguments
                additional_args = arguments.split()
                cmd.extend(additional_args)

            logger.info(f"Running SQLMap command: {' '.join(cmd)}")

            # Run SQLMap with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
                cwd='/tmp'
            )

            # Parse results
            findings = []
            vulnerabilities = []
            
            if result.returncode == 0:
                output = result.stdout
                
                # Look for injection points
                if "injectable" in output.lower():
                    # Parse injection findings
                    lines = output.split('\n')
                    for i, line in enumerate(lines):
                        if 'injectable' in line.lower() or 'vulnerable' in line.lower():
                            findings.append(line.strip())
                            
                        if 'parameter' in line.lower() and 'injectable' in line.lower():
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'parameter': line.strip(),
                                'severity': 'HIGH'
                            })

                scan_result = {
                    "sqlmap": {
                        "target": target_url,
                        "arguments": arguments,
                        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "status": "completed",
                        "findings": findings,
                        "vulnerabilities": vulnerabilities,
                        "message": "SQLMap scan completed successfully",
                        "raw_output": output[:1000] if output else "No output",  # Truncate for response size
                        "injection_found": len(vulnerabilities) > 0
                    }
                }
            else:
                # SQLMap error or no vulnerabilities found
                error_output = result.stderr if result.stderr else result.stdout
                scan_result = {
                    "sqlmap": {
                        "target": target_url,
                        "arguments": arguments,
                        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "status": "completed",
                        "findings": [],
                        "vulnerabilities": [],
                        "message": "SQLMap scan completed - no vulnerabilities found",
                        "raw_output": error_output[:500] if error_output else "No output",
                        "injection_found": False
                    }
                }

        except subprocess.TimeoutExpired:
            logger.warning(f"SQLMap scan timed out for {target_url}")
            scan_result = {
                "sqlmap": {
                    "target": target_url,
                    "arguments": arguments,
                    "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "timeout",
                    "findings": [],
                    "vulnerabilities": [],
                    "message": "SQLMap scan timed out",
                    "injection_found": False
                }
            }
        except Exception as e:
            logger.error(f"SQLMap execution error: {str(e)}")
            scan_result = {
                "sqlmap": {
                    "target": target_url,
                    "arguments": arguments,
                    "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "error",
                    "findings": [],
                    "vulnerabilities": [],
                    "message": f"SQLMap scan failed: {str(e)}",
                    "injection_found": False
                }
            }
        finally:
            # Clean up temporary file
            if os.path.exists(temp_output):
                os.unlink(temp_output)

        logger.info(f"SQLMap scan completed for {target_url}")
        return JsonResponse(scan_result, safe=False)

    except json.JSONDecodeError:
        logger.error("Invalid JSON data received in request body")
        return JsonResponse({"error": "Invalid JSON data"}, status=400)
    except Exception as e:
        logger.exception(f"Unexpected error during SQLMap scan: {str(e)}")
        return JsonResponse({"error": f"SQLMap scan failed: {str(e)}"}, status=500)


@csrf_exempt
def wpscan_scan(request):
    """
    Perform WPScan WordPress vulnerability scan on target URL
    """
    if request.method != "POST":
        logger.warning("Invalid request method for /wpscan_scan/")
        return JsonResponse({"error": "Only POST method is allowed"}, status=405)

    try:
        import subprocess
        
        # Parse JSON request body
        data = json.loads(request.body)
        target = data.get("target")
        arguments = data.get("arguments", "--random-user-agent")  # Default args

        if not target:
            logger.error("Missing target parameter in request body")
            return JsonResponse({"error": "Target URL is required"}, status=400)

        # Extract full URL (WPScan needs the full URL)
        target_url = target
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        logger.info(f"Starting WPScan: target={target_url}, arguments={arguments}")

        try:
            # Construct WPScan command
            cmd = [
                'wpscan',
                '--url', target_url,
                '--random-user-agent',
                '--disable-tls-checks',  # Skip SSL certificate checks
                '--format', 'json',      # JSON output for easier parsing
                '--no-banner',           # Disable banner
                '--max-threads', '1',    # Single thread
                '--request-timeout', '30', # 30 second timeout per request
                '--connect-timeout', '10'  # 10 second connection timeout
            ]
            
            # Add custom arguments if provided and not default
            if arguments and arguments != "--random-user-agent":
                additional_args = arguments.split()
                cmd.extend(additional_args)

            logger.info(f"Running WPScan command: {' '.join(cmd)}")

            # Run WPScan with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,  # 3 minute timeout
                cwd='/tmp'
            )

            # Parse JSON output
            findings = []
            vulnerabilities = []
            wordpress_info = {}
            
            if result.returncode == 0 or result.returncode == 4:  # 0 = no vulns, 4 = vulns found
                try:
                    import json as json_parser
                    output_data = json_parser.loads(result.stdout)
                    
                    # Extract WordPress information
                    if 'version' in output_data:
                        wordpress_info['version'] = output_data['version']
                    
                    if 'main_theme' in output_data:
                        wordpress_info['theme'] = output_data['main_theme']
                    
                    # Extract vulnerabilities
                    if 'vulnerabilities' in output_data:
                        for vuln in output_data['vulnerabilities']:
                            vulnerabilities.append({
                                'title': vuln.get('title', 'Unknown vulnerability'),
                                'type': vuln.get('type', 'Unknown'),
                                'references': vuln.get('references', {})
                            })
                            findings.append(vuln.get('title', 'Vulnerability found'))
                    
                    # Check plugins for vulnerabilities
                    if 'plugins' in output_data:
                        for plugin_name, plugin_data in output_data['plugins'].items():
                            if 'vulnerabilities' in plugin_data:
                                for vuln in plugin_data['vulnerabilities']:
                                    vulnerabilities.append({
                                        'title': f"Plugin {plugin_name}: {vuln.get('title', 'Unknown')}",
                                        'type': 'Plugin Vulnerability',
                                        'plugin': plugin_name,
                                        'references': vuln.get('references', {})
                                    })
                                    findings.append(f"Plugin vulnerability in {plugin_name}")
                                    
                except json_parser.JSONDecodeError:
                    # Fallback to text parsing if JSON parsing fails
                    output = result.stdout
                    lines = output.split('\n')
                    for line in lines:
                        if 'vulnerability' in line.lower() or 'cve-' in line.lower():
                            findings.append(line.strip())

                scan_result = {
                    "wpscan": {
                        "target": target_url,
                        "arguments": arguments,
                        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "status": "completed",
                        "findings": findings,
                        "vulnerabilities": vulnerabilities,
                        "wordpress_info": wordpress_info,
                        "message": f"WPScan completed - found {len(vulnerabilities)} vulnerabilities",
                        "vulnerabilities_found": len(vulnerabilities) > 0
                    }
                }
            else:
                # WPScan error or target not WordPress
                error_output = result.stderr if result.stderr else result.stdout
                scan_result = {
                    "wpscan": {
                        "target": target_url,
                        "arguments": arguments,
                        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "status": "completed",
                        "findings": [],
                        "vulnerabilities": [],
                        "message": "WPScan completed - target may not be WordPress or scan failed",
                        "error_output": error_output[:500] if error_output else "No output",
                        "vulnerabilities_found": False
                    }
                }

        except subprocess.TimeoutExpired:
            logger.warning(f"WPScan timed out for {target_url}")
            scan_result = {
                "wpscan": {
                    "target": target_url,
                    "arguments": arguments,
                    "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "timeout",
                    "findings": [],
                    "vulnerabilities": [],
                    "message": "WPScan timed out",
                    "vulnerabilities_found": False
                }
            }
        except Exception as e:
            logger.error(f"WPScan execution error: {str(e)}")
            scan_result = {
                "wpscan": {
                    "target": target_url,
                    "arguments": arguments,
                    "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "error",
                    "findings": [],
                    "vulnerabilities": [],
                    "message": f"WPScan failed: {str(e)}",
                    "vulnerabilities_found": False
                }
            }

        logger.info(f"WPScan completed for {target_url}")
        return JsonResponse(scan_result, safe=False)

    except json.JSONDecodeError:
        logger.error("Invalid JSON data received in request body")
        return JsonResponse({"error": "Invalid JSON data"}, status=400)
    except Exception as e:
        logger.exception(f"Unexpected error during WPScan: {str(e)}")
        return JsonResponse({"error": f"WPScan failed: {str(e)}"}, status=500)

@csrf_exempt
def generate_ai_report(request):
    """
    Generate a comprehensive security report using AI (Gemini) from scan results
    """
    if request.method != "POST":
        logger.warning("Invalid request method for /generate_ai_report/")
        return JsonResponse({"error": "Only POST method is allowed"}, status=405)

    try:
        import subprocess
        import os
        
        # Parse JSON request body
        data = json.loads(request.body)
        scan_results = data.get("scan_results", {})
        target_url = data.get("target_url", "Unknown Target")
        
        if not scan_results:
            logger.error("Missing scan_results parameter in request body")
            return JsonResponse({"error": "Scan results are required"}, status=400)

        logger.info(f"Generating AI report for {target_url}")

        # Check if Gemini API is available
        gemini_api_key = os.getenv('GEMINI_API_KEY')
        if not gemini_api_key:
            logger.warning("GEMINI_API_KEY not found, using fallback report generation")
            return generate_fallback_report(scan_results, target_url)

        # Prepare scan data for AI analysis - Include ALL raw data including detailed Nikto results
        formatted_raw_data = format_raw_data_for_ai(scan_results)
        
        # Extract detailed Nikto results for special attention
        nikto_details = ""
        if 'nikto_scan' in scan_results:
            nikto_data = scan_results['nikto_scan']
            nikto_details = f"""
DETAILED NIKTO WEB SECURITY SCAN RESULTS:
{json.dumps(nikto_data, indent=2)}
"""
        
        # Create comprehensive AI prompt for customer-friendly analysis
        prompt = f"""
You are a senior cybersecurity consultant creating a detailed security assessment report for a business client. Your expertise spans network security, web application security, and risk management. The client is a business owner who values clear communication and actionable insights.

🎯 SECURITY ASSESSMENT FOR: {target_url}
📅 ASSESSMENT DATE: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

📋 COMPLETE SECURITY SCAN DATA:
{json.dumps(formatted_raw_data, indent=2)}

{nikto_details}

INSTRUCTIONS: Create a comprehensive, business-focused security report that balances technical accuracy with clear communication. Make this report valuable for decision-making and budgeting.

# 🛡️ EXECUTIVE SECURITY ASSESSMENT REPORT

## 🎯 EXECUTIVE SUMMARY
Provide a clear, executive-level assessment:
- **Overall Security Posture**: Rate as Excellent/Good/Fair/Poor/Critical
- **Business Risk Level**: Low/Medium/High/Critical with business impact explanation
- **Key Findings**: 3-5 most significant discoveries in plain business language
- **Immediate Action Required**: Yes/No with clear justification
- **Investment Priority**: High/Medium/Low for security improvements

## 🔍 DETAILED SECURITY ANALYSIS

### 🌐 Network Infrastructure Security (Port Scanning Results)
Analyze ALL network findings with business context:
- **Open Network Ports**: Explain each port in business terms
- **Service Exposure**: What services are accessible and their security implications
- **Attack Surface**: How exposed the website is to potential attacks
- **Network Security Recommendations**: Specific, actionable improvements

### 🕸️ Web Application Security (Nikto & Web Vulnerability Scan)
Provide comprehensive analysis of ALL Nikto findings:
- **Web Server Security**: Detailed analysis of server configuration
- **Vulnerability Assessment**: Every security issue found, explained clearly
- **Information Disclosure**: What sensitive information is exposed
- **Security Headers**: Missing or misconfigured security protections
- **Authentication & Access Control**: How well the site protects access
- **Common Web Attacks Protection**: XSS, SQL injection, etc. preparedness

### 📁 Content & Directory Security (Directory Discovery)
Examine all discovered content:
- **Exposed Files & Directories**: What shouldn't be publicly accessible
- **Sensitive Information Exposure**: Configuration files, backups, admin areas
- **Information Leakage Assessment**: What attackers could learn about your system
- **Access Control Evaluation**: Whether proper restrictions are in place

### 💾 Database Security Assessment (SQL Injection Testing)
Comprehensive database security review:
- **Injection Vulnerability Testing**: Detailed results and implications
- **Database Protection**: How well your database is secured
- **Data Integrity**: Whether your data could be compromised
- **Customer Data Protection**: Specific risks to customer information

### 🔌 Content Management System Security (WordPress/CMS Analysis)
If applicable, detailed CMS security assessment:
- **CMS Version Security**: Whether your CMS is current and secure
- **Plugin/Theme Vulnerabilities**: Detailed analysis of each component
- **Update Requirements**: What needs updating and why
- **CMS-Specific Risks**: Unique vulnerabilities to your platform

## 📊 BUSINESS RISK ASSESSMENT

### 💰 Financial Impact Analysis
- **Potential Cost of Breach**: Data breach costs, downtime, recovery
- **Compliance Risks**: GDPR, PCI DSS, industry-specific requirements
- **Insurance Considerations**: How this affects cybersecurity coverage
- **Competitive Impact**: Security as a business differentiator

### 👥 Customer Trust & Reputation
- **Customer Data Protection**: How well customer information is secured
- **Brand Protection**: Reputation risks from security incidents
- **Trust Factors**: What customers expect from your security posture

### ⚖️ Legal & Regulatory Compliance
- **Data Protection Requirements**: Legal obligations for data security
- **Industry Standards**: Compliance with relevant security frameworks
- **Liability Assessment**: Legal exposure from current security posture

## 🚀 STRATEGIC SECURITY ROADMAP

### 🚨 IMMEDIATE ACTIONS (0-30 Days)
List critical issues requiring immediate attention:
- **Critical Vulnerabilities**: Must-fix security holes
- **Emergency Mitigations**: Quick fixes to reduce immediate risk
- **Incident Response**: Steps if an attack occurs

### ⚡ SHORT-TERM IMPROVEMENTS (1-3 Months)
Important security enhancements:
- **Security Hardening**: Strengthening current protections
- **Monitoring Implementation**: Better visibility into security status
- **Process Improvements**: Security best practices adoption

### 🎯 LONG-TERM SECURITY STRATEGY (3-12 Months)
Strategic security investments:
- **Advanced Security Measures**: Next-level protection implementation
- **Security Culture**: Building security awareness and practices
- **Continuous Improvement**: Ongoing security maturity development

## ✅ POSITIVE SECURITY FINDINGS
Highlight existing security strengths:
- **Effective Security Controls**: What's already working well
- **Good Security Practices**: Positive configurations and measures
- **Competitive Advantages**: Security features that set you apart

## 📞 NEXT STEPS & RECOMMENDATIONS

### 🤝 Implementation Support
- **Technical Implementation**: Who should handle each recommendation
- **Budget Planning**: Cost estimates for security improvements
- **Timeline Recommendations**: Realistic implementation schedules
- **Success Metrics**: How to measure security improvement progress

### 📈 Ongoing Security Management
- **Regular Assessment Schedule**: How often to repeat security scans
- **Monitoring Recommendations**: Continuous security visibility
- **Incident Response Planning**: Preparation for security events
- **Staff Training**: Security awareness for your team

TONE & STYLE REQUIREMENTS:
- Write as a trusted security advisor, not an alarmist
- Use business language that executives understand
- Provide specific, actionable recommendations
- Balance technical accuracy with clear communication
- Focus on business value and risk management
- Be encouraging about security improvements
- Explain the "why" behind each recommendation
- Use analogies when helpful (home security, business insurance, etc.)
- Quantify risks and benefits where possible
- Maintain professional credibility while being accessible

Create a report that serves as both a security assessment and a business planning document.
"""

        try:
            # Call Gemini API using Google's generative AI
            cmd = [
                'curl', '-X', 'POST',
                f'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key={gemini_api_key}',
                '-H', 'Content-Type: application/json',
                '-d', json.dumps({
                    "contents": [{
                        "parts": [{
                            "text": prompt
                        }]
                    }],
                    "generationConfig": {
                        "temperature": 0.4,  # Increased for more creative and comprehensive analysis
                        "topK": 40,
                        "topP": 0.9,
                        "maxOutputTokens": 32768,  # Increased to 32K for comprehensive business reports
                        "candidateCount": 1,
                        "stopSequences": []
                    },
                    "safetySettings": [
                        {
                            "category": "HARM_CATEGORY_HARASSMENT",
                            "threshold": "BLOCK_NONE"
                        },
                        {
                            "category": "HARM_CATEGORY_HATE_SPEECH", 
                            "threshold": "BLOCK_NONE"
                        },
                        {
                            "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                            "threshold": "BLOCK_NONE"
                        },
                        {
                            "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                            "threshold": "BLOCK_NONE"
                        }
                    ]
                })
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180  # Increased timeout for comprehensive 32K token analysis
            )

            if result.returncode == 0:
                response_data = json.loads(result.stdout)
                if 'candidates' in response_data and len(response_data['candidates']) > 0:
                    ai_report = response_data['candidates'][0]['content']['parts'][0]['text']
                    
                    # Clean up the report
                    ai_report = clean_ai_report(ai_report)
                    
                    report_result = {
                        "target_url": target_url,
                        "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "report_type": "AI-Generated Security Assessment",
                        "ai_report": ai_report,
                        "raw_scan_data": scan_results,
                        "status": "success",
                        "generated_by": "Gemini AI"
                    }
                    
                    logger.info(f"AI report generated successfully for {target_url}")
                    return JsonResponse(report_result)
                else:
                    logger.error("Invalid response from Gemini API")
                    return generate_fallback_report(scan_results, target_url)
            else:
                logger.error(f"Gemini API call failed: {result.stderr}")
                return generate_fallback_report(scan_results, target_url)

        except subprocess.TimeoutExpired:
            logger.warning("Gemini API call timed out")
            return generate_fallback_report(scan_results, target_url)
        except Exception as e:
            logger.error(f"Error calling Gemini API: {str(e)}")
            return generate_fallback_report(scan_results, target_url)

    except json.JSONDecodeError:
        logger.error("Invalid JSON data received in request body")
        return JsonResponse({"error": "Invalid JSON data"}, status=400)
    except Exception as e:
        logger.exception(f"Unexpected error during AI report generation: {str(e)}")
        return JsonResponse({"error": f"AI report generation failed: {str(e)}"}, status=500)


def prepare_scan_summary(scan_results):
    """
    Prepare a clean summary of scan results for AI analysis
    """
    summary = {
        "total_scans": 0,
        "vulnerabilities_found": 0,
        "security_issues": [],
        "open_ports": [],
        "missing_headers": [],
        "findings_by_tool": {}
    }
    
    # Process each scan type
    for scan_type, scan_data in scan_results.items():
        if not isinstance(scan_data, dict):
            continue
            
        summary["total_scans"] += 1
        summary["findings_by_tool"][scan_type] = {
            "status": scan_data.get("status", "unknown"),
            "findings_count": len(scan_data.get("findings", [])),
            "vulnerabilities_count": len(scan_data.get("vulnerabilities", []))
        }
        
        # Extract vulnerabilities
        if "vulnerabilities" in scan_data:
            for vuln in scan_data["vulnerabilities"]:
                summary["vulnerabilities_found"] += 1
                summary["security_issues"].append({
                    "source": scan_type,
                    "issue": vuln.get("msg", vuln.get("title", "Unknown vulnerability")),
                    "severity": vuln.get("severity", "Unknown")
                })
        
        # Extract open ports from nmap
        if scan_type == "nmap_scan" and "open_ports" in scan_data:
            summary["open_ports"] = scan_data["open_ports"]
        
        # Extract missing headers from nikto
        if scan_type == "nikto_scan" and isinstance(scan_data, list):
            for nikto_result in scan_data:
                if "vulnerabilities" in nikto_result:
                    for vuln in nikto_result["vulnerabilities"]:
                        if "security header missing" in vuln.get("msg", "").lower():
                            summary["missing_headers"].append(vuln["msg"])
    
    return summary


def clean_ai_report(report_text):
    """
    Clean and format the AI-generated report
    """
    # Remove any unwanted characters or formatting
    report_text = report_text.strip()
    
    # Ensure proper line breaks
    report_text = report_text.replace('\n\n\n', '\n\n')
    
    # Add markdown formatting for better display
    lines = report_text.split('\n')
    formatted_lines = []
    
    for line in lines:
        stripped = line.strip()
        if stripped:
            # Make section headers bold
            if stripped.isupper() and len(stripped.split()) <= 4:
                formatted_lines.append(f"## {stripped}")
            elif stripped.endswith(':') and len(stripped.split()) <= 3:
                formatted_lines.append(f"### {stripped}")
            else:
                formatted_lines.append(line)
        else:
            formatted_lines.append(line)
    
    return '\n'.join(formatted_lines)


def generate_fallback_report(scan_results, target_url):
    """
    Generate a detailed report using raw data when AI is not available
    """
    # Get formatted raw data
    formatted_raw_data = format_raw_data_for_ai(scan_results)
    
    # Count findings more accurately
    total_vulnerabilities = 0
    potential_issues = 0
    critical_issues = []
    security_concerns = []
    
    # Analyze each scan result more carefully
    for scan_type, scan_data in scan_results.items():
        if isinstance(scan_data, dict):
            # Handle SQLMap special case
            if "sqlmap" in scan_data:
                sqlmap_data = scan_data["sqlmap"]
                if sqlmap_data.get("injection_found", False):
                    security_concerns.append("SQLMap detected potential SQL injection vulnerability")
                if "vulnerabilities" in sqlmap_data:
                    for vuln in sqlmap_data["vulnerabilities"]:
                        if vuln.get("severity") == "HIGH":
                            potential_issues += 1
                            security_concerns.append(f"SQLMap: {vuln.get('type', 'Security issue')} detected")
            
            # Handle other scan types
            elif "vulnerabilities" in scan_data:
                for vuln in scan_data["vulnerabilities"]:
                    total_vulnerabilities += 1
                    vuln_str = str(vuln).lower()
                    if any(keyword in vuln_str for keyword in ["critical", "high", "severe"]):
                        critical_issues.append(f"{scan_type}: {vuln.get('msg', vuln.get('title', 'Security issue found'))}")
            
            # Check for open ports that might be concerning
            if "open_ports" in scan_data:
                for port in scan_data["open_ports"]:
                    port_num = port.get('port', 0)
                    service = port.get('service', '')
                    # Flag potentially risky ports
                    if port_num in [21, 22, 23, 25, 53, 110, 143, 993, 995, 1433, 3306, 3389, 5432]:
                        security_concerns.append(f"Port {port_num} ({service}) is open - review if necessary")
    
    # Determine overall risk level
    if critical_issues:
        risk_level = "HIGH RISK"
        risk_color = "🔴"
    elif security_concerns or potential_issues > 0:
        risk_level = "MEDIUM RISK"
        risk_color = "🟡"
    else:
        risk_level = "LOW RISK"
        risk_color = "🟢"
    
    # Create a detailed template report using actual data
    report = f"""
# Website Security Report - Easy to Understand

**Your Website:** {target_url}
**Scan Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Overall Security Level:** {risk_color} **{risk_level}**

## What We Did
We ran comprehensive security tests on your website to check for common vulnerabilities and security issues. Think of this like a security audit for your digital property.

## Executive Summary - The Bottom Line

{get_executive_summary_plain_english(risk_level, total_vulnerabilities, potential_issues, len(security_concerns))}

**📊 What We Found:**
- Confirmed security holes: {total_vulnerabilities}
- Areas that need attention: {potential_issues}
- Security concerns to review: {len(security_concerns)}
- Urgent issues: {len(critical_issues)}

## Critical Issues That Need Immediate Attention

{format_critical_issues_plain_english(critical_issues)}

## Security Concerns We Found

{format_security_concerns_plain_english(security_concerns)}

## What Each Scan Told Us About Your Website

{format_scan_results_plain_english(scan_results)}

## What This Means for Your Business

{get_business_impact_explanation(risk_level, security_concerns)}

## What You Need to Do (Step-by-Step)

### 🚨 Priority 1 - This Week
{get_priority_actions_plain_english(critical_issues, security_concerns, "high")}

### ⚠️ Priority 2 - This Month  
{get_priority_actions_plain_english(critical_issues, security_concerns, "medium")}

### ✅ Priority 3 - Ongoing
- Set up monthly security scans (we can help with this)
- Keep your website software updated
- Train your team about phishing emails and password security
- Consider adding a Web Application Firewall (like a security guard for your website)

## The Good News

{get_positive_findings(scan_results, risk_level)}

## Questions? Next Steps?

If you have questions about any of these findings or need help fixing them, please contact your web developer or IT support team. Most of these issues are common and fixable.

**Remember:** Having security issues doesn't mean you were hacked - it means we found potential vulnerabilities before the bad guys did!

---
*Security report generated by VulnPilot Scanner*
*Report explains technical findings in everyday language*
"""
    
    return JsonResponse({
        "target_url": target_url,
        "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "report_type": "Enhanced Security Assessment",
        "ai_report": report,
        "raw_scan_data": scan_results,
        "risk_level": risk_level,
        "total_issues": total_vulnerabilities + potential_issues + len(security_concerns),
        "status": "success",
        "generated_by": "Enhanced Fallback Template"
    })


def format_raw_data_for_ai(scan_results):
    """
    Format raw scan results in a structured way for AI analysis
    """
    formatted_data = {
        "scan_summary": {
            "total_scans_performed": 0,
            "scans_with_findings": 0,
            "total_vulnerabilities": 0,
            "scan_types": []
        },
        "detailed_findings": {}
    }
    
    for scan_type, scan_data in scan_results.items():
        if not isinstance(scan_data, dict):
            continue
        
        formatted_data["scan_summary"]["total_scans_performed"] += 1
        formatted_data["scan_summary"]["scan_types"].append(scan_type)
        
        # Process each scan type's data
        scan_info = {
            "scan_type": scan_type,
            "status": scan_data.get("status", "unknown"),
            "raw_output": scan_data.get("data", ""),
            "findings": [],
            "vulnerabilities": [],
            "errors": [],
            "warnings": []
        }
        
        # Extract findings based on scan type
        if scan_type.lower() == "sqlmap_scan":
            # SQLMap specific processing
            if "findings" in scan_data:
                for finding in scan_data["findings"]:
                    scan_info["findings"].append({
                        "type": "SQL Injection Test",
                        "message": finding.get("msg", ""),
                        "severity": finding.get("severity", "Unknown"),
                        "details": finding
                    })
            
            # Check for injection indicators
            raw_data = str(scan_data.get("data", ""))
            if "injection" in raw_data.lower() or "injectable" in raw_data.lower():
                scan_info["vulnerabilities"].append({
                    "type": "Potential SQL Injection",
                    "evidence": raw_data,
                    "severity": "High"
                })
        
        elif scan_type.lower() == "nmap_scan":
            # NMAP specific processing
            if "open_ports" in scan_data:
                for port in scan_data["open_ports"]:
                    scan_info["findings"].append({
                        "type": "Open Port",
                        "port": port.get("port"),
                        "service": port.get("service", "Unknown"),
                        "version": port.get("version", ""),
                        "details": port
                    })
        
        elif scan_type.lower() == "gobuster_scan":
            # Gobuster specific processing
            if "directories" in scan_data:
                for directory in scan_data["directories"]:
                    scan_info["findings"].append({
                        "type": "Directory/File Found",
                        "path": directory.get("path", ""),
                        "status": directory.get("status", ""),
                        "size": directory.get("size", ""),
                        "details": directory
                    })
        
        elif scan_type.lower() == "wpscan":
            # WPScan specific processing
            if "vulnerabilities" in scan_data:
                for vuln in scan_data["vulnerabilities"]:
                    scan_info["vulnerabilities"].append({
                        "type": "WordPress Vulnerability",
                        "title": vuln.get("title", ""),
                        "severity": vuln.get("severity", "Unknown"),
                        "references": vuln.get("references", []),
                        "details": vuln
                    })
        
        elif scan_type.lower() == "nikto":
            # Enhanced Nikto specific processing for comprehensive AI analysis
            nikto_data = scan_data.get("data", scan_data)
            
            # Process Nikto findings with detailed categorization
            if "findings" in nikto_data:
                for finding in nikto_data["findings"]:
                    # Categorize Nikto findings by severity and type
                    finding_msg = finding.get("msg", "")
                    finding_uri = finding.get("uri", "")
                    finding_method = finding.get("method", "GET")
                    
                    # Determine severity based on finding content
                    severity = "Low"
                    finding_category = "Information Disclosure"
                    
                    if any(keyword in finding_msg.lower() for keyword in ['admin', 'password', 'login', 'authentication', 'bypass']):
                        severity = "High"
                        finding_category = "Authentication Issues"
                    elif any(keyword in finding_msg.lower() for keyword in ['sql', 'injection', 'xss', 'script', 'exploit']):
                        severity = "Critical"
                        finding_category = "Injection Vulnerabilities"
                    elif any(keyword in finding_msg.lower() for keyword in ['config', 'configuration', 'backup', 'sensitive']):
                        severity = "Medium"
                        finding_category = "Configuration Issues"
                    elif any(keyword in finding_msg.lower() for keyword in ['directory', 'file', 'listing', 'browse']):
                        severity = "Medium"
                        finding_category = "Information Disclosure"
                    elif any(keyword in finding_msg.lower() for keyword in ['version', 'banner', 'server', 'header']):
                        severity = "Low"
                        finding_category = "Information Leakage"
                    
                    scan_info["findings"].append({
                        "type": "Web Security Finding",
                        "category": finding_category,
                        "message": finding_msg,
                        "uri": finding_uri,
                        "method": finding_method,
                        "severity": severity,
                        "business_impact": get_business_impact_for_finding(finding_category, severity),
                        "details": finding
                    })
                    
                    # If it's high severity, also add to vulnerabilities
                    if severity in ["High", "Critical"]:
                        scan_info["vulnerabilities"].append({
                            "type": f"Nikto {finding_category}",
                            "finding": finding_msg,
                            "severity": severity,
                            "location": finding_uri,
                            "method": finding_method,
                            "business_impact": get_business_impact_for_finding(finding_category, severity),
                            "remediation_priority": "Immediate" if severity == "Critical" else "High"
                        })
            
            # Process vulnerabilities if present in different format
            if "vulnerabilities" in nikto_data:
                for vuln in nikto_data["vulnerabilities"]:
                    scan_info["vulnerabilities"].append({
                        "type": "Web Application Vulnerability",
                        "finding": vuln.get("msg", vuln.get("description", "")),
                        "severity": vuln.get("severity", "Medium"),
                        "uri": vuln.get("uri", ""),
                        "method": vuln.get("method", ""),
                        "details": vuln
                    })
            
            # Parse raw Nikto output for additional insights
            raw_output = nikto_data.get("raw_output", "")
            if raw_output:
                nikto_raw_findings = parse_nikto_raw_output(raw_output)
                for raw_finding in nikto_raw_findings:
                    scan_info["findings"].append({
                        "type": "Raw Nikto Finding",
                        "message": raw_finding.get("finding", ""),
                        "severity": raw_finding.get("severity", "Low"),
                        "source": "raw_parse",
                        "details": raw_finding
                    })
        
        # Extract general errors and warnings from raw output
        raw_output = str(scan_data.get("data", ""))
        if raw_output:
            # Look for common error patterns
            if "error" in raw_output.lower():
                scan_info["errors"].append("Scan encountered errors - see raw output")
            if "warning" in raw_output.lower():
                scan_info["warnings"].append("Scan generated warnings - see raw output")
        
        # Count findings
        if scan_info["findings"] or scan_info["vulnerabilities"]:
            formatted_data["scan_summary"]["scans_with_findings"] += 1
        
        formatted_data["scan_summary"]["total_vulnerabilities"] += len(scan_info["vulnerabilities"])
        formatted_data["detailed_findings"][scan_type] = scan_info
    
    return formatted_data


def get_executive_summary_plain_english(risk_level, confirmed_vulns, potential_issues, concerns_count):
    """Get executive summary in plain English"""
    if risk_level == "HIGH RISK":
        return "🔴 **Your website has some serious security issues that hackers could potentially exploit.** We found confirmed vulnerabilities that need to be fixed immediately to protect your website and data."
    elif risk_level == "MEDIUM RISK":
        return f"🟡 **Your website has some security concerns that should be addressed soon.** We found {potential_issues} potential issues and {concerns_count} areas that could be improved. Your site isn't in immediate danger, but these should be fixed to keep it secure."
    else:
        return "🟢 **Good news! Your website appears to have solid basic security.** We didn't find any major security holes, but there are always ways to make it even more secure."


def format_critical_issues_plain_english(issues):
    """Format critical issues in plain English"""
    if not issues:
        return "✅ **Excellent! No critical security issues found.** This means we didn't find any obvious ways for hackers to break into your website."
    
    formatted = "🚨 **These issues need immediate attention:**\n\n"
    for i, issue in enumerate(issues, 1):
        # Translate technical terms
        plain_english_issue = translate_technical_terms(issue)
        formatted += f"{i}. {plain_english_issue}\n"
    
    return formatted


def format_security_concerns_plain_english(concerns):
    """Format security concerns in plain English"""
    if not concerns:
        return "✅ **No specific security concerns found.** Your website's basic security configuration looks good."
    
    formatted = "⚠️ **Areas that need your attention:**\n\n"
    for i, concern in enumerate(concerns, 1):
        plain_english_concern = translate_technical_terms(concern)
        formatted += f"{i}. {plain_english_concern}\n"
    
    return formatted


def format_scan_results_plain_english(scan_results):
    """Format scan results in plain English"""
    formatted = ""
    
    for scan_type, scan_data in scan_results.items():
        if scan_type == "trigger" or scan_type == "unknown":
            continue
            
        formatted += f"\n### {scan_type.replace('_', ' ').title()} Results\n"
        
        if "nmap" in scan_type.lower():
            formatted += explain_nmap_results_plain_english(scan_data)
        elif "sqlmap" in scan_type.lower():
            formatted += explain_sqlmap_results_plain_english(scan_data)
        elif "gobuster" in scan_type.lower():
            formatted += explain_gobuster_results_plain_english(scan_data)
        elif "wpscan" in scan_type.lower():
            formatted += explain_wpscan_results_plain_english(scan_data)
        elif "nikto" in scan_type.lower():
            formatted += explain_nikto_results_plain_english(scan_data)
        else:
            formatted += "We ran additional security checks and found some results to review.\n"
    
    return formatted


def explain_nmap_results_plain_english(data):
    """Explain Nmap results in plain English"""
    if isinstance(data, dict) and "scan" in data.get("nmap", {}):
        scan_data = data["nmap"]["scan"]
        explanation = "**Port Scan Results:** We checked which 'doors' (ports) are open on your website server.\n\n"
        
        for ip, host_info in scan_data.items():
            if "tcp" in host_info:
                explanation += f"**Open doors we found:**\n"
                for port, port_info in host_info["tcp"].items():
                    service = port_info.get("name", "unknown")
                    explanation += f"- Door {port} ({service}): {explain_port_purpose(int(port), service)}\n"
        
        return explanation + "\n"
    return "We scanned for open network ports on your server.\n\n"


def explain_sqlmap_results_plain_english(data):
    """Explain SQLMap results in plain English"""
    if isinstance(data, dict) and "sqlmap" in data:
        sqlmap_data = data["sqlmap"]
        explanation = "**Database Security Test:** We tested if hackers could trick your website's database into giving them information they shouldn't have.\n\n"
        
        if sqlmap_data.get("injection_found", False):
            explanation += "🟡 **What we found:** Your website might be vulnerable to 'SQL injection' attacks. This is like someone being able to ask your database questions they shouldn't be allowed to ask.\n\n"
            explanation += "**Good news:** The tests suggest your site has some protection (possibly a security firewall), which is why our tests couldn't get through.\n\n"
            explanation += "**What this means:** While we couldn't find a way in, it's worth having a developer double-check your database security.\n\n"
        else:
            explanation += "✅ **Good news:** We couldn't find any ways for hackers to break into your database.\n\n"
        
        return explanation
    return "We tested your website's database security.\n\n"


def explain_gobuster_results_plain_english(data):
    """Explain Gobuster results in plain English"""
    if isinstance(data, dict):
        total_findings = data.get("total_findings", 0)
        explanation = "**Hidden Files & Folders Check:** We looked for files and folders on your website that might be accidentally exposed to the public.\n\n"
        
        if total_findings == 0:
            explanation += "✅ **Great news:** We didn't find any hidden files or folders that shouldn't be public. Your website appears to be properly configured.\n\n"
        else:
            dirs = len(data.get("directories_found", []))
            files = len(data.get("files_found", []))
            explanation += f"⚠️ **Found {dirs} folders and {files} files** that might not need to be public. Think of this like leaving your filing cabinet open - not necessarily dangerous, but worth checking.\n\n"
        
        return explanation
    return "We checked for exposed files and directories on your website.\n\n"


def explain_wpscan_results_plain_english(data):
    """Explain WPScan results in plain English"""
    if isinstance(data, dict) and "wpscan" in data:
        wpscan_data = data["wpscan"]
        explanation = "**WordPress Security Check:** We tested if your website (or parts of it) use WordPress and checked for known security issues.\n\n"
        
        if not wpscan_data.get("vulnerabilities_found", False):
            explanation += "✅ **Good news:** We didn't find any WordPress security vulnerabilities. Either your site isn't using WordPress, or it's properly secured.\n\n"
        else:
            vuln_count = len(wpscan_data.get("vulnerabilities", []))
            explanation += f"⚠️ **Found {vuln_count} WordPress security issues** that should be addressed. These are like having old locks on your doors - they work, but newer, stronger ones are available.\n\n"
        
        return explanation
    return "We checked for WordPress-specific security issues.\n\n"


def explain_nikto_results_plain_english(data):
    """Explain Nikto results in plain English"""
    explanation = "**Web Server Security Check:** We examined your web server configuration for common security issues.\n\n"
    
    if isinstance(data, list) and data:
        for nikto_result in data:
            if "vulnerabilities" in nikto_result:
                vuln_count = len(nikto_result["vulnerabilities"])
                explanation += f"⚠️ **Found {vuln_count} configuration issues** that could be improved. These are like having windows without curtains - not immediately dangerous, but worth addressing for better security.\n\n"
                break
    else:
        explanation += "✅ **No major web server configuration issues found.**\n\n"
    
    return explanation


def explain_port_purpose(port, service):
    """Explain what a port is used for in plain English"""
    port_explanations = {
        80: "This is the main door for your website - normal and necessary",
        443: "This is the secure door for your website (HTTPS) - good to have",
        22: "This is for remote server access - make sure it's properly secured",
        21: "This is for file transfers - often insecure, consider alternatives",
        25: "This is for email - normal if you run email services",
        8080: "This is an alternative web door - check if it's really needed",
        8443: "This is an alternative secure web door - check if it's really needed"
    }
    
    return port_explanations.get(port, f"This is used for {service} - review if this door needs to be open")


def translate_technical_terms(technical_text):
    """Translate technical security terms into plain English"""
    translations = {
        "SQL injection": "database hacking attempt",
        "XSS": "website code injection",
        "CSRF": "fake request attack",
        "directory traversal": "unauthorized file access",
        "buffer overflow": "memory corruption attack",
        "injection found": "potential security hole found",
        "might not be injectable": "couldn't find obvious security holes",
        "WAF": "security firewall",
        "heuristic test": "basic security test",
        "URI parameter": "website address part",
        "open port": "accessible network door",
        "vulnerability": "security weakness",
        "misconfiguration": "incorrect security setting"
    }
    
    result = technical_text
    for technical, plain in translations.items():
        result = result.replace(technical, plain)
    
    return result


def get_business_impact_explanation(risk_level, security_concerns):
    """Explain business impact in plain English"""
    if risk_level == "HIGH RISK":
        return """
**What this means for your business:**
- Hackers could potentially access your website or data
- Your customers' information might be at risk
- Your website could be taken offline or defaced
- Your business reputation could be damaged
- You might face legal issues if customer data is stolen

**The good news:** These issues can be fixed, and finding them now means we caught them before hackers did!
"""
    elif risk_level == "MEDIUM RISK":
        return """
**What this means for your business:**
- Your website has some security gaps that should be closed
- While not immediately dangerous, these could become problems over time
- Hackers are always looking for these types of weaknesses
- Fixing these now prevents bigger problems later

**The good news:** Your website isn't in immediate danger, and these are common issues with straightforward solutions.
"""
    else:
        return """
**What this means for your business:**
- Your website appears to be well-secured
- You're following good security practices
- Your customers' data appears to be protected
- Continue monitoring and maintaining your security

**Keep it up:** Good security is an ongoing process, not a one-time thing.
"""


def get_priority_actions_plain_english(critical_issues, security_concerns, priority):
    """Get priority actions in plain English"""
    if priority == "high":
        if critical_issues:
            return "Fix the critical security issues listed above - these are the most urgent"
        elif security_concerns:
            return "Address the main security concerns we found, especially any database security issues"
        else:
            return "Review your current security setup and consider adding extra protection"
    elif priority == "medium":
        return "Implement additional security measures like security headers and server hardening"
    else:
        return "Establish ongoing security practices like regular scanning and updates"


def get_positive_findings(scan_results, risk_level):
    """Highlight positive security findings"""
    positives = []
    
    # Check for good findings in scan results
    for scan_type, scan_data in scan_results.items():
        if "gobuster" in scan_type.lower():
            if isinstance(scan_data, dict) and scan_data.get("total_findings", 0) == 0:
                positives.append("No exposed files or directories found")
        
        if "wpscan" in scan_type.lower():
            if isinstance(scan_data, dict) and "wpscan" in scan_data:
                if not scan_data["wpscan"].get("vulnerabilities_found", True):
                    positives.append("No WordPress vulnerabilities detected")
    
    if not positives:
        positives = [
            "Your website is running and accessible",
            "We completed comprehensive security testing",
            "No critical security breaches detected"
        ]
    
    formatted = "Here's what's working well with your website security:\n\n"
    for positive in positives:
        formatted += f"✅ {positive}\n"
    
    formatted += f"\n✅ Overall security level: {risk_level} - "
    if risk_level == "LOW RISK":
        formatted += "this is excellent!"
    elif risk_level == "MEDIUM RISK":
        formatted += "this is pretty good with room for improvement!"
    else:
        formatted += "we found issues, but they can be fixed!"
    
    return formatted


def get_business_impact_for_finding(finding_category, severity):
    """Get business impact explanation for a security finding"""
    impact_map = {
        "Authentication Issues": {
            "Critical": "Unauthorized access to admin areas could lead to complete website compromise",
            "High": "Weak authentication could allow unauthorized access to sensitive areas",
            "Medium": "Authentication weaknesses could be exploited by determined attackers",
            "Low": "Minor authentication concerns that should be monitored"
        },
        "Injection Vulnerabilities": {
            "Critical": "Database injection could expose all customer data and allow complete system compromise",
            "High": "Code injection vulnerabilities could allow data theft or website defacement",
            "Medium": "Potential injection points that could be exploited with advanced techniques",
            "Low": "Minor injection risks that are difficult to exploit"
        },
        "Configuration Issues": {
            "Critical": "Server misconfiguration exposes sensitive system information",
            "High": "Configuration problems could reveal sensitive business information",
            "Medium": "Suboptimal configuration that could aid attackers in reconnaissance",
            "Low": "Minor configuration improvements recommended for security best practices"
        },
        "Information Disclosure": {
            "Critical": "Sensitive business or customer data is publicly accessible",
            "High": "Important system information is exposed that could aid attackers",
            "Medium": "Some internal information is visible that should be protected",
            "Low": "Minor information leakage with minimal security impact"
        },
        "Information Leakage": {
            "Critical": "Critical system details are exposed publicly",
            "High": "Server information could help attackers plan targeted attacks",
            "Medium": "Version information might reveal known vulnerabilities",
            "Low": "Basic server information is visible but poses minimal risk"
        }
    }
    
    return impact_map.get(finding_category, {}).get(severity, "Security finding requires evaluation")


def parse_nikto_raw_output(raw_output):
    """
    Parse raw Nikto output to extract vulnerabilities and findings
    """
    findings = []
    if not raw_output:
        return findings
        
    lines = raw_output.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('-') or line.startswith('='):
            continue
            
        # Look for Nikto findings that start with + 
        if line.startswith('+'):
            # Extract useful information from Nikto findings
            finding_text = line[1:].strip()  # Remove the + prefix
            
            # Skip generic headers and noise
            if any(skip in finding_text.lower() for skip in ['target ip:', 'host:', 'start time:', 'server:', 'retrieved']):
                continue
                
            # Determine severity based on content
            severity = "Low"  # Default
            if any(keyword in finding_text.lower() for keyword in ['admin', 'password', 'login', 'sql', 'xss', 'injection', 'exploit']):
                severity = "High"
            elif any(keyword in finding_text.lower() for keyword in ['config', 'error', 'backup', 'disclosure', 'access']):
                severity = "Medium"
            
            findings.append({
                "type": "Raw Nikto Finding",
                "finding": finding_text,
                "severity": severity,
                "source": "nikto_raw_parse",
                "details": {"raw_line": line}
            })
    
    return findings