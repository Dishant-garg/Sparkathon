import json
import nmap
import logging
from datetime import datetime
from urllib.parse import urlparse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db import connection
from django.conf import settings

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("nmap_scan.log"),
        logging.StreamHandler()
    ],
)

# Initialize scanner lazily to avoid import-time errors
scanner = None

def get_scanner():
    """Get or initialize the nmap scanner"""
    global scanner
    if scanner is None:
        try:
            scanner = nmap.PortScanner()
        except nmap.PortScannerError as e:
            logging.error(f"Failed to initialize nmap scanner: {e}")
            scanner = False  # Mark as failed
    return scanner if scanner is not False else None

@require_http_methods(["GET"])
def health_check(request):
    """Health check endpoint for monitoring system status"""
    try:
        # Check database connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        
        # Check if essential tools are available
        tools_status = {
            'nmap': bool(scanner),
            'database': True,
            'django': True
        }
        
        health_data = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0',
            'tools': tools_status,
            'database': 'connected'
        }
        
        return JsonResponse(health_data, status=200)
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return JsonResponse({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }, status=500)

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
        
        # Get scanner instance
        scanner = get_scanner()
        if not scanner:
            logger.error("Nmap scanner not available")
            return JsonResponse({"error": "Nmap scanner not available. Please install nmap."}, status=500)
        
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
        scanner = get_scanner()
        if not scanner:
            logger.error("Nmap scanner not available")
            return JsonResponse({"error": "Nmap scanner not available. Please install nmap."}, status=500)
            
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
            # Construct SQLMap command with enhanced options
            cmd = [
                'python3', '/opt/sqlmap/sqlmap.py',
                '--url', target_url,
                '--batch',  # Non-interactive mode
                '--random-agent',  # Use random User-Agent
                '--text-only',  # Output only text
                '--output-dir', '/tmp',  # Output directory
                '--timeout', '30',  # 30 second timeout
                '--threads', '1',  # Single thread
                '--level', '3',  # Medium level for better detection
                '--risk', '2',   # Medium risk for more tests
                '--technique', 'BEUSTQ',  # All SQL injection techniques
                '--tamper', 'space2comment',  # Basic evasion
                '--forms',  # Test forms automatically
                '--crawl', '2',  # Crawl 2 levels deep
                '--smart',  # Smart payload selection
                '--flush-session',  # Start fresh session
                '--fresh-queries'  # Don't use cached queries
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
            # Construct WPScan command with enhanced options
            cmd = [
                'wpscan',
                '--url', target_url,
                '--random-user-agent',
                '--disable-tls-checks',  # Skip SSL certificate checks
                '--format', 'json',      # JSON output for easier parsing
                '--no-banner',           # Disable banner
                '--max-threads', '2',    # Dual thread for better performance
                '--request-timeout', '30', # 30 second timeout per request
                '--connect-timeout', '10',  # 10 second connection timeout
                '--enumerate', 'vp,vt,tt,cb,dbe,u,m',  # Enumerate vulnerabilities, themes, timthumbs, config backups, db exports, users, media
                '--plugins-detection', 'aggressive',  # Aggressive plugin detection
                '--plugins-version-detection', 'aggressive',  # Aggressive version detection
                '--api-token', 'YOUR_WPSCAN_API_TOKEN',  # Add your WPScan API token for better results
                '--ignore-main-redirect',  # Ignore main redirect
                '--disable-wordpress-check'  # Don't check if it's WordPress first
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

        # Prepare scan data for AI analysis
        scan_summary = prepare_scan_summary(scan_results)
        formatted_raw_data = format_raw_data_for_ai(scan_results)
        
        # Create AI prompt for report generation
        prompt = f"""
        You are a cybersecurity expert who specializes in explaining technical security findings to non-technical business people. 
        Your goal is to create a security report that anyone can understand, using simple language and real-world analogies.
        
        Generate a user-friendly security report for this website scan:

        TARGET WEBSITE: {target_url}
        SCAN DATE: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

        SCAN SUMMARY:
        {json.dumps(scan_summary, indent=2)}

        DETAILED SCAN RESULTS:
        {json.dumps(formatted_raw_data, indent=2)}

        IMPORTANT: Write this report as if you're explaining to a business owner who has no technical background. Use analogies, simple language, and focus on business impact.

        Structure your report with these sections:

        ## 🏠 Your Website's Security Health Check

        **What We Did:** Explain in simple terms what security scanning means (like a home security inspection)

        **Overall Security Grade:** Give an A-F grade with simple explanation

        ## 🚨 What We Found (The Good, Bad, and Urgent)

        For each finding, explain:
        - **What this means in simple terms** (use analogies like "leaving your front door unlocked")
        - **Why this matters for your business** (could hackers steal customer data? crash your website?)
        - **How urgent this is** (fix today vs. fix this month)

        ## 🛠 What You Need To Do

        **Critical Actions (Do These First):**
        - List 1-3 most important things in plain English
        - Explain what happens if they don't fix these

        **Important Improvements (Do These Soon):**
        - List other important fixes
        - Explain the business benefits

        **Good-to-Have Upgrades (Do These When You Can):**
        - List nice-to-have security improvements

        ## 💡 Think of Your Website Security Like...

        Use a house security analogy to explain their overall security posture.

        ## 📞 Next Steps

        Give them a simple action plan with priorities.

        REMEMBER: 
        - No technical jargon unless you explain it immediately
        - Use analogies (house security, car safety, bank vault, etc.)
        - Focus on business impact (money, reputation, customers)
        - Make recommendations actionable and prioritized
        - Be encouraging but honest about risks
        """

        try:
            # Call Gemini API using Google's generative AI
            cmd = [
                'curl', '-X', 'POST',
                f'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key={gemini_api_key}',
                '-H', 'Content-Type: application/json',
                '-d', json.dumps({
                    "contents": [{
                        "parts": [{
                            "text": prompt
                        }]
                    }],
                    "generationConfig": {
                        "temperature": 0.3,
                        "topK": 40,
                        "topP": 0.8,
                        "maxOutputTokens": 4096
                    }
                })
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
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
                        "scan_summary": scan_summary,
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
    Generate a user-friendly report when AI is not available
    """
    summary = prepare_scan_summary(scan_results)
    
    # Analyze the severity of findings
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    
    for issue in summary.get('security_issues', []):
        severity = issue.get('severity', '').lower()
        if 'critical' in severity or 'high' in severity:
            critical_count += 1
        elif 'medium' in severity:
            medium_count += 1
        else:
            low_count += 1
    
    # Determine overall security grade
    total_issues = summary['vulnerabilities_found']
    if critical_count > 0:
        grade = "F"
        grade_explanation = "❌ **URGENT ATTENTION NEEDED** - Critical security issues found that need immediate fixing!"
    elif high_count > 0:
        grade = "D"
        grade_explanation = "⚠️ **NEEDS IMPROVEMENT** - Several important security issues that should be addressed soon."
    elif medium_count > 0:
        grade = "C"
        grade_explanation = "⚡ **DECENT BUT COULD BE BETTER** - Some security improvements would make your website safer."
    elif total_issues > 0:
        grade = "B"
        grade_explanation = "✅ **GOOD SECURITY** - Only minor issues found, you're doing well!"
    else:
        grade = "A"
        grade_explanation = "🎉 **EXCELLENT SECURITY** - Your website looks very secure!"
    
    # Create a user-friendly report
    report = f"""# 🛡️ Your Website Security Report

**Website Checked:** {target_url}  
**Security Scan Date:** {datetime.now().strftime("%B %d, %Y at %I:%M %p")}  
**Report Type:** Complete Security Health Check

---

## 🏠 Your Website's Security Health Check

**What We Did:** We ran a comprehensive security scan on your website - think of it like a thorough home security inspection. We checked for unlocked doors, broken windows, faulty alarms, and anything that might let unwanted visitors (hackers) into your digital property.

**Your Security Grade: {grade}**  
{grade_explanation}

---

## 🔍 What We Found

We scanned your website with {summary['total_scans']} different security tools and found **{total_issues} security issues** that need your attention.

{format_findings_user_friendly(summary.get('security_issues', []), summary.get('open_ports', []))}

---

## 🛠️ What You Need To Do

{generate_action_plan(critical_count, high_count, medium_count, low_count, summary)}

---

## 💡 Think of Your Website Security Like Your House

{generate_house_analogy(grade, total_issues, critical_count)}

---

## 📞 Your Next Steps

1. **Right Now:** {get_immediate_action(critical_count, high_count)}
2. **This Week:** Review all the findings above and prioritize fixes
3. **This Month:** Implement the recommended security improvements
4. **Ongoing:** Run security scans regularly (monthly is good practice)

---

**Remember:** Website security is like home security - it's better to prevent problems than to deal with them after something bad happens. Most of these issues can be fixed relatively easily by your web developer or hosting provider.

---
*Report generated by VulnPilot Security Scanner - Making security simple to understand*
"""
    
    return JsonResponse({
        "target_url": target_url,
        "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "report_type": "User-Friendly Security Assessment",
        "ai_report": report,
        "scan_summary": summary,
        "status": "success",
        "generated_by": "VulnPilot Fallback Generator",
        "security_grade": grade,
        "total_issues": total_issues,
        "critical_issues": critical_count
    })


def format_findings_user_friendly(security_issues, open_ports):
    """Format security findings in user-friendly language"""
    if not security_issues and not open_ports:
        return "🎉 **Great news!** We didn't find any major security issues. Your website appears to be well-protected!"
    
    findings = []
    
    # Format security issues with user-friendly explanations
    for issue in security_issues:
        source = issue.get('source', '').upper()
        description = issue.get('issue', 'Unknown issue')
        severity = issue.get('severity', '').lower()
        
        # Translate technical findings to user-friendly language
        user_friendly = translate_finding_to_plain_english(source, description, severity)
        findings.append(user_friendly)
    
    # Format open ports in simple terms
    if open_ports:
        port_explanation = translate_open_ports_to_plain_english(open_ports)
        findings.append(port_explanation)
    
    return '\n\n'.join(findings)


def translate_finding_to_plain_english(source, description, severity):
    """Translate technical security findings to plain English"""
    
    # Determine urgency emoji and level
    if 'critical' in severity or 'high' in severity:
        urgency = "🚨 **URGENT**"
        timeline = "Fix immediately"
    elif 'medium' in severity:
        urgency = "⚠️ **Important**"
        timeline = "Fix this week"
    else:
        urgency = "📝 **Good to Fix**"
        timeline = "Fix when convenient"
    
    # Translate based on scan type and content
    if source == "SQLMAP_SCAN" or "sql injection" in description.lower():
        return f"{urgency} **Database Vulnerability Found**\n" \
               f"**What this means:** Your website's database (where customer info is stored) might be accessible to hackers - like having a broken lock on your filing cabinet.\n" \
               f"**Business risk:** Hackers could steal customer data, which could cost you customers, money, and damage your reputation.\n" \
               f"**Action needed:** {timeline} - Contact your web developer to secure your database immediately."
    
    elif source == "WPSCAN" or "wordpress" in description.lower():
        return f"{urgency} **WordPress Security Issue**\n" \
               f"**What this means:** Your WordPress website has a security weakness - like having a window that doesn't lock properly.\n" \
               f"**Business risk:** Hackers could break into your website, change content, or use it to attack others.\n" \
               f"**Action needed:** {timeline} - Update WordPress, plugins, or themes. Your web developer can help."
    
    elif source == "GOBUSTER" or "directory" in description.lower():
        return f"{urgency} **Hidden Files Exposed**\n" \
               f"**What this means:** Some files on your website are visible to anyone - like leaving private documents on your front porch.\n" \
               f"**Business risk:** Sensitive information might be exposed, or hackers could find ways to break in.\n" \
               f"**Action needed:** {timeline} - Hide or remove these exposed files."
    
    elif source == "NIKTO_SCAN":
        return f"{urgency} **Web Server Security Issue**\n" \
               f"**What this means:** Your web server (the computer hosting your website) has a security problem - like having a faulty alarm system.\n" \
               f"**Business risk:** Your website could be hacked, go offline, or be used to attack other websites.\n" \
               f"**Action needed:** {timeline} - Update your web server software or contact your hosting provider."
    
    elif source == "NMAP_SCAN" or "port" in description.lower():
        return f"{urgency} **Network Security Concern**\n" \
               f"**What this means:** Your website has some network connections that might not be secure - like having extra doors that might not be locked.\n" \
               f"**Business risk:** Hackers might find alternative ways to access your systems.\n" \
               f"**Action needed:** {timeline} - Review with your IT team or hosting provider."
    
    else:
        # Generic translation for unknown issues
        return f"{urgency} **Security Issue Detected**\n" \
               f"**What this means:** We found a potential security problem that needs attention.\n" \
               f"**Issue details:** {description}\n" \
               f"**Action needed:** {timeline} - Have your web developer or IT team review this."


def translate_open_ports_to_plain_english(open_ports):
    """Explain open ports in simple terms"""
    if not open_ports:
        return ""
    
    port_count = len(open_ports)
    
    explanation = f"📡 **Network Connections Found**\n" \
                 f"**What this means:** Your website has {port_count} network connection(s) open - think of these like different doors or windows to your digital building.\n"
    
    # Analyze common ports
    web_ports = [p for p in open_ports if p.get('port') in [80, 443, 8080, 8443]]
    ssh_ports = [p for p in open_ports if p.get('port') in [22, 2222]]
    database_ports = [p for p in open_ports if p.get('port') in [3306, 5432, 1433, 27017]]
    
    if web_ports:
        explanation += f"**Good news:** Most of these are normal web connections (ports {', '.join([str(p.get('port')) for p in web_ports])}) - these are like your front door, necessary for visitors.\n"
    
    if ssh_ports:
        explanation += f"**Admin access found:** Remote administration access is available (SSH) - this is like a staff entrance. Make sure it's properly secured.\n"
    
    if database_ports:
        explanation += f"⚠️ **Database access detected:** Your database might be directly accessible from the internet - this is like having your filing cabinet accessible from the street. This should usually be secured.\n"
    
    explanation += f"**Action needed:** Have your IT team review these connections to ensure only necessary ones are open and properly secured."
    
    return explanation


def generate_action_plan(critical_count, high_count, medium_count, low_count, summary):
    """Generate a prioritized action plan in plain English"""
    
    if critical_count > 0:
        plan = f"### 🚨 Critical Actions (Do These RIGHT NOW)\n\n"
        plan += f"You have **{critical_count} critical security issue(s)** that need immediate attention. These are like having your front door wide open - fix these today!\n\n"
        plan += f"**What to do:**\n"
        plan += f"1. Contact your web developer or IT team immediately\n"
        plan += f"2. Show them this report and ask them to fix the critical issues first\n"
        plan += f"3. Consider taking your website offline temporarily if customer data is at risk\n\n"
    else:
        plan = f"### ✅ No Critical Issues Found\n\nGood news! No emergency-level security problems were detected.\n\n"
    
    if high_count > 0:
        plan += f"### ⚠️ Important Actions (Do These This Week)\n\n"
        plan += f"You have **{high_count} important security issue(s)** that should be addressed soon. These are like having weak locks - not emergency level, but important to fix.\n\n"
    
    if medium_count > 0:
        plan += f"### 📝 Improvements (Do These This Month)\n\n"
        plan += f"You have **{medium_count} medium-priority security improvement(s)**. These are like upgrading your home security system - good to do but not urgent.\n\n"
    
    if low_count > 0:
        plan += f"### 💡 Nice-to-Have Upgrades (Do These When You Can)\n\n"
        plan += f"You have **{low_count} minor security suggestion(s)**. These are like adding extra security features - helpful but not essential.\n\n"
    
    # Add general recommendations
    plan += f"### 🔄 Ongoing Security (Make This a Habit)\n\n"
    plan += f"1. **Monthly scans:** Run security scans like this one every month\n"
    plan += f"2. **Keep things updated:** Regularly update your website, plugins, and software\n"
    plan += f"3. **Backup regularly:** Keep recent backups of your website (like insurance for your digital property)\n"
    plan += f"4. **Monitor access:** Watch for unusual activity on your website\n"
    
    return plan


def generate_house_analogy(grade, total_issues, critical_count):
    """Generate a house security analogy based on the findings"""
    
    if grade == "A":
        return "Your website security is like a **modern, well-secured house** with excellent locks, a good alarm system, security cameras, and proper lighting. You've done a great job protecting your digital property!"
    
    elif grade == "B":
        return "Your website security is like a **well-maintained house with good basic security**. You have decent locks and most security features in place, but there are a few small things (like better outdoor lighting) that could make it even more secure."
    
    elif grade == "C":
        return "Your website security is like a **typical house that needs some security upgrades**. You have basic protection, but there are several areas (like better locks or adding security cameras) that would significantly improve your safety."
    
    elif grade == "D":
        return "Your website security is like a **house with some security gaps**. While you have some basic protection, there are important security measures missing - like having good locks but no alarm system, or security cameras but poor lighting."
    
    else:  # Grade F
        return f"Your website security is like a **house with serious security problems**. With {critical_count} critical issue(s), it's similar to having broken locks, alarms that don't work, or even doors left wide open. These need immediate attention to protect your digital property and visitors!"


def get_immediate_action(critical_count, high_count):
    """Get the most immediate action needed"""
    
    if critical_count > 0:
        return f"Contact your web developer/IT team immediately about the {critical_count} critical security issue(s)"
    elif high_count > 0:
        return f"Schedule time with your web developer this week to address {high_count} important security issue(s)"
    else:
        return "Review the security improvements listed above and plan to implement them over the next month"


def format_open_ports(ports):
    """Format open ports for report"""
    if not ports:
        return "No open ports detected or scan not performed."
    
    formatted = []
    for port in ports:
        formatted.append(f"- Port {port.get('port', 'Unknown')}/{port.get('protocol', 'tcp')}: {port.get('service', 'Unknown service')}")
    
    return '\n'.join(formatted)


def format_security_issues(issues):
    """Format security issues for report"""
    if not issues:
        return "No security issues detected."
    
    formatted = []
    for issue in issues:
        formatted.append(f"- **{issue['source'].upper()}**: {issue['issue']}")
    
    return '\n'.join(formatted)


def format_missing_headers(headers):
    """Format missing headers for report"""
    if not headers:
        return "Security headers analysis not available."
    
    formatted = []
    for header in headers:
        formatted.append(f"- {header}")
    
    return '\n'.join(formatted)


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
        
        elif scan_type.lower() == "nikto_scan":
            # Nikto specific processing
            if "findings" in scan_data:
                for finding in scan_data["findings"]:
                    scan_info["findings"].append({
                        "type": "Web Server Issue",
                        "message": finding.get("msg", ""),
                        "uri": finding.get("uri", ""),
                        "method": finding.get("method", ""),
                        "details": finding
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