import json
import nmap
import logging
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