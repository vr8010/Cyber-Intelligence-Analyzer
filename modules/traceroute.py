"""
Traceroute Module - Network path tracing
"""
import socket
import subprocess
import platform
import re

def traceroute(domain, max_hops=15):
    """
    Perform traceroute to domain (limited hops for speed)
    """
    result = {
        'domain': domain,
        'hops': [],
        'total_hops': 0
    }
    
    try:
        # Resolve domain
        ip = socket.gethostbyname(domain)
        result['ip'] = ip
        
        # Determine OS and use appropriate command
        system = platform.system().lower()
        
        if system == 'windows':
            # Windows: -h max_hops, -w timeout_ms
            cmd = ['tracert', '-h', str(max_hops), '-w', '500', domain]
        else:
            # Linux/Mac: -m max_hops, -w timeout_sec
            cmd = ['traceroute', '-m', str(max_hops), '-w', '1', domain]
        
        # Execute traceroute with shorter timeout
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, error = process.communicate(timeout=15)
        
        if error and process.returncode != 0:
            result['error'] = 'Traceroute failed'
            return result
        
        # Parse output
        lines = output.split('\n')
        hop_num = 0
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Parse hop information (basic parsing)
            if system == 'windows':
                # Windows format: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
                match = re.search(r'^\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+|\*)', line)
                if match:
                    hop_num = int(match.group(1))
                    hop_ip = match.group(2) if match.group(2) != '*' else 'timeout'
                    result['hops'].append({
                        'hop': hop_num,
                        'ip': hop_ip
                    })
            else:
                # Unix format: " 1  192.168.1.1 (192.168.1.1)  1.234 ms"
                match = re.search(r'^\s*(\d+)\s+.*?\((\d+\.\d+\.\d+\.\d+)\)', line)
                if match:
                    hop_num = int(match.group(1))
                    hop_ip = match.group(2)
                    result['hops'].append({
                        'hop': hop_num,
                        'ip': hop_ip
                    })
        
        result['total_hops'] = len(result['hops'])
        
        # If no hops found, add a note
        if result['total_hops'] == 0:
            result['error'] = 'No traceroute data available (may be blocked by firewall)'
        
    except subprocess.TimeoutExpired:
        result['error'] = 'Traceroute timeout (network may block ICMP)'
        # Try to get partial results
        try:
            process.kill()
        except:
            pass
    except socket.gaierror:
        result['error'] = 'Unable to resolve domain'
    except FileNotFoundError:
        result['error'] = 'Traceroute command not found on system'
    except Exception as e:
        result['error'] = f'Traceroute unavailable: {str(e)}'
    
    return result
