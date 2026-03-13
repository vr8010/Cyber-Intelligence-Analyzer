"""
Directory Enumeration - Find common directories and files
"""
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Common directories and files to check
COMMON_PATHS = [
    # Admin panels
    'admin', 'administrator', 'admin.php', 'admin.html',
    'wp-admin', 'cpanel', 'phpmyadmin', 'adminer',
    
    # Configuration files
    '.env', '.git', '.gitignore', 'config.php', 'config.json',
    'web.config', '.htaccess', 'composer.json', 'package.json',
    
    # Backup files
    'backup', 'backups', 'backup.zip', 'backup.sql',
    'db.sql', 'database.sql', 'dump.sql',
    
    # Common directories
    'api', 'assets', 'css', 'js', 'images', 'img',
    'uploads', 'files', 'download', 'downloads',
    'docs', 'documentation', 'help',
    
    # Development files
    'test', 'tests', 'testing', 'dev', 'development',
    'staging', 'demo', 'phpinfo.php', 'info.php',
    
    # Security files
    'robots.txt', 'sitemap.xml', 'security.txt',
    '.well-known/security.txt',
    
    # Common files
    'readme.txt', 'README.md', 'changelog.txt',
    'license.txt', 'LICENSE',
    
    # Login pages
    'login', 'login.php', 'signin', 'auth',
    
    # API endpoints
    'api/v1', 'api/v2', 'graphql', 'rest',
]

def check_path(domain, path, timeout=2):
    """Check if a path exists on domain"""
    try:
        url = f'https://{domain}/{path}'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.head(url, headers=headers, timeout=timeout, 
                                verify=False, allow_redirects=False)
        
        # Consider 200, 301, 302, 403 as "found"
        if response.status_code in [200, 301, 302, 403]:
            return {
                'path': path,
                'url': url,
                'status': response.status_code,
                'found': True
            }
        
        return None
        
    except:
        return None

def enumerate_directories(domain, custom_paths=None, max_workers=20):
    """
    Enumerate common directories and files
    """
    result = {
        'domain': domain,
        'found_paths': [],
        'total_found': 0,
        'total_checked': 0
    }
    
    paths_to_check = custom_paths if custom_paths else COMMON_PATHS
    result['total_checked'] = len(paths_to_check)
    
    try:
        found = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_path, domain, path): path 
                      for path in paths_to_check}
            
            for future in as_completed(futures):
                try:
                    path_result = future.result()
                    if path_result:
                        found.append(path_result)
                except:
                    pass
        
        # Sort by status code
        result['found_paths'] = sorted(found, key=lambda x: x['status'])
        result['total_found'] = len(found)
        
        # Categorize findings
        result['categories'] = {
            'accessible': [p for p in found if p['status'] == 200],
            'redirects': [p for p in found if p['status'] in [301, 302]],
            'forbidden': [p for p in found if p['status'] == 403]
        }
        
    except Exception as e:
        result['error'] = f'Enumeration error: {str(e)}'
    
    return result
