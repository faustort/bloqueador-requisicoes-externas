<?php
/**
 * Plugin Name: NW2 Security Suite (MU) — Bloqueador + Scanner + Hardening
 * Plugin URI:  https://www.nw2web.com.br
 * Description: Bloqueador de requisições externas + scanner de permissões + hardening .htaccess + monitoramento arquivos. Tudo em um único MU-plugin.
 * Author:      NW2
 * Version:     3.0.1
 *
 * Instale como MU-plugin: wp-content/mu-plugins/wp-security-super-mu.php
 *
 * ATENÇÃO: NUNCA defina WP_HTTP_BLOCK_EXTERNAL=true — este plugin usa sistema próprio via pre_http_request
 */

if (!defined('ABSPATH')) exit;

/* =============================================================================
 * CONFIGURAÇÕES GLOBAIS
 * ========================================================================== */
if (!defined('NW2_DEFAULT_DENY')) define('NW2_DEFAULT_DENY', true);
if (!defined('NW2_DEFAULT_DENY_DRY_RUN')) define('NW2_DEFAULT_DENY_DRY_RUN', false);
if (!defined('NW2_SCAN_PERMISSIONS')) define('NW2_SCAN_PERMISSIONS', true);
if (!defined('NW2_FIX_PERMISSIONS')) define('NW2_FIX_PERMISSIONS', false);
if (!defined('NW2_PERMISSION_BACKUP')) define('NW2_PERMISSION_BACKUP', true);
if (!defined('NW2_PERMISSION_NOTIFY')) define('NW2_PERMISSION_NOTIFY', false);
if (!defined('NW2_SCAN_PROGRESS')) define('NW2_SCAN_PROGRESS', 0);
if (!defined('NW2_AUTO_HARDEN_HTACCESS')) define('NW2_AUTO_HARDEN_HTACCESS', true);
if (!defined('NW2_MONITOR_FILE_CHANGES')) define('NW2_MONITOR_FILE_CHANGES', true);
if (!defined('NW2_SANITIZE_UPLOADS')) define('NW2_SANITIZE_UPLOADS', true);

/* =============================================================================
 * HELPERS COMPARTILHADOS
 * ========================================================================== */
if (!function_exists('nw2_is_smtp_host')) {
    function nw2_is_smtp_host(?string $host): bool {
        if (!$host) return false;
        $h = strtolower($host);
        return (
            strpos($h, 'smtp') !== false ||
            strpos($h, 'mail.') === 0 ||
            strpos($h, '.mail.') !== false ||
            strpos($h, 'mx.') === 0 ||
            strpos($h, 'email-smtp.') !== false ||
            strpos($h, 'email-ssl.') !== false
        );
    }
}

if (!function_exists('nw2_get_post_smtp_host')) {
    function nw2_get_post_smtp_host(): string {
        $host = '';
        $ps = get_option('post_smtp');
        if (is_array($ps)) {
            if (!empty($ps['hostname'])) $host = $ps['hostname'];
            if (!$host && !empty($ps['outgoing_hostname'])) $host = $ps['outgoing_hostname'];
        }
        if (!$host) {
            $pm = get_option('postman_options');
            if (is_array($pm) && !empty($pm['hostname'])) $host = $pm['hostname'];
        }
        $host = preg_replace('~^\s*(ssl://|tls://|tcp://)~i', '', (string)$host);
        return strtolower(trim((string)$host));
    }
}

if (!function_exists('nw2_host_matches')) {
    function nw2_host_matches(string $url, string $domain): bool {
        $host = strtolower((string)(parse_url($url, PHP_URL_HOST) ?: ''));
        $domain = strtolower(ltrim($domain, '.'));
        if ($host === '') return false;
        return $host === $domain || str_ends_with($host, '.' . $domain);
    }
}

if (!function_exists('nw2_google_or_cf_hosts')) {
    function nw2_google_or_cf_hosts(): array {
        static $hosts;
        if ($hosts !== null) return $hosts;
        $hosts = apply_filters('nw2_blocker_whitelist', [
            // Google
            'withgoogle.com', 'googleapis.com', 'accounts.google.com',
            'googleusercontent.com', 'googletagmanager.com', 'google-analytics.com',
            'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
            'gstatic.com', 'appspot.com', 'google.com',
            // Cloudflare
            'cloudflare.com',
            // WordPress.org
            'wordpress.org', 'api.wordpress.org',
            // WAF / segurança
            'sucuri.net', 'wordfence.com', 'ithemes.com', 'solidwp.com',
            'malcare.io', 'blogvault.net',
            // WooCommerce / Automattic
            'woocommerce.com', 'jetpack.com', 'wordpress.com', 'wp.com',
            // Gateways globais
            'stripe.com', 'paypal.com',
            // CEP / endereço Brasil
            'viacep.com.br', 'brasilapi.com.br', 'correios.com.br',
        ]);
        return $hosts;
    }
}

if (!function_exists('nw2_is_google_or_cf')) {
    function nw2_is_google_or_cf(string $url): bool {
        foreach (nw2_google_or_cf_hosts() as $domain) {
            if (nw2_host_matches($url, $domain)) return true;
        }
        return false;
    }
}

if (!function_exists('nw2_is_local_request')) {
    function nw2_is_local_request(string $url): bool {
        $host = parse_url($url, PHP_URL_HOST);
        if (!$host) return (bool) preg_match('~^/(?!/)~', $url);
        $home = parse_url(home_url(), PHP_URL_HOST);
        if (!$home) return false;
        $host = ltrim($host, 'www.');
        $home = ltrim($home, 'www.');
        return ($host === $home);
    }
}

if (!function_exists('nw2_is_cron')) {
    function nw2_is_cron(): bool {
        return defined('DOING_CRON') && DOING_CRON;
    }
}

if (!function_exists('nw2_is_woocommerce_critical_context')) {
    function nw2_is_woocommerce_critical_context(): bool {
        if (!class_exists('WooCommerce')) return false;
        if (isset($_REQUEST['wc-ajax'])) return true;
        if (isset($_GET['wc-api'])) return true;
        if (defined('REST_REQUEST') && REST_REQUEST) {
            $uri = $_SERVER['REQUEST_URI'] ?? '';
            if (strpos($uri, '/wc/') !== false || strpos($uri, '/wc-') !== false) return true;
        }
        if (nw2_is_cron()) return true;
        if (function_exists('is_checkout') && did_action('wp') &&
            (is_checkout() || is_wc_endpoint_url('order-pay') || is_wc_endpoint_url('order-received'))) {
            return true;
        }
        if (is_admin() && isset($_GET['page']) && $_GET['page'] === 'wc-settings') return true;
        return false;
    }
}

/* =============================================================================
 * PARTE 1: BLOQUEADOR DE REQUISIÇÕES EXTERNAS (Original)
 * ========================================================================== */
add_action('admin_init', function () {
    if (strpos(__DIR__, 'mu-plugins') === false && current_user_can('manage_options')) {
        add_action('admin_notices', function () {
            echo '<div class="notice notice-warning"><p><strong>NW2:</strong> mova para <code>wp-content/mu-plugins/</code>.</p></div>';
        });
    }
});

// 1) BYPASS TOTAL — GOOGLE + CLOUDFLARE + LOCAL
add_filter('pre_http_request', function ($pre, $args, $url) {
    if (nw2_is_google_or_cf($url)) return false;
    if (nw2_is_local_request($url)) return false;
    return $pre;
}, -1000, 3);

// 2) SMTP + GOOGLE HOSTS DECLARADOS COMO EXTERNOS (para compatibilidade)
add_filter('http_request_host_is_external', function ($external, $host) {
    $host = strtolower((string)$host);
    if (nw2_is_smtp_host($host)) return true;
    $cfg = nw2_get_post_smtp_host();
    if ($cfg && $host === $cfg) return true;
    foreach (nw2_google_or_cf_hosts() as $gh) {
        if ($host === $gh || str_ends_with($host, '.' . $gh)) return true;
    }
    return $external;
}, 10, 2);

// 3) ELEMENTOR — STUB TOTAL (NUNCA CONECTA)
add_filter('elementor/admin/show_home_screen', '__return_false', 0);
add_filter('pre_http_request', function ($pre, $args, $url) {
    if (false !== $pre) return $pre;
    $host = parse_url($url, PHP_URL_HOST) ?: '';
    if (!preg_match('~(^|\.)elementor\.(com|cloud|io)$~i', $host)) return false;
    return [
        'headers'  => ['content-type' => 'application/json; charset=UTF-8'],
        'body'     => wp_json_encode([
            'success' => true,
            'status'  => 'ok',
            'data'    => ['license' => 'active', 'expires' => '2099-12-31', 'items' => []],
        ]),
        'response' => ['code' => 200, 'message' => 'OK'],
        'cookies'  => [],
        'filename' => null,
    ];
}, -500, 3);

// 4) WP-CRON — FAIL-FAST DE DOMINIOS NULLED
add_filter('pre_http_request', function ($pre, $args, $url) {
    if (false !== $pre) return $pre;
    if (!nw2_is_cron()) return false;
    $host = parse_url($url, PHP_URL_HOST) ?: '';
    if (!$host) return false;
    $bloqueios_cron = ['wpnull', 'nulled', 'gpl', 'crack', 'null.', 'festinger'];
    foreach ($bloqueios_cron as $kw) {
        if (stripos($url, $kw) !== false) {
            return new WP_Error('nw2_cron_blocked', 'Requisição bloqueada (cron).');
        }
    }
    return false;
}, -200, 3);

// 5) FAIL-FAST — APENAS AJAX PURO
add_filter('pre_http_request', function ($pre, $args, $url) {
    if (false !== $pre) return $pre;
    if (!defined('DOING_AJAX') || !DOING_AJAX) return false;
    if (defined('REST_REQUEST') && REST_REQUEST) return false;
    if (nw2_is_google_or_cf($url)) return false;
    if (nw2_is_cron()) return false;
    if (nw2_is_woocommerce_critical_context()) return false;
    $host = parse_url($url, PHP_URL_HOST) ?: '';
    if (!$host) return false;
    if (nw2_is_smtp_host($host) || $host === nw2_get_post_smtp_host()) return false;
    return new WP_Error('nw2_fast_fail', 'Requisição externa bloqueada por política.');
}, 10, 3);

// 6) BLACKLIST — EXPANDIDA (AGRESSIVA)
add_filter('pre_http_request', function ($pre, $args, $url) {
    if (false !== $pre) return $pre;
    if (nw2_is_google_or_cf($url) || nw2_is_local_request($url) || nw2_is_smtp_host(parse_url($url, PHP_URL_HOST) ?: '')) {
        return false;
    }
    $bloqueios_dominio = apply_filters('nw2_blocker_blacklist', [
        'wpnull24.com','wplocker.com','gpldl.com','gpl.coffee','nulled.to',
        'api.envato.com','support.wpbakery.com','sliderrevolution.com',
        'update.themeforest.net','update.avada.com','update.divi.com',
        'hotjar.com','mouseflow.com','fullstory.com',
    ]);
    foreach ($bloqueios_dominio as $dominio) {
        if (nw2_host_matches($url, $dominio)) {
            return new WP_Error('nw2_blacklist', 'Conexão externa bloqueada por política de segurança.');
        }
    }
    $bloqueios_keyword = apply_filters('nw2_blocker_blacklist_keywords', [
        'revslider', 'slider-revolution', 'salient', 'betheme',
        'purchasekey.com', 'license-check.', 'usage.tracking.',
    ]);
    foreach ($bloqueios_keyword as $kw) {
        if (stripos($url, $kw) !== false) {
            return new WP_Error('nw2_blacklist', 'Conexão externa bloqueada por política de segurança.');
        }
    }
    return false;
}, 20, 3);

// 7) WOOCOMMERCE — SILENCIO (tracking/marketplace)
add_action('init', function () {
    add_filter('woocommerce_admin_disabled', '__return_true');
    add_filter('woocommerce_allow_marketplace_suggestions', '__return_false');
    add_filter('woocommerce_show_marketplace_suggestions', '__return_false');
    add_filter('woocommerce_tracker_send_event', '__return_false');
    add_filter('woocommerce_tracker_enabled', '__return_false');
    add_filter('woocommerce_helper_suppress_admin_notices', '__return_true');
    add_filter('woocommerce_show_admin_notice', '__return_false');
    add_filter('woocommerce_helper_updater_enabled', '__return_false');
}, 10);

// 8) DEFAULT DENY — LIGADO POR PADRAO
if (NW2_DEFAULT_DENY) {
    add_filter('pre_http_request', function ($pre, $args, $url) {
        if (false !== $pre) return $pre;
        $host = parse_url($url, PHP_URL_HOST) ?: '';
        if (!$host) return false;
        if (nw2_is_local_request($url)) return false;
        if (nw2_is_google_or_cf($url)) return false;
        if (nw2_is_smtp_host($host) || $host === nw2_get_post_smtp_host()) return false;
        if (nw2_is_woocommerce_critical_context()) return false;
        if (NW2_DEFAULT_DENY_DRY_RUN) {
            $log = '[' . gmdate('Y-m-d H:i:s') . "] nw2_default_deny_DRY_RUN (teria bloqueado) | Host: {$host} | URL: {$url}\n";
            nw2_log_blocked($log);
            return false;
        }
        return new WP_Error('nw2_default_deny', "Requisição externa bloqueada: $host");
    }, 100, 3);
}

/* =============================================================================
 * PARTE 2: SCANNER DE PERMISSÕES WORDPRESS
 * ========================================================================== */
if (NW2_SCAN_PERMISSIONS && is_admin()) {
    add_action('admin_init', function () {
        if (!current_user_can('manage_options')) return;

        // Verificação única por dia
        $last_scan = get_transient('nw2_last_permission_scan_result');
        if (!$last_scan) {
            $scan_result = nw2_scan_wordpress_permissions();
            set_transient('nw2_last_permission_scan_result', $scan_result, 24 * HOUR_IN_SECONDS);
        }
    });
}

if (!function_exists('nw2_scan_wordpress_permissions')) {
    function nw2_scan_wordpress_permissions($fix = false): array {
        $issues = [];
        $fixed = 0;
        $recommended = [
            ABSPATH . 'wp-config.php' => 0400,
            ABSPATH . '.htaccess' => 0444,
            ABSPATH . 'wp-content/uploads' => 0755,
            ABSPATH . 'wp-content/plugins' => 0755,
            ABSPATH . 'wp-content/themes' => 0755,
            ABSPATH . 'index.php' => 0644,
            ABSPATH . 'wp-login.php' => 0644,
        ];

        $total_files = count($recommended);
        $processed = 0;

        // Backup permissions if enabled
        if (NW2_PERMISSION_BACKUP && $fix) {
            $backup = get_option('nw2_permissions_backup', []);
            foreach ($recommended as $path => $expected) {
                if (file_exists($path) && !isset($backup[$path])) {
                    $backup[$path] = fileperms($path) & 0777;
                }
            }
            update_option('nw2_permissions_backup', $backup);
        }

        foreach ($recommended as $path => $expected) {
            if (!file_exists($path)) {
                $processed++;
                continue;
            }
            $current = fileperms($path) & 0777;
            if ($current !== $expected) {
                $issues[] = [
                    'file' => $path,
                    'current' => decoct($current),
                    'expected' => decoct($expected),
                    'severity' => ($current > $expected) ? 'high' : 'low'
                ];
                if ($fix && NW2_FIX_PERMISSIONS) {
                    // Attempt to chmod
                    if (@chmod($path, $expected)) {
                        $fixed++;
                        // Log
                        error_log('[NW2] Fixed permissions: ' . $path . ' from ' . decoct($current) . ' to ' . decoct($expected));
                    }
                }
            }
            $processed++;

            // Update progress transient
            set_transient('nw2_scan_progress', round(($processed / $total_files) * 100), 30);
        }

        // Verificação extra: arquivos PHP em uploads
        $uploads_dir = WP_CONTENT_DIR . '/uploads';
        if (is_dir($uploads_dir)) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($uploads_dir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($iterator as $file_info) {
                if (!$file_info->isFile() || strtolower($file_info->getExtension()) !== 'php') {
                    continue;
                }
                $php_file = $file_info->getPathname();
                $issues[] = [
                    'file' => $php_file,
                    'issue' => 'Arquivo PHP em pasta de uploads',
                    'severity' => 'critical'
                ];
                if ($fix && NW2_FIX_PERMISSIONS) {
                    if (@unlink($php_file)) {
                        $fixed++;
                        error_log('[NW2] Removed PHP file from uploads: ' . $php_file);
                    }
                }
            }
        }

        // Prepare result
        $result = [
            'issues' => $issues,
            'count' => count($issues),
            'fixed' => $fixed,
            'total_files' => $total_files,
            'processed' => $processed,
        ];

        // Notify if fixes applied and notifications enabled
        if ($fix && NW2_FIX_PERMISSIONS && $fixed > 0 && NW2_PERMISSION_NOTIFY && is_admin() && current_user_can('manage_options')) {
            // Could send email, but for now just log
            error_log('[NW2] Permission fix completed: ' . $fixed . ' items fixed.');
            // Optionally set a transient for admin notice
            set_transient('nw2_permission_fixed_notice', $fixed, 12 * HOUR_IN_SECONDS);
        }

        // Mostra aviso se encontrar problemas (only when not fixing, to avoid duplicate messages)
        if (!$fix && !empty($issues) && is_admin() && current_user_can('manage_options')) {
            add_action('admin_notices', function() use ($issues) {
                $count = count($issues);
                echo '<div class="notice notice-warning"><p><strong>NW2 Scanner:</strong> ';
                echo "Encontrados {$count} problema(s) de permissões. ";
                echo '<a href="#" onclick="jQuery(\'#nw2-permission-details\').toggle(); return false;">Ver detalhes</a></p>';
                echo '<div id="nw2-permission-details" style="display:none; background:#f5f5f5; padding:10px; margin-top:10px;">';
                foreach ($issues as $issue) {
                    echo "<p><strong>{$issue['file']}</strong><br>";
                    if (isset($issue['current'])) {
                        echo "Atual: {$issue['current']} | Recomendado: {$issue['expected']}";
                    } else {
                        echo $issue['issue'];
                    }
                    echo " <span style='color:" . ($issue['severity'] === 'critical' ? 'red' : 'orange') . "'>";
                    echo "[" . strtoupper($issue['severity']) . "]</span></p>";
                }
                echo '</div></div>';
            });
        }

        return $result;
    }
}

/* =============================================================================
 * PARTE 3: HARDENING DE .HTACCESS AUTOMÁTICO
 * ========================================================================== */
if (NW2_AUTO_HARDEN_HTACCESS) {
    add_action('init', function() {
        if (!is_admin() || !current_user_can('manage_options')) return;

        // Aplica hardening uma vez
        $htaccess_hash = get_transient('nw2_htaccess_hash');
        $current_hash = md5_file(ABSPATH . '.htaccess');

        if (!$htaccess_hash || $htaccess_hash !== $current_hash) {
            nw2_harden_htaccess();
            set_transient('nw2_htaccess_hash', $current_hash, 7 * DAY_IN_SECONDS);
        }
    });
}

if (!function_exists('nw2_harden_htaccess')) {
    function nw2_harden_htaccess(): bool {
        $htaccess_path = ABSPATH . '.htaccess';
        if (!file_exists($htaccess_path)) {
            return false;
        }
        $original_content = (string) file_get_contents($htaccess_path);
        $home_host = parse_url(home_url(), PHP_URL_HOST) ?: '';

        // Regras de segurança específicas
        $security_rules = "\n# ======= NW2 SECURITY HARDENING =======\n";

        // 1. Protege wp-config.php
        $security_rules .= "<Files \"wp-config.php\">\n";
        $security_rules .= "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n";
        $security_rules .= "<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n";
        $security_rules .= "</Files>\n\n";

        // 2. Bloqueia acesso a arquivos sensíveis
        $security_rules .= "<FilesMatch \"\\.(log|ini|conf|bak|old|swp)$\">\n";
        $security_rules .= "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n";
        $security_rules .= "<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n";
        $security_rules .= "</FilesMatch>\n\n";

        // 3. Protege diretórios
        $security_rules .= "<IfModule mod_rewrite.c>\n";
        $security_rules .= "RewriteEngine On\n";
        $security_rules .= "# Bloqueia acesso a includes\n";
        $security_rules .= "RewriteRule ^wp-content/includes/ - [F,L]\n";
        $security_rules .= "# Bloqueia acesso a backups\n";
        $security_rules .= "RewriteRule ^.*\\.(sql|tar|gz|zip)$ - [F,L]\n";
        $security_rules .= "</IfModule>\n\n";

        // 4. Previne hotlinking
        if ($home_host) {
            $security_rules .= "<IfModule mod_rewrite.c>\n";
            $security_rules .= "RewriteCond %{HTTP_REFERER} !^$\n";
            $security_rules .= "RewriteCond %{HTTP_REFERER} !^https?://(www\\.)?".preg_quote($home_host)." [NC]\n";
            $security_rules .= "RewriteRule \\.(jpg|jpeg|png|gif)$ - [F,NC]\n";
            $security_rules .= "</IfModule>\n\n";
        }

        // 5. Bloqueia user agents maliciosos
        $security_rules .= "<IfModule mod_rewrite.c>\n";
        $security_rules .= "RewriteCond %{HTTP_USER_AGENT} (libwww-perl|wget|python|nikto|wkto|scan|java|curl) [NC]\n";
        $security_rules .= "RewriteRule .* - [F,L]\n";
        $security_rules .= "</IfModule>\n";

        // Remove regras anteriores NW2 se existirem
        $pattern = '/# ======= NW2 SECURITY HARDENING =======.*?# ======= END NW2 =======/s';
        $original_content = preg_replace($pattern, '', $original_content);

        // Adiciona novas regras
        $new_content = $original_content . $security_rules . "# ======= END NW2 =======\n";

        // Backup do original
        if ($original_content !== '' && !file_exists($htaccess_path . '.backup')) {
            file_put_contents($htaccess_path . '.backup', $original_content);
        }

        return file_put_contents($htaccess_path, $new_content) !== false;
    }
}

/* =============================================================================
 * PARTE 4: MONITORAMENTO DE ALTERAÇÕES DE ARQUIVOS
 * ========================================================================== */
if (NW2_MONITOR_FILE_CHANGES) {
    add_action('admin_init', function() {
        if (!current_user_can('manage_options')) return;

        // Verificação a cada 6 horas
        $last_check = get_transient('nw2_last_file_monitor');
        if (!$last_check || time() - $last_check > 6 * HOUR_IN_SECONDS) {
            nw2_monitor_core_files();
            set_transient('nw2_last_file_monitor', time(), 6 * HOUR_IN_SECONDS);
        }
    });
}

if (!function_exists('nw2_monitor_core_files')) {
    function nw2_monitor_core_files(): array {
        $changes = [];
        $critical_files = [
            ABSPATH . 'wp-config.php',
            ABSPATH . '.htaccess',
            ABSPATH . 'index.php',
            ABSPATH . 'wp-login.php',
            ABSPATH . 'xmlrpc.php'
        ];

        // Hash atual dos arquivos
        $current_hashes = [];
        foreach ($critical_files as $file) {
            if (file_exists($file)) {
                $current_hashes[$file] = md5_file($file);
            }
        }

        // Compara com hash anterior
        $previous_hashes = get_option('nw2_file_hashes', []);

        foreach ($current_hashes as $file => $hash) {
            if (isset($previous_hashes[$file]) && $previous_hashes[$file] !== $hash) {
                $changes[] = [
                    'file' => $file,
                    'previous_hash' => $previous_hashes[$file],
                    'current_hash' => $hash,
                    'timestamp' => filemtime($file)
                ];
            }
        }

        // Atualiza hashes
        update_option('nw2_file_hashes', $current_hashes);

        // Apenas retorna mudanças - avisos centralizados no dashboard

        return $changes;
    }
}

/* =============================================================================
 * PARTE 5: SANITIZAÇÃO DE UPLOADS
 * ========================================================================== */
if (NW2_SANITIZE_UPLOADS) {
    add_filter('wp_handle_upload_prefilter', function($file) {
        $filename = $file['name'];
        $tmp_name = $file['tmp_name'];

        // 1. Verifica extensões perigosas
        $dangerous_exts = ['.php', '.phtml', '.phar', '.inc', '.php3', '.php4', '.php5', '.php7'];
        foreach ($dangerous_exts as $ext) {
            if (strtolower(substr($filename, -strlen($ext))) === $ext) {
                $file['error'] = 'Extensão de arquivo não permitida.';
                return $file;
            }
        }

        // 2. Verifica conteúdo de arquivos de imagem
        if (preg_match('/\.(jpg|jpeg|png|gif)$/i', $filename)) {
            $size = @getimagesize($tmp_name);
            if ($size === false) {
                $file['error'] = 'Arquivo de imagem inválido.';
                return $file;
            }
        }

        // 3. Verifica arquivos SVG para scripts maliciosos
        if (strtolower(substr($filename, -4)) === '.svg') {
            $content = file_get_contents($tmp_name);
            if (stripos($content, '<script') !== false || stripos($content, 'javascript:') !== false) {
                $file['error'] = 'SVG contém scripts potencialmente perigosos.';
                return $file;
            }
        }

        return $file;
    });
}

/* =============================================================================
 * FUNÇÕES DE LOG E UTILITÁRIAS (COMPATIBILIDADE)
 * ========================================================================== */
if (!function_exists('nw2_ensure_log_protected')) {
    function nw2_ensure_log_protected(): void {
        $htaccess = WP_CONTENT_DIR . '/.htaccess';
        $marker = 'nw2-blocked-requests.log';
        $existing = is_file($htaccess) ? (string)file_get_contents($htaccess) : '';
        if (strpos($existing, $marker) !== false) return;
        $rule = "\n# NW2 — protege log de requisições bloqueadas\n<Files \"{$marker}\">\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n</Files>\n";
        @file_put_contents($htaccess, $existing . $rule);
    }
}

if (!function_exists('nw2_log_blocked')) {
    function nw2_log_blocked(string $message): void {
        $log_path = WP_CONTENT_DIR . '/nw2-blocked-requests.log';
        nw2_ensure_log_protected();
        if (file_exists($log_path) && filesize($log_path) > 5 * 1024 * 1024) {
            @rename($log_path, $log_path . '.old');
        }
        error_log($message, 3, $log_path);
    }
}

/* =============================================================================
 * HARDENING BÁSICO (COMPATIBILIDADE)
 * ========================================================================== */
if (!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true);
add_filter('xmlrpc_enabled', '__return_false');

/* =============================================================================
 * TIMEOUTS CONTROLADOS + AVISO ANTI-CURL NATIVO
 * ========================================================================== */
add_filter('http_request_args', function ($r) {
    $r['timeout'] = 15;
    $r['connect_timeout'] = 7;
    $r['redirection'] = 3;
    $r['sslverify'] = true;
    return $r;
});

// O alerta sobre curl_exec agora é centralizado no sistema de avisos

/* =============================================================================
 * DEBUG MODE (OPCIONAL) — Loga requisicoes bloqueadas
 * ========================================================================== */
if (defined('NW2_DEBUG_LOG') && NW2_DEBUG_LOG) {
    add_action('http_api_debug', function ($response, $context, $class, $args, $url) {
        if (is_wp_error($response)) {
            $code = $response->get_error_code();
            if (strpos($code, 'nw2_') === 0) {
                $log  = '[' . gmdate('Y-m-d H:i:s') . '] ';
                $log .= $code . ' | ' . $response->get_error_message() . ' | ';
                $log .= 'URL: ' . $url . ' | ';
                $log .= 'Context: ' . $context . ' | ';
                $log .= 'Cron: ' . (nw2_is_cron() ? 'sim' : 'nao') . ' | ';
                $log .= 'AJAX: ' . ((defined('DOING_AJAX') && DOING_AJAX) ? 'sim' : 'nao') . "\n";
                nw2_log_blocked($log);
            }
        }
    }, 10, 5);
}

/* =============================================================================
 * SISTEMA DE AVISOS UNIFICADO (NÃO DESTRUTIVO)
 * ========================================================================== */
if (!function_exists('nw2_get_all_alerts')) {
    function nw2_get_all_alerts(): array {
        $alerts = [];
        $alert_count = 0;

        // 1. Alerta sobre curl_exec
        if (function_exists('curl_exec') && !get_user_meta(get_current_user_id(), 'nw2_hide_curl_alert', true)) {
            $alerts[] = [
                'id' => 'curl_alert',
                'title' => 'Função PHP curl_exec habilitada',
                'message' => 'Plugins podem bypassar este bloqueador usando curl nativo ou sockets crus.',
                'solution' => 'Adicione ao php.ini:<br><code>disable_functions = curl_exec, curl_multi_exec, file_get_contents, fsockopen, stream_socket_client</code>',
                'severity' => 'warning',
                'dismissible' => true
            ];
            $alert_count++;
        }

        // 2. Scanner de permissões (executa apenas quando necessário)
        if (NW2_SCAN_PERMISSIONS && !get_transient('nw2_last_permission_scan_result')) {
            $scan_result = nw2_scan_wordpress_permissions();
            if (!empty($scan_result['issues'])) {
                $count = $scan_result['count'];
                $alerts[] = [
                    'id' => 'permission_scan',
                    'title' => "{$count} problema(s) de permissões encontrados",
                    'message' => 'Alguns arquivos têm permissões incorretas.',
                    'details' => array_slice($scan_result['issues'], 0, 5), // Mostra até 5
                    'severity' => 'warning',
                    'dismissible' => true
                ];
                $alert_count += $count;
            }
            set_transient('nw2_last_permission_scan_result', $scan_result, 24 * HOUR_IN_SECONDS);
        }

        // 3. Monitor de arquivos
        if (NW2_MONITOR_FILE_CHANGES) {
            $file_changes = nw2_monitor_core_files();
            if (!empty($file_changes) && !get_user_meta(get_current_user_id(), 'nw2_hide_file_changes_alert', true)) {
                $alerts[] = [
                    'id' => 'file_changes',
                    'title' => count($file_changes) . ' arquivo(s) crítico(s) alterados',
                    'message' => 'Arquivos do WordPress foram modificados.',
                    'details' => $file_changes,
                    'severity' => 'warning',
                    'dismissible' => true
                ];
                $alert_count++;
            }
        }

        return [
            'alerts' => $alerts,
            'count' => $alert_count,
            'timestamp' => time()
        ];
    }
}

/* =============================================================================
 * DASHBOARD UNIFICADO NW2
 * ========================================================================== */
add_action('admin_menu', function() {
    // Menu principal com badge
    $alerts = nw2_get_all_alerts();
    $badge = $alerts['count'] > 0 ? ' <span class="update-plugins count-' . $alerts['count'] . '"><span class="plugin-count">' . $alerts['count'] . '</span></span>' : '';

    add_menu_page(
        'NW2 Security Suite',
        'NW2 Security' . $badge,
        'manage_options',
        'nw2-security-dashboard',
        'nw2_render_dashboard',
        'dashicons-shield',
        80
    );

    // Subpáginas
    add_submenu_page(
        'nw2-security-dashboard',
        'Dashboard',
        'Dashboard',
        'manage_options',
        'nw2-security-dashboard',
        'nw2_render_dashboard'
    );

    add_submenu_page(
        'nw2-security-dashboard',
        'Configurações',
        'Configurações',
        'manage_options',
        'nw2-security-settings',
        'nw2_render_settings'
    );

    add_submenu_page(
        'nw2-security-dashboard',
        'Alertas',
        'Alertas',
        'manage_options',
        'nw2-security-alerts',
        'nw2_render_alerts'
    );
});

function nw2_render_dashboard() {
    $alerts = nw2_get_all_alerts();
    ?>
    <div class="wrap">
        <h1>NW2 Security Dashboard</h1>

        <!-- Status Cards -->
        <div class="nw2-dashboard-grid">
            <div class="nw2-card">
                <h2>Status Geral</h2>
                <p><strong>Bloqueador:</strong> <span class="nw2-status nw2-<?php echo NW2_DEFAULT_DENY ? 'active' : 'inactive'; ?>"><?php echo NW2_DEFAULT_DENY ? 'Ativo' : 'Inativo'; ?></span></p>
                <p><strong>Scanner:</strong> <span class="nw2-status nw2-<?php echo NW2_SCAN_PERMISSIONS ? 'active' : 'inactive'; ?>"><?php echo NW2_SCAN_PERMISSIONS ? 'Ativo' : 'Inativo'; ?></span></p>
                <p><strong>Hardening:</strong> <span class="nw2-status nw2-<?php echo NW2_AUTO_HARDEN_HTACCESS ? 'active' : 'inactive'; ?>"><?php echo NW2_AUTO_HARDEN_HTACCESS ? 'Ativo' : 'Inativo'; ?></span></p>
                <p><strong>Monitor:</strong> <span class="nw2-status nw2-<?php echo NW2_MONITOR_FILE_CHANGES ? 'active' : 'inactive'; ?>"><?php echo NW2_MONITOR_FILE_CHANGES ? 'Ativo' : 'Inativo'; ?></span></p>
                <p><strong>Sanitização:</strong> <span class="nw2-status nw2-<?php echo NW2_SANITIZE_UPLOADS ? 'active' : 'inactive'; ?>"><?php echo NW2_SANITIZE_UPLOADS ? 'Ativo' : 'Inativo'; ?></span></p>
            </div>

            <div class="nw2-card">
                <h2>Alertas Ativos</h2>
                <?php if ($alerts['count'] > 0): ?>
                    <div class="nw2-alerts-summary">
                        <p><strong><?php echo $alerts['count']; ?> alerta(s) encontrado(s)</strong></p>
                        <a href="?page=nw2-security-alerts" class="button button-primary">Ver Todos</a>
                    </div>
                <?php else: ?>
                    <p class="nw2-success">Nenhum alerta ativo</p>
                <?php endif; ?>
            </div>

        <!-- Quick Actions -->
        <div class="nw2-card">
            <h2>Ações Rápidas</h2>
            <form method="post">
                <?php wp_nonce_field('nw2_actions', 'nw2_nonce'); ?>
                <p>
                    <button type="submit" name="nw2_scan_now" class="button button-primary">
                        Executar Scanner Agora
                    </button>
                    <button type="submit" name="nw2_harden_now" class="button button-secondary">
                        Aplicar Hardening .htaccess
                    </button>
                    <?php if ($alerts['count'] > 0): ?>
                        <button type="submit" name="nw2_dismiss_all" class="button">
                            Dispensar Todos os Alertas
                        </button>
                    <?php endif; ?>
                </p>
            </form>
        </div>
    </div>

    <style>
        .nw2-dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .nw2-card { background: #fff; border: 1px solid #ccd0d4; padding: 20px; border-radius: 4px; }
        .nw2-status { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
        .nw2-active { background: #d4edda; color: #155724; }
        .nw2-inactive { background: #f8d7da; color: #721c24; }
        .nw2-success { color: #46b450; font-weight: bold; }
        .nw2-alerts-summary { background: #fff8e5; padding: 15px; border-radius: 4px; border-left: 4px solid #f0ad4e; }
    </style>
    <?php
}

function nw2_render_settings() {
    ?>
    <div class="wrap">
        <h1>Configurações NW2 Security</h1>

        <div class="nw2-card">
            <h2>Configurações do Sistema</h2>
            <p>Configure via <code>wp-config.php</code>:</p>
            <pre style="background: #f5f5f5; padding: 15px; border-radius: 4px;">
define('NW2_DEFAULT_DENY', true);           // Bloqueador de requisições
define('NW2_SCAN_PERMISSIONS', true);       // Scanner de permissões
define('NW2_AUTO_HARDEN_HTACCESS', true);   // Hardening .htaccess
define('NW2_MONITOR_FILE_CHANGES', true);   // Monitor de arquivos
define('NW2_SANITIZE_UPLOADS', true);       // Sanitização de uploads
define('NW2_DEBUG_LOG', false);             // Log de debug (opcional)
            </pre>

            <p><strong>ATENÇÃO:</strong> Nunca defina <code>WP_HTTP_BLOCK_EXTERNAL=true</code> — este plugin usa sistema próprio.</p>
        </div>
    </div>
    <?php
}

function nw2_render_alerts() {
    $alerts = nw2_get_all_alerts();
    ?>
    <div class="wrap">
        <h1>Alertas NW2 Security</h1>

        <?php if (empty($alerts['alerts'])): ?>
            <div class="nw2-card">
                <p class="nw2-success">Nenhum alerta ativo</p>
            </div>
        <?php else: ?>
            <form method="post">
                <?php wp_nonce_field('nw2_alerts', 'nw2_nonce'); ?>

                <?php foreach ($alerts['alerts'] as $index => $alert): ?>
                    <div class="nw2-card" style="border-left: 4px solid <?php echo $alert['severity'] === 'warning' ? '#f0ad4e' : '#d9534f'; ?>;">
                        <h3><?php echo esc_html($alert['title']); ?></h3>
                        <p><?php echo $alert['message']; ?></p>

                        <?php if (!empty($alert['details'])): ?>
                            <details style="margin-top: 10px;">
                                <summary>Detalhes</summary>
                                <ul style="margin-left: 20px; margin-top: 10px;">
                                    <?php foreach ($alert['details'] as $detail): ?>
                                        <li><?php
                                            if (is_array($detail)) {
                                                echo esc_html($detail['file'] ?? '');
                                                if (isset($detail['current'])) {
                                                    echo " (Atual: {$detail['current']} | Recomendado: {$detail['expected']})";
                                                }
                                            } else {
                                                echo esc_html($detail);
                                            }
                                        ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </details>
                        <?php endif; ?>

                        <?php if (!empty($alert['solution'])): ?>
                            <div style="margin-top: 10px; padding: 10px; background: #e7f3ff; border-radius: 4px;">
                                <strong>Solução:</strong><br><?php echo $alert['solution']; ?>
                            </div>
                        <?php endif; ?>

                        <?php if ($alert['dismissible']): ?>
                            <div style="margin-top: 15px;">
                                <button type="submit" name="nw2_dismiss_alert" value="<?php echo esc_attr($alert['id']); ?>" class="button">
                                    Não mostrar novamente
                                </button>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>

                <div style="margin-top: 20px;">
                    <button type="submit" name="nw2_dismiss_all_alerts" class="button button-primary">
                        Dispensar Todos os Alertas
                    </button>
                </div>
            </form>
        <?php endif; ?>
    </div>
    <style>
        .nw2-card { background: #fff; border: 1px solid #ccd0d4; padding: 20px; margin: 20px 0; border-radius: 4px; }
    </style>
    <?php
}

/* =============================================================================
 * HANDLERS DE AÇÕES
 * ========================================================================== */
add_action('admin_init', function() {
    if (!current_user_can('manage_options')) return;

    // Dismiss single alert
    if (isset($_POST['nw2_dismiss_alert']) && wp_verify_nonce($_POST['nw2_nonce'], 'nw2_alerts')) {
        $alert_id = sanitize_text_field($_POST['nw2_dismiss_alert']);
        update_user_meta(get_current_user_id(), "nw2_hide_{$alert_id}_alert", true);
        wp_redirect(admin_url('admin.php?page=nw2-security-alerts&dismissed=1'));
        exit;
    }

    // Dismiss all alerts
    if (isset($_POST['nw2_dismiss_all_alerts']) && wp_verify_nonce($_POST['nw2_nonce'], 'nw2_alerts')) {
        $alerts = ['curl_alert', 'permission_scan', 'file_changes'];
        foreach ($alerts as $alert_id) {
            update_user_meta(get_current_user_id(), "nw2_hide_{$alert_id}_alert", true);
        }
        wp_redirect(admin_url('admin.php?page=nw2-security-alerts&dismissed_all=1'));
        exit;
    }

    // Quick actions
    if (isset($_POST['nw2_scan_now']) && wp_verify_nonce($_POST['nw2_nonce'], 'nw2_actions')) {
        $issues = nw2_scan_wordpress_permissions();
        set_transient('nw2_scan_result', count($issues), 300);
        wp_redirect(admin_url('admin.php?page=nw2-security-dashboard&scanned=1'));
        exit;
    }

    if (isset($_POST['nw2_harden_now']) && wp_verify_nonce($_POST['nw2_nonce'], 'nw2_actions')) {
        $result = nw2_harden_htaccess();
        set_transient('nw2_harden_result', $result ? 'success' : 'error', 300);
        wp_redirect(admin_url('admin.php?page=nw2-security-dashboard&hardened=1'));
        exit;
    }

    // Dismiss all from dashboard
    if (isset($_POST['nw2_dismiss_all']) && wp_verify_nonce($_POST['nw2_nonce'], 'nw2_actions')) {
        $alerts = ['curl_alert', 'permission_scan', 'file_changes'];
        foreach ($alerts as $alert_id) {
            update_user_meta(get_current_user_id(), "nw2_hide_{$alert_id}_alert", true);
        }
        wp_redirect(admin_url('admin.php?page=nw2-security-dashboard&dismissed_all=1'));
        exit;
    }
});

/* =============================================================================
 * ADMIN NOTICE ÚNICO (LIMPO)
 * ========================================================================== */
add_action('admin_notices', function() {
    $alerts = nw2_get_all_alerts();

    // Se não há alertas ou usuário já viu todos, não mostra nada
    if ($alerts['count'] === 0 || get_user_meta(get_current_user_id(), 'nw2_hide_global_alert', true)) {
        return;
    }

    // Apenas UM aviso limpo
    ?>
    <div class="notice notice-warning is-dismissible nw2-global-alert">
        <p>
            <strong>NW2 Security:</strong> Você tem <?php echo esc_html($alerts['count']); ?> alerta(s) de segurança.
            <a href="<?php echo esc_url(admin_url('admin.php?page=nw2-security-alerts')); ?>">Ver detalhes</a>
            <button type="button" class="button-link nw2-dismiss-all" style="margin-left: 10px;">Dispensar todos</button>
        </p>
    </div>

    <script>
    jQuery(document).ready(function($) {
        // Dismiss individual notice
        $('.nw2-global-alert .notice-dismiss').on('click', function() {
            $.post(ajaxurl, {
                action: 'nw2_dismiss_notice',
                nonce: '<?php echo wp_create_nonce('nw2_dismiss'); ?>'
            });
        });

        // Dismiss all alerts
        $('.nw2-dismiss-all').on('click', function() {
            if (confirm('Dispensar todos os alertas de segurança?')) {
                $.post(ajaxurl, {
                    action: 'nw2_dismiss_all_alerts',
                    nonce: '<?php echo wp_create_nonce('nw2_dismiss_all'); ?>'
                }, function() {
                    $('.nw2-global-alert').fadeOut();
                });
            }
        });
    });
    </script>
    <?php
});

// AJAX handlers
add_action('wp_ajax_nw2_dismiss_notice', function() {
    if (!current_user_can('manage_options')) wp_die('Unauthorized');
    if (!wp_verify_nonce($_POST['nonce'] ?? '', 'nw2_dismiss')) wp_die('Invalid nonce');
    update_user_meta(get_current_user_id(), 'nw2_hide_global_alert', true);
    wp_die();
});

add_action('wp_ajax_nw2_dismiss_all_alerts', function() {
    if (!current_user_can('manage_options')) wp_die('Unauthorized');
    if (!wp_verify_nonce($_POST['nonce'] ?? '', 'nw2_dismiss_all')) wp_die('Invalid nonce');
    update_user_meta(get_current_user_id(), 'nw2_hide_all_alerts', true);
    wp_die();
});

/* =============================================================================
 * FIM DO PLUGIN
 * ========================================================================== */