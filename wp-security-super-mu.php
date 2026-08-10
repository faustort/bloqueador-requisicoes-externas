<?php
/**
 * Plugin Name: NW2 Security Suite (MU) — Bloqueador + Scanner + Hardening
 * Plugin URI:  https://www.nw2web.com.br
 * Description: Bloqueador de requisições externas + scanner de permissões + hardening .htaccess + monitoramento arquivos. Tudo em um único MU-plugin.
 * Author:      NW2
 * Version:     3.0.0
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
        return apply_filters('nw2_blocker_whitelist', [
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
            nw2_ensure_log_protected();
            $log = '[' . gmdate('Y-m-d H:i:s') . "] nw2_default_deny_DRY_RUN (teria bloqueado) | Host: {$host} | URL: {$url}\n";
            error_log($log, 3, WP_CONTENT_DIR . '/nw2-blocked-requests.log');
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
        $last_scan = get_transient('nw2_last_permission_scan');
        if (!$last_scan) {
            nw2_scan_wordpress_permissions();
            set_transient('nw2_last_permission_scan', time(), 24 * HOUR_IN_SECONDS);
        }
    });
}

if (!function_exists('nw2_scan_wordpress_permissions')) {
    function nw2_scan_wordpress_permissions(): array {
        $issues = [];
        $recommended = [
            ABSPATH . 'wp-config.php' => 0400,
            ABSPATH . '.htaccess' => 0444,
            ABSPATH . 'wp-content/uploads' => 0755,
            ABSPATH . 'wp-content/plugins' => 0755,
            ABSPATH . 'wp-content/themes' => 0755,
            ABSPATH . 'index.php' => 0644,
            ABSPATH . 'wp-login.php' => 0644,
        ];

        foreach ($recommended as $path => $expected) {
            if (!file_exists($path)) continue;
            $current = fileperms($path) & 0777;
            if ($current !== $expected) {
                $issues[] = [
                    'file' => $path,
                    'current' => decoct($current),
                    'expected' => decoct($expected),
                    'severity' => ($current > $expected) ? 'high' : 'low'
                ];
            }
        }

        // Verificação extra: arquivos PHP em uploads
        $uploads_dir = WP_CONTENT_DIR . '/uploads';
        if (is_dir($uploads_dir)) {
            $php_files = glob($uploads_dir . '/**/*.php');
            foreach ($php_files as $php_file) {
                $issues[] = [
                    'file' => $php_file,
                    'issue' => 'Arquivo PHP em pasta de uploads',
                    'severity' => 'critical'
                ];
            }
        }

        // Mostra aviso se encontrar problemas
        if (!empty($issues) && is_admin() && current_user_can('manage_options')) {
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

        return $issues;
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
        $original_content = file_exists($htaccess_path) ? file_get_contents($htaccess_path) : '';

        // Regras de segurança específicas
        $security_rules = "\n# ======= NW2 SECURITY HARDENING =======\n";

        // 1. Protege wp-config.php
        $security_rules .= "<Files \"wp-config.php\">\n";
        $security_rules .= "Order allow,deny\nDeny from all\n";
        $security_rules .= "</Files>\n\n";

        // 2. Bloqueia acesso a arquivos sensíveis
        $security_rules .= "<FilesMatch \"\\.(log|ini|conf|bak|old|swp)$\">\n";
        $security_rules .= "Order allow,deny\nDeny from all\n";
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
        $security_rules .= "RewriteCond %{HTTP_REFERER} !^$\n";
        $security_rules .= "RewriteCond %{HTTP_REFERER} !^https?://(www\\.)?".preg_quote(parse_url(home_url(), PHP_URL_HOST))." [NC]\n";
        $security_rules .= "RewriteRule \\.(jpg|jpeg|png|gif)$ - [F,NC]\n\n";

        // 5. Bloqueia user agents maliciosos
        $security_rules .= "RewriteCond %{HTTP_USER_AGENT} (libwww-perl|wget|python|nikto|wkto|scan|java|curl) [NC]\n";
        $security_rules .= "RewriteRule .* - [F,L]\n";

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

        // Notifica admin sobre mudanças
        if (!empty($changes) && is_admin() && current_user_can('manage_options')) {
            add_action('admin_notices', function() use ($changes) {
                echo '<div class="notice notice-warning"><p><strong>NW2 Monitor:</strong> ';
                echo count($changes) . ' arquivo(s) crítico(s) foram alterados. ';
                echo '<a href="#" onclick="jQuery(\'#nw2-changes-details\').toggle(); return false;">Ver alterações</a></p>';
                echo '<div id="nw2-changes-details" style="display:none; background:#f5f5f5; padding:10px; margin-top:10px;">';
                foreach ($changes as $change) {
                    $filename = basename($change['file']);
                    $time = date('d/m/Y H:i:s', $change['timestamp']);
                    echo "<p><strong>{$filename}</strong> alterado em {$time}</p>";
                }
                echo '</div></div>';
            });
        }

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

if (function_exists('curl_exec') && is_admin()) {
    add_action('admin_notices', function () {
        if (!current_user_can('manage_options')) return;
        if (get_transient('nw2_curl_notice_shown')) return;
        set_transient('nw2_curl_notice_shown', 1, DAY_IN_SECONDS);
        echo '<div class="notice notice-warning"><p><strong>NW2 Seguranca:</strong> ';
        echo 'A funcao PHP <code>curl_exec</code> esta habilitada. Plugins podem ';
        echo 'bypassar este bloqueador usando curl nativo ou sockets crus. Para ';
        echo 'maxima protecao, adicione ao <code>php.ini</code>:<br>';
        echo '<code>disable_functions = curl_exec, curl_multi_exec, file_get_contents, fsockopen, stream_socket_client</code>';
        echo '</p></div>';
    });
}

/* =============================================================================
 * DEBUG MODE (OPCIONAL) — Loga requisicoes bloqueadas
 * ========================================================================== */
if (defined('NW2_DEBUG_LOG') && NW2_DEBUG_LOG) {
    add_action('http_api_debug', function ($response, $context, $class, $args, $url) {
        if (is_wp_error($response)) {
            $code = $response->get_error_code();
            if (strpos($code, 'nw2_') === 0) {
                nw2_ensure_log_protected();
                $log  = '[' . gmdate('Y-m-d H:i:s') . '] ';
                $log .= $code . ' | ' . $response->get_error_message() . ' | ';
                $log .= 'URL: ' . $url . ' | ';
                $log .= 'Context: ' . $context . ' | ';
                $log .= 'Cron: ' . (nw2_is_cron() ? 'sim' : 'nao') . ' | ';
                $log .= 'AJAX: ' . ((defined('DOING_AJAX') && DOING_AJAX) ? 'sim' : 'nao') . "\n";
                error_log($log, 3, WP_CONTENT_DIR . '/nw2-blocked-requests.log');
            }
        }
    }, 10, 5);
}

/* =============================================================================
 * PÁGINA DE CONFIGURAÇÃO NO ADMIN
 * ========================================================================== */
add_action('admin_menu', function() {
    add_options_page(
        'NW2 Security Suite',
        'NW2 Security',
        'manage_options',
        'nw2-security-settings',
        function() {
            ?>
            <div class="wrap">
                <h1>NW2 Security Suite</h1>
                <div class="card">
                    <h2>Status do Sistema</h2>
                    <p><strong>Bloqueador de Requisições:</strong> <?php echo NW2_DEFAULT_DENY ? '✅ Ativo' : '❌ Inativo'; ?></p>
                    <p><strong>Scanner de Permissões:</strong> <?php echo NW2_SCAN_PERMISSIONS ? '✅ Ativo' : '❌ Inativo'; ?></p>
                    <p><strong>Hardening .htaccess:</strong> <?php echo NW2_AUTO_HARDEN_HTACCESS ? '✅ Ativo' : '❌ Inativo'; ?></p>
                    <p><strong>Monitor de Arquivos:</strong> <?php echo NW2_MONITOR_FILE_CHANGES ? '✅ Ativo' : '❌ Inativo'; ?></p>
                    <p><strong>Sanitização de Uploads:</strong> <?php echo NW2_SANITIZE_UPLOADS ? '✅ Ativo' : '❌ Inativo'; ?></p>
                </div>
                <div class="card">
                    <h2>Ações</h2>
                    <form method="post">
                        <?php wp_nonce_field('nw2_security_actions', 'nw2_nonce'); ?>
                        <p>
                            <button type="submit" name="nw2_scan_permissions" class="button button-primary">
                                Executar Scanner de Permissões
                            </button>
                            <button type="submit" name="nw2_harden_htaccess" class="button button-secondary">
                                Aplicar Hardening .htaccess
                            </button>
                        </p>
                    </form>
                </div>
            </div>
            <style>
                .card { background: #fff; border: 1px solid #ccd0d4; padding: 20px; margin: 20px 0; }
            </style>
            <?php
        }
    );
});

add_action('admin_init', function() {
    if (!current_user_can('manage_options')) return;

    if (isset($_POST['nw2_scan_permissions']) && wp_verify_nonce($_POST['nw2_nonce'], 'nw2_security_actions')) {
        $issues = nw2_scan_wordpress_permissions();
        add_action('admin_notices', function() use ($issues) {
            $count = count($issues);
            echo '<div class="notice notice-success"><p>';
            echo "<strong>Scanner executado:</strong> Encontrados {$count} problema(s).";
            echo '</p></div>';
        });
    }

    if (isset($_POST['nw2_harden_htaccess']) && wp_verify_nonce($_POST['nw2_nonce'], 'nw2_security_actions')) {
        $result = nw2_harden_htaccess();
        add_action('admin_notices', function() use ($result) {
            echo '<div class="notice notice-' . ($result ? 'success' : 'error') . '"><p>';
            echo "<strong>Hardening .htaccess:</strong> " . ($result ? 'Aplicado com sucesso!' : 'Falha ao aplicar.');
            echo '</p></div>';
        });
    }
});

/* =============================================================================
 * FIM DO PLUGIN
 * ========================================================================== */