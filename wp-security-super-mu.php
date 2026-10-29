<?php
/**
 * Plugin Name: NW2 Security Suite Pro (MU)
 * Plugin URI:  https://www.nw2web.com.br
 * Description: Substituto leve do Sucuri: Bloqueador de requisições externas (100% amigável ao WordPress e Google) + Stub total Elementor + Limpeza total do Dashboard WP + WAF anti-enumeração + Scanner de permissões + Hardening .htaccess + Sanitização de uploads.
 * Author:      NW2
 * Version:     3.2.0
 *
 * Instale como MU-plugin: wp-content/mu-plugins/wp-security-super-mu.php
 *
 * ATENÇÃO: NUNCA defina WP_HTTP_BLOCK_EXTERNAL=true — este plugin usa sistema próprio via pre_http_request
 */

if (!defined('ABSPATH')) { exit; }

/* =============================================================================
 * CONFIGURAÇÕES GLOBAIS
 * ========================================================================== */
if (!defined('NW2_DEFAULT_DENY')) define('NW2_DEFAULT_DENY', true);
if (!defined('NW2_DEFAULT_DENY_DRY_RUN')) define('NW2_DEFAULT_DENY_DRY_RUN', false);
if (!defined('NW2_DEBUG_BLOCKED_HOSTS')) define('NW2_DEBUG_BLOCKED_HOSTS', false);
if (!defined('NW2_DISABLE_CURL')) define('NW2_DISABLE_CURL', true);
if (!defined('NW2_SCAN_PERMISSIONS')) define('NW2_SCAN_PERMISSIONS', true);
if (!defined('NW2_MAX_LOG_AGE_DAYS')) define('NW2_MAX_LOG_AGE_DAYS', 90);
if (!defined('NW2_MAX_HTACCESS_BACKUPS')) define('NW2_MAX_HTACCESS_BACKUPS', 25);
if (!defined('NW2_FIX_PERMISSIONS')) define('NW2_FIX_PERMISSIONS', false);
if (!defined('NW2_PERMISSION_BACKUP')) define('NW2_PERMISSION_BACKUP', true);
if (!defined('NW2_PERMISSION_NOTIFY')) define('NW2_PERMISSION_NOTIFY', false);
if (!defined('NW2_AUTO_HARDEN_HTACCESS')) define('NW2_AUTO_HARDEN_HTACCESS', true);
if (!defined('NW2_MONITOR_FILE_CHANGES')) define('NW2_MONITOR_FILE_CHANGES', true);
if (!defined('NW2_SANITIZE_UPLOADS')) define('NW2_SANITIZE_UPLOADS', true);
if (!defined('NW2_CLEAN_DASHBOARD')) define('NW2_CLEAN_DASHBOARD', true);
if (!defined('NW2_PROTECT_USER_ENUM')) define('NW2_PROTECT_USER_ENUM', true);

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
            // Google Ecosystem (Site Kit, Analytics, GTM, Ads, Fonts, reCAPTCHA, Maps, YouTube oEmbed)
            'withgoogle.com', 'googleapis.com', 'accounts.google.com', 'firebase.google.com',
            'googleusercontent.com', 'googletagmanager.com', 'google-analytics.com',
            'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
            'gstatic.com', 'appspot.com', 'google.com', 'google.com.br',
            'recaptcha.net', 'youtube.com', 'youtu.be', 'ytimg.com',
            // Cloudflare
            'cloudflare.com',
            // WordPress.org Ecosystem Completo (Core, Plugins, Themes, Translations, CDN, Gravatar)
            'wordpress.org', 'api.wordpress.org', 'downloads.wordpress.org',
            'w.org', 's.w.org', 'ps.w.org', 'ts.w.org', 'gravatar.com',
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
        $host = strtolower((string)(parse_url($url, PHP_URL_HOST) ?: ''));
        if (!$host) return (bool) preg_match('~^/(?!/)~', $url);
        if ($host === 'localhost' || $host === '127.0.0.1' || $host === '::1') return true;
        $home = strtolower((string)(parse_url(home_url(), PHP_URL_HOST) ?: ''));
        if (!$home) return false;
        $host = preg_replace('/^www\./i', '', $host);
        $home = preg_replace('/^www\./i', '', $home);
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
 * PARTE 1: BLOQUEADOR DE REQUISIÇÕES EXTERNAS (WordPress + Google Safe)
 * ========================================================================== */
add_action('admin_init', function () {
    if (strpos(__DIR__, 'mu-plugins') === false && current_user_can('manage_options')) {
        add_action('admin_notices', function () {
            echo '<div class="notice notice-warning"><p><strong>NW2:</strong> mova para <code>wp-content/mu-plugins/</code>.</p></div>';
        });
    }
});

// 1) BYPASS TOTAL — GOOGLE + WORDPRESS.ORG + CLOUDFLARE + LOCAL
add_filter('pre_http_request', function ($pre, $args, $url) {
    if (nw2_is_google_or_cf($url)) return false;
    if (nw2_is_local_request($url)) return false;
    return $pre;
}, -1000, 3);

// 2) SMTP + GOOGLE + WP HOSTS DECLARADOS COMO EXTERNOS SEGUROS
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

// 3) ELEMENTOR & ELEMENTOR PRO — STUB TOTAL INTELIGENTE (NUNCA CONECTA AO SERVIDOR DO ELEMENTOR)
add_filter('elementor/admin/show_home_screen', '__return_false', 0);
add_filter('elementor/tracker/send_event', '__return_false', 0);
add_action('init', function () {
    // Desarma cron de telemetria do Elementor para nem tentar iniciar request
    if (wp_next_scheduled('elementor/tracker/send_event')) {
        wp_clear_scheduled_hook('elementor/tracker/send_event');
    }
}, 20);

add_filter('pre_http_request', function ($pre, $args, $url) {
    if (false !== $pre) return $pre;
    $host = parse_url($url, PHP_URL_HOST) ?: '';
    if (!preg_match('~(^|\.)(elementor\.(com|cloud|io|net)|elemnt\.ro)$~i', $host)) return false;

    $path = strtolower((string)(parse_url($url, PHP_URL_PATH) ?: ''));

    // Resposta específica para Biblioteca / Templates / Info do Elementor (evita warnings de array keys)
    if (strpos($path, 'library') !== false || strpos($path, '/info') !== false || strpos($path, 'templates') !== false) {
        $payload = [
            'success'      => true,
            'status'       => 'ok',
            'templates'    => [],
            'categories'   => [],
            'types_data'   => ['block' => ['categories' => []], 'page' => ['categories' => []]],
            'upgrade_notice' => [],
            'data'         => ['templates' => [], 'categories' => []],
        ];
    } else {
        // Resposta padrão para Licença / Ativação / Connect / API
        $payload = [
            'success'  => true,
            'status'   => 'valid',
            'license'  => 'valid',
            'expires'  => '2099-12-31 23:59:59',
            'features' => [],
            'data'     => [
                'license' => 'active',
                'status'  => 'valid',
                'expires' => '2099-12-31',
                'items'   => [],
            ],
        ];
    }

    return [
        'headers'  => ['content-type' => 'application/json; charset=UTF-8'],
        'body'     => wp_json_encode($payload),
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
    if (nw2_is_google_or_cf($url) || nw2_is_local_request($url)) return false;
    if (nw2_is_cron()) return false;
    if (nw2_is_woocommerce_critical_context()) return false;
    $host = parse_url($url, PHP_URL_HOST) ?: '';
    if (!$host) return false;
    if (nw2_is_smtp_host($host) || $host === nw2_get_post_smtp_host()) return false;
    return new WP_Error('nw2_fast_fail', 'Requisição externa bloqueada por política.');
}, 10, 3);

// 6) BLACKLIST — EXPANDIDA (AGRESSIVA, INCLUINDO SUCURI EXTERNO E TEMAS PESADOS)
add_filter('pre_http_request', function ($pre, $args, $url) {
    if (false !== $pre) return $pre;
    if (nw2_is_google_or_cf($url) || nw2_is_local_request($url) || nw2_is_smtp_host(parse_url($url, PHP_URL_HOST) ?: '')) {
        return false;
    }
    $bloqueios_dominio = apply_filters('nw2_blocker_blacklist', [
        'wpnull24.com','wpnull24.net','wplocker.com','gpldl.com','gpl.coffee','nulled.to',
        'festingervault.com','babia.to','srmehranclub.com','weadown.com','codelist.cc',
        'api.envato.com','support.wpbakery.com','sliderrevolution.com',
        'update.themeforest.net','update.avada.com','update.divi.com',
        'wp-plugin.sucuri.net','sitecheck.sucuri.net','sucuri.net',
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

// 8) DEFAULT DENY — LIGADO POR PADRAO (BLOQUEIA QUALQUER OUTRO SITE EXTERNO)
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
 * PARTE 1.5: LIMPEZA TOTAL DO DASHBOARD DO WORDPRESS (ZERO WIDGETS PESADOS)
 * ========================================================================== */
if (NW2_CLEAN_DASHBOARD) {
    // Remove o painel "Bem-vindo ao WordPress"
    add_action('load-index.php', function () {
        remove_action('welcome_panel', 'wp_welcome_panel');
    });
    add_filter('get_user_metadata', function ($value, $object_id, $meta_key) {
        if ($meta_key === 'show_welcome_panel') {
            return 0;
        }
        return $value;
    }, 10, 3);

    // Remove TODOS os widgets da página inicial do wp-admin (nativos + plugins como Elementor, Yoast, WooCommerce)
    $nw2_strip_dashboard_widgets = function () {
        global $wp_meta_boxes;
        remove_action('welcome_panel', 'wp_welcome_panel');

        if (isset($wp_meta_boxes['dashboard'])) {
            $wp_meta_boxes['dashboard'] = [];
        }
        if (isset($wp_meta_boxes['dashboard-network'])) {
            $wp_meta_boxes['dashboard-network'] = [];
        }
    };
    add_action('wp_dashboard_setup', $nw2_strip_dashboard_widgets, 9999);
    add_action('wp_network_dashboard_setup', $nw2_strip_dashboard_widgets, 9999);

    // Oculta as caixas tracejadas vazias ("Arraste caixas aqui") e botão "Opções de tela" na home do Dashboard
    add_action('admin_head-index.php', function () {
        ?>
        <style>
            #dashboard-widgets-wrap,
            #screen-options-link-wrap,
            #welcome-panel {
                display: none !important;
            }
        </style>
        <?php
    });
}

/* =============================================================================
 * PARTE 1.6: WAF LEVE SUBSTITUTO DO SUCURI (ANTI-ENUMERAÇÃO & FINGERPRINT)
 * ========================================================================== */
// Oculta versão do WordPress no front-end e feeds
remove_action('wp_head', 'wp_generator');
add_filter('the_generator', '__return_empty_string');

if (NW2_PROTECT_USER_ENUM) {
    // 1) Bloqueia enumeração de usuários via /?author=1 no front-end
    add_action('template_redirect', function () {
        if (!is_admin() && isset($_REQUEST['author']) && !current_user_can('edit_posts')) {
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }, 1);

    // 2) Bloqueia listagem pública de usuários na REST API (/wp-json/wp/v2/users) para não-logados
    add_filter('rest_endpoints', function ($endpoints) {
        if (!is_user_logged_in() || !current_user_can('edit_posts')) {
            unset($endpoints['/wp/v2/users']);
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }
        return $endpoints;
    });
}

/* =============================================================================
 * PARTE 2: SCANNER DE PERMISSÕES WORDPRESS
 * ========================================================================== */
if (NW2_SCAN_PERMISSIONS && is_admin()) {
    add_action('admin_init', function () {
        if (!current_user_can('manage_options')) return;
        if (defined('DOING_AJAX') && DOING_AJAX) return;

        // Verificação única por dia
        $last_scan = get_transient('nw2_last_permission_scan_result');
        if ($last_scan === false) {
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
                    if (@chmod($path, $expected)) {
                        $fixed++;
                        error_log('[NW2] Fixed permissions: ' . $path . ' from ' . decoct($current) . ' to ' . decoct($expected));
                    } else {
                        error_log('[NW2] Failed to fix permissions: ' . $path);
                    }
                }
            }
            $processed++;
        }

        // Verificação extra: arquivos PHP em uploads (limitado a 4 níveis e máx 3000 itens para não travar painel)
        $uploads_dir = WP_CONTENT_DIR . '/uploads';
        if (is_dir($uploads_dir)) {
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($uploads_dir, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );
                $iterator->setMaxDepth(4);
                $checked_files = 0;
                foreach ($iterator as $file_info) {
                    if (++$checked_files > 3000) break;
                    if (!$file_info->isFile()) continue;
                    $ext = strtolower($file_info->getExtension());
                    if (!in_array($ext, ['php', 'phtml', 'phar', 'php7', 'php8'], true)) {
                        continue;
                    }
                    $php_file = $file_info->getPathname();
                    $issues[] = [
                        'file' => $php_file,
                        'issue' => 'Arquivo executável PHP em pasta de uploads',
                        'severity' => 'critical'
                    ];
                    if ($fix && NW2_FIX_PERMISSIONS) {
                        if (@unlink($php_file)) {
                            $fixed++;
                            error_log('[NW2] Removed PHP file from uploads: ' . $php_file);
                        }
                    }
                }
            } catch (Exception $e) {
                error_log('[NW2] Upload scan error: ' . $e->getMessage());
            }
        }

        $result = [
            'issues' => $issues,
            'count' => count($issues),
            'fixed' => $fixed,
            'total_files' => $total_files,
            'processed' => $processed,
        ];

        if ($fix && NW2_FIX_PERMISSIONS && $fixed > 0 && NW2_PERMISSION_NOTIFY && is_admin() && current_user_can('manage_options')) {
            $admin_email = get_option('admin_email');
            if ($admin_email) {
                $subject = '[NW2 Security] Permissões corrigidas automaticamente';
                $body = "Foram corrigidos {$fixed} item(s) de permissão no site " . home_url() . ".\n\nNW2 Security Suite";
                @wp_mail($admin_email, $subject, $body);
            }
            set_transient('nw2_permission_fixed_notice', $fixed, 12 * HOUR_IN_SECONDS);
        }

        return $result;
    }
}

/* =============================================================================
 * PARTE 3: HARDENING DE .HTACCESS AUTOMÁTICO (AMIGÁVEL AO GOOGLE E WORDPRESS)
 * ========================================================================== */
if (NW2_AUTO_HARDEN_HTACCESS) {
    add_action('admin_init', function() {
        if (!current_user_can('manage_options')) return;
        if (defined('DOING_AJAX') && DOING_AJAX) return;

        $htaccess_file = ABSPATH . '.htaccess';
        if (!file_exists($htaccess_file)) return;

        $htaccess_hash = get_transient('nw2_htaccess_hash');
        $current_hash = md5_file($htaccess_file);

        if (!$htaccess_hash || $htaccess_hash !== $current_hash) {
            if (nw2_harden_htaccess()) {
                $current_hash = md5_file($htaccess_file);
            }
            set_transient('nw2_htaccess_hash', $current_hash, 7 * DAY_IN_SECONDS);
        }

        // Garante proteção contra execução de PHP dentro de wp-content/uploads
        nw2_harden_uploads_htaccess();
    });
}

if (!function_exists('nw2_harden_uploads_htaccess')) {
    function nw2_harden_uploads_htaccess(): void {
        $uploads_htaccess = WP_CONTENT_DIR . '/uploads/.htaccess';
        if (!is_dir(WP_CONTENT_DIR . '/uploads')) return;
        $marker = '# NW2 UPLOADS NO-PHP';
        $existing = is_file($uploads_htaccess) ? (string)file_get_contents($uploads_htaccess) : '';
        if (strpos($existing, $marker) !== false) return;

        $rules = "\n{$marker}\n";
        $rules .= "<FilesMatch \"\\.(?i:php|phtml|phar|php3|php4|php5|php7|php8|pht|shtml|cgi|pl|py)$\">\n";
        $rules .= "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n";
        $rules .= "<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n";
        $rules .= "</FilesMatch>\n";
        $rules .= "# END NW2 UPLOADS NO-PHP\n";
        @file_put_contents($uploads_htaccess, $existing . $rules);
    }
}

if (!function_exists('nw2_harden_htaccess')) {
    function nw2_harden_htaccess(): bool {
        $htaccess_path = ABSPATH . '.htaccess';
        if (!file_exists($htaccess_path)) {
            return false;
        }
        if (filesize($htaccess_path) > 2 * 1024 * 1024) {
            error_log('[NW2] .htaccess muito grande para hardening.');
            return false;
        }
        $original_content = (string) file_get_contents($htaccess_path);

        // Regras de segurança compatíveis com Google (Imagens/Bots) e WordPress (Cron/REST)
        $security_rules = "\n# ======= NW2 SECURITY HARDENING =======\n";
        $security_rules .= "<IfModule mod_headers.c>\n";
        $security_rules .= "Header always set X-Content-Type-Options \"nosniff\"\n";
        $security_rules .= "Header always set X-Frame-Options \"SAMEORIGIN\"\n";
        $security_rules .= "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n";
        $security_rules .= "</IfModule>\n\n";

        // 1. Protege wp-config.php e xmlrpc.php
        $security_rules .= "<FilesMatch \"^(wp-config\\.php|xmlrpc\\.php)$\">\n";
        $security_rules .= "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n";
        $security_rules .= "<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n";
        $security_rules .= "</FilesMatch>\n\n";

        // 2. Bloqueia acesso a arquivos sensíveis, dumps SQL e backups (sem bloquear .zip legítimos de mídia)
        $security_rules .= "<FilesMatch \"(^\\.|wp-config-sample\\.php|readme\\.html|license\\.txt|\\.(sql|tar|tgz|bak|old|swp|log|ini|conf|env|sh)$)\">\n";
        $security_rules .= "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n";
        $security_rules .= "<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n";
        $security_rules .= "</FilesMatch>\n\n";

        // 3. Bloqueia scanners de vulnerabilidade conhecidos (preservando curl/Googlebot/WordPress)
        $security_rules .= "<IfModule mod_rewrite.c>\n";
        $security_rules .= "RewriteEngine On\n";
        $security_rules .= "RewriteRule ^wp-content/includes/ - [F,L]\n";
        $security_rules .= "RewriteCond %{HTTP_USER_AGENT} (libwww-perl|nikto|wkto|sqlmap|zgrab|masscan|nuclei|acunetix|dirbuster|havij) [NC]\n";
        $security_rules .= "RewriteRule .* - [F,L]\n";
        $security_rules .= "</IfModule>\n";
        $security_rules .= "Options -Indexes\n";
        $security_rules .= "ServerSignature Off\n";

        // Remove regras anteriores NW2 se existirem
        $pattern = '/# ======= NW2 SECURITY HARDENING =======.*?# ======= END NW2 =======/s';
        $cleaned_content = preg_replace($pattern, '', $original_content);
        $cleaned_content = preg_replace('/\n{3,}/', "\n\n", (string)$cleaned_content);

        // Adiciona novas regras
        $new_content = rtrim($cleaned_content) . "\n" . $security_rules . "# ======= END NW2 =======\n";

        if ($new_content === $original_content) {
            return true;
        }

        // Backup versionado do original
        if ($original_content !== '') {
            $backup_path = $htaccess_path . '.backup-' . gmdate('Ymd-His');
            if (!file_exists($backup_path)) {
                @file_put_contents($backup_path, $original_content);
            }
            $backups = glob($htaccess_path . '.backup-*');
            if (is_array($backups) && count($backups) > NW2_MAX_HTACCESS_BACKUPS) {
                usort($backups, 'filemtime');
                for ($i = 0; $i < count($backups) - 10; $i++) {
                    @unlink($backups[$i]);
                }
            }
        }

        if (!is_writable($htaccess_path)) {
            error_log('[NW2] .htaccess não é gravável.');
            return false;
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
        if (defined('DOING_AJAX') && DOING_AJAX) return;
        nw2_monitor_core_files();
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

        $last_check = get_transient('nw2_last_file_monitor_check');
        $previous_hashes = get_option('nw2_file_hashes', []);
        if ($last_check && time() - $last_check < 6 * HOUR_IN_SECONDS) {
            return nw2_detect_file_changes($previous_hashes, $critical_files);
        }

        $current_hashes = [];
        foreach ($critical_files as $file) {
            if (file_exists($file)) {
                $current_hashes[$file] = md5_file($file);
            }
        }

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

        update_option('nw2_file_hashes', $current_hashes);
        set_transient('nw2_last_file_monitor_check', time(), 6 * HOUR_IN_SECONDS);

        return $changes;
    }
}

if (!function_exists('nw2_detect_file_changes')) {
    function nw2_detect_file_changes(array $previous_hashes, array $critical_files): array {
        $changes = [];
        foreach ($critical_files as $file) {
            if (!file_exists($file) || !isset($previous_hashes[$file])) {
                continue;
            }
            $hash = md5_file($file);
            if ($previous_hashes[$file] !== $hash) {
                $changes[] = [
                    'file' => $file,
                    'previous_hash' => $previous_hashes[$file],
                    'current_hash' => $hash,
                    'timestamp' => filemtime($file)
                ];
            }
        }
        return $changes;
    }
}

/* =============================================================================
 * PARTE 5: SANITIZAÇÃO DE UPLOADS
 * ========================================================================== */
if (NW2_SANITIZE_UPLOADS) {
    add_filter('wp_handle_upload_prefilter', function($file) {
        $filename = $file['name'] ?? '';
        $tmp_name = $file['tmp_name'] ?? '';

        // 1. Verifica extensões perigosas e dupla extensão (ex: shell.php.jpg)
        $dangerous_exts = ['.php', '.phtml', '.phar', '.inc', '.php3', '.php4', '.php5', '.php7', '.php8', '.pht', '.shtml', '.htaccess', '.user.ini'];
        $lower_name = strtolower($filename);
        foreach ($dangerous_exts as $ext) {
            if (str_ends_with($lower_name, $ext) || strpos($lower_name, $ext . '.') !== false) {
                $file['error'] = 'Extensão ou nome de arquivo não permitido por segurança.';
                return $file;
            }
        }

        // 2. Verifica conteúdo de arquivos de imagem e bloqueia payload PHP embutido
        if (preg_match('/\.(jpg|jpeg|png|gif|webp)$/i', $filename) && is_readable($tmp_name)) {
            $size = @getimagesize($tmp_name);
            if ($size === false) {
                $file['error'] = 'Arquivo de imagem inválido ou corrompido.';
                return $file;
            }
            $head = (string) @file_get_contents($tmp_name, false, null, 0, 4096);
            if (stripos($head, '<?php') !== false || stripos($head, '<?=') !== false) {
                $file['error'] = 'Imagem contém código executável bloqueado.';
                return $file;
            }
        }

        // 3. Verifica arquivos SVG para conteúdo malicioso
        if (str_ends_with($lower_name, '.svg')) {
            $max_svg_size = 2 * 1024 * 1024;
            if (!is_readable($tmp_name) || filesize($tmp_name) > $max_svg_size) {
                $file['error'] = 'SVG muito grande ou ilegível.';
                return $file;
            }
            $content = (string) file_get_contents($tmp_name);
            $dangerous_patterns = [
                '~<script~i',
                '~javascript:~i',
                '~\sonload\s*=~i',
                '~\sonerror\s*=~i',
                '~\sonclick\s*=~i',
                '~<iframe~i',
                '~<object~i',
                '~<embed~i',
                '~xlink:href\s*=\s*["\'][^"\']*data:~i',
            ];
            foreach ($dangerous_patterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $file['error'] = 'SVG contém elementos potencialmente perigosos.';
                    return $file;
                }
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
        $marker = 'NW2_BLOCKED_REQUESTS';
        $existing = is_file($htaccess) ? (string)file_get_contents($htaccess) : '';
        if (strpos($existing, $marker) !== false) return;
        $rule = "\n# NW2_BLOCKED_REQUESTS — protege log de requisições bloqueadas\n<FilesMatch \"^nw2-blocked-requests-.*\\.log(\\.old)?$\">\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n</FilesMatch>\n";
        @file_put_contents($htaccess, $existing . $rule);
    }
}

if (!function_exists('nw2_log_blocked')) {
    function nw2_log_blocked(string $message): void {
        $log_dir = WP_CONTENT_DIR;
        $log_file = $log_dir . '/nw2-blocked-requests-' . gmdate('Y-m') . '.log';
        nw2_ensure_log_protected();
        if (file_exists($log_file) && filesize($log_file) > 10 * 1024 * 1024) {
            rename($log_file, $log_file . '.old');
        }
        $fp = fopen($log_file, 'a');
        if (!$fp) {
            error_log('[NW2] Failed to open log file: ' . $log_file);
            return;
        }
        if (flock($fp, LOCK_EX)) {
            fwrite($fp, $message);
            fflush($fp);
            flock($fp, LOCK_UN);
        }
        fclose($fp);

        // Auto-limpeza diária de logs antigos
        if (!get_transient('nw2_logs_cleaned_today')) {
            nw2_clear_old_logs(NW2_MAX_LOG_AGE_DAYS);
            set_transient('nw2_logs_cleaned_today', true, DAY_IN_SECONDS);
            nw2_ensure_log_protected();
        }
    }
}

/* =============================================================================
 * HARDENING BÁSICO (COMPATIBILIDADE)
 * ========================================================================== */
if (!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true);
add_filter('xmlrpc_enabled', '__return_false');

/* =============================================================================
 * TIMEOUTS CONTROLADOS (SEM INTERROMPER DOWNLOADS DO WORDPRESS.ORG)
 * ========================================================================== */
add_filter('http_request_args', function ($r, $url = '') {
    // Preserva o timeout longo (300s) para downloads de pacotes de atualização do WordPress.org
    if (!empty($r['stream']) || ($url && (nw2_host_matches($url, 'wordpress.org') || nw2_host_matches($url, 'w.org')))) {
        $r['timeout'] = max((int)($r['timeout'] ?? 30), 120);
        $r['sslverify'] = true;
        return $r;
    }
    $r['timeout'] = 15;
    $r['connect_timeout'] = 7;
    $r['redirection'] = 3;
    $r['sslverify'] = true;
    return $r;
}, 10, 2);

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
        $user_id = get_current_user_id();

        if ($user_id && get_user_meta($user_id, 'nw2_hide_all_alerts', true)) {
            return ['alerts' => [], 'count' => 0, 'timestamp' => time()];
        }

        // 1. Alerta sobre curl_exec
        if (function_exists('curl_exec') && !get_user_meta($user_id, 'nw2_hide_curl_alert', true)) {
            $alerts[] = [
                'id' => 'curl_alert',
                'title' => 'Função PHP curl_exec habilitada',
                'message' => 'Plugins podem bypassar este bloqueador usando curl nativo ou sockets crus.',
                'solution' => 'Adicione ao php.ini:<br><code>disable_functions = curl_exec, curl_multi_exec, fsockopen, stream_socket_client</code>',
                'severity' => 'warning',
                'dismissible' => true
            ];
            $alert_count++;
        }

        // 2. Scanner de permissões (lê do cache transient ou executa 1x/dia)
        if (NW2_SCAN_PERMISSIONS && !get_user_meta($user_id, 'nw2_hide_permission_scan_alert', true)) {
            $scan_result = get_transient('nw2_last_permission_scan_result');
            if ($scan_result === false) {
                $scan_result = nw2_scan_wordpress_permissions();
                set_transient('nw2_last_permission_scan_result', $scan_result, 24 * HOUR_IN_SECONDS);
            }
            if (is_array($scan_result) && !empty($scan_result['issues'])) {
                $count = (int)$scan_result['count'];
                $alerts[] = [
                    'id' => 'permission_scan',
                    'title' => "{$count} problema(s) de permissões encontrados",
                    'message' => 'Alguns arquivos têm permissões incorretas.',
                    'details' => array_slice($scan_result['issues'], 0, 5),
                    'severity' => 'warning',
                    'dismissible' => true
                ];
                $alert_count += $count;
            }
        }

        // 3. Monitor de arquivos
        if (NW2_MONITOR_FILE_CHANGES && !get_user_meta($user_id, 'nw2_hide_file_changes_alert', true)) {
            $file_changes = nw2_monitor_core_files();
            if (!empty($file_changes)) {
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

    add_submenu_page(
        'nw2-security-dashboard',
        'Logs',
        'Logs',
        'manage_options',
        'nw2-security-logs',
        'nw2_render_logs'
    );
});

function nw2_render_dashboard() {
    $alerts = nw2_get_all_alerts();
    ?>
    <div class="wrap">
        <h1>NW2 Security Dashboard <small style="font-size:13px;color:#666;">v<?php echo esc_html(nw2_security_version()); ?></small></h1>
        <?php if (isset($_GET['scanned'])): ?>
            <div class="notice notice-success is-dismissible"><p>Scanner executado com sucesso.</p></div>
        <?php endif; ?>
        <?php if (isset($_GET['hardened'])): ?>
            <div class="notice notice-success is-dismissible"><p>Hardening aplicado.</p></div>
        <?php endif; ?>
        <?php if (isset($_GET['dismissed_all'])): ?>
            <div class="notice notice-info is-dismissible"><p>Alertas dispensados.</p></div>
        <?php endif; ?>

        <!-- Status Cards -->
        <div class="nw2-dashboard-grid">
            <div class="nw2-card">
                <h2>Status Geral</h2>
                <p><strong>Bloqueador Externo (Elementor Stub):</strong> <span class="nw2-status nw2-<?php echo NW2_DEFAULT_DENY ? 'active' : 'inactive'; ?>"><?php echo NW2_DEFAULT_DENY ? 'Ativo' : 'Inativo'; ?></span></p>
                <p><strong>Dashboard WP Limpo:</strong> <span class="nw2-status nw2-<?php echo NW2_CLEAN_DASHBOARD ? 'active' : 'inactive'; ?>"><?php echo NW2_CLEAN_DASHBOARD ? 'Ativo' : 'Inativo'; ?></span></p>
                <p><strong>WAF Anti-Enumeração:</strong> <span class="nw2-status nw2-<?php echo NW2_PROTECT_USER_ENUM ? 'active' : 'inactive'; ?>"><?php echo NW2_PROTECT_USER_ENUM ? 'Ativo' : 'Inativo'; ?></span></p>
                <p><strong>Scanner Permissões:</strong> <span class="nw2-status nw2-<?php echo NW2_SCAN_PERMISSIONS ? 'active' : 'inactive'; ?>"><?php echo NW2_SCAN_PERMISSIONS ? 'Ativo' : 'Inativo'; ?></span></p>
                <p><strong>Hardening .htaccess:</strong> <span class="nw2-status nw2-<?php echo NW2_AUTO_HARDEN_HTACCESS ? 'active' : 'inactive'; ?>"><?php echo NW2_AUTO_HARDEN_HTACCESS ? 'Ativo' : 'Inativo'; ?></span></p>
                <p><strong>Monitor de Arquivos:</strong> <span class="nw2-status nw2-<?php echo NW2_MONITOR_FILE_CHANGES ? 'active' : 'inactive'; ?>"><?php echo NW2_MONITOR_FILE_CHANGES ? 'Ativo' : 'Inativo'; ?></span></p>
                <p><strong>Sanitização Uploads:</strong> <span class="nw2-status nw2-<?php echo NW2_SANITIZE_UPLOADS ? 'active' : 'inactive'; ?>"><?php echo NW2_SANITIZE_UPLOADS ? 'Ativo' : 'Inativo'; ?></span></p>
            </div>

            <div class="nw2-card">
                <h2>Alertas Ativos</h2>
                <?php if ($alerts['count'] > 0): ?>
                    <div class="nw2-alerts-summary">
                        <p><strong><?php echo esc_html($alerts['count']); ?> alerta(s) encontrado(s)</strong></p>
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
define('NW2_DEFAULT_DENY', true);           // Bloqueador de requisições externas
define('NW2_CLEAN_DASHBOARD', true);        // Limpa 100% dos widgets do Dashboard WP
define('NW2_PROTECT_USER_ENUM', true);      // Bloqueia enumeração de usuários (?author=1 e REST)
define('NW2_SCAN_PERMISSIONS', true);       // Scanner de permissões
define('NW2_AUTO_HARDEN_HTACCESS', true);   // Hardening .htaccess + uploads sem PHP
define('NW2_MONITOR_FILE_CHANGES', true);   // Monitor de arquivos críticos
define('NW2_SANITIZE_UPLOADS', true);       // Sanitização de uploads (imagens/SVG/dupla ext)
define('NW2_DEBUG_LOG', false);             // Log de debug de bloqueios (opcional)
            </pre>

            <p><strong>ATENÇÃO:</strong> Nunca defina <code>WP_HTTP_BLOCK_EXTERNAL=true</code> — este plugin usa sistema próprio inteligente.</p>
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
                        <p><?php echo esc_html($alert['message']); ?></p>

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
                                                } elseif (isset($detail['issue'])) {
                                                    echo " ({$detail['issue']})";
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
                                <strong>Solução:</strong><br><?php echo wp_kses_post($alert['solution']); ?>
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

function nw2_render_logs() {
    $log_files = nw2_get_log_files();
    $current_file = isset($_GET['log']) ? sanitize_text_field($_GET['log']) : (reset($log_files) ?: '');
    // Valida que o arquivo pertence ao diretório WP_CONTENT_DIR
    if ($current_file && strpos(realpath($current_file) ?: '', realpath(WP_CONTENT_DIR) ?: WP_CONTENT_DIR) !== 0) {
        $current_file = '';
    }
    $content = ($current_file && file_exists($current_file)) ? file_get_contents($current_file) : '';
    $lines = $content ? array_filter(array_map('trim', explode("\n", $content))) : [];
    $lines = array_values($lines);
    $per_page = 200;
    $total_lines = count($lines);
    $total_pages = max(1, (int) ceil($total_lines / $per_page));
    $page = isset($_GET['log_page']) ? max(1, (int) $_GET['log_page']) : 1;
    $page = min($page, $total_pages);
    $offset = ($page - 1) * $per_page;
    $paged_lines = array_slice($lines, $offset, $per_page);
    ?>
    <div class="wrap">
        <h1>Logs NW2 Security</h1>
        <?php if (empty($log_files)): ?>
            <div class="nw2-card">
                <p>Nenhum log encontrado.</p>
            </div>
        <?php else: ?>
            <div class="nw2-card">
                <form method="get">
                    <input type="hidden" name="page" value="nw2-security-logs" />
                    <label for="log-select">Arquivo:</label>
                    <select id="log-select" name="log" onchange="this.form.submit()">
                        <?php foreach ($log_files as $file): ?>
                            <option value="<?php echo esc_attr($file); ?>" <?php selected($current_file, $file); ?>>
                                <?php echo esc_html(basename($file)); ?> (<?php echo esc_html(file_exists($file) ? size_format(filesize($file)) : 'N/A'); ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </form>
                <form method="post" style="margin-top: 10px;">
                    <?php wp_nonce_field('nw2_logs', 'nw2_nonce'); ?>
                    <button type="submit" name="nw2_clear_old_logs" class="button" onclick="return confirm('Remover logs com mais de 90 dias?');">
                        Limpar Logs Antigos
                    </button>
                </form>
            </div>
            <div class="nw2-card">
                <pre style="background: #f5f5f5; padding: 15px; border-radius: 4px; max-height: 600px; overflow: auto;"><?php echo esc_html($content ? implode("\n", $paged_lines) : 'Log vazio.'); ?></pre>
                <?php if ($total_pages > 1): ?>
                <div class="tablenav">
                    <div class="tablenav-pages">
                        <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                            <?php if ($i === $page): ?>
                                <strong><?php echo esc_html($i); ?></strong>
                            <?php else: ?>
                                <a href="<?php echo esc_url(add_query_arg('log_page', $i)); ?>"><?php echo esc_html($i); ?></a>
                            <?php endif; ?>
                        <?php endfor; ?>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
    <style>
        .nw2-card { background: #fff; border: 1px solid #ccd0d4; padding: 20px; margin: 20px 0; border-radius: 4px; }
    </style>
    <?php
}

if (!function_exists('nw2_get_log_files')) {
    function nw2_get_log_files(): array {
        $files = glob(WP_CONTENT_DIR . '/nw2-blocked-requests-*.log*');
        return is_array($files) ? array_reverse($files) : [];
    }
}

if (!function_exists('nw2_clear_old_logs')) {
    function nw2_clear_old_logs(int $days = NW2_MAX_LOG_AGE_DAYS): int {
        $removed = 0;
        $cutoff = time() - ($days * DAY_IN_SECONDS);
        foreach (nw2_get_log_files() as $file) {
            if (filemtime($file) < $cutoff) {
                if (@unlink($file)) {
                    $removed++;
                }
            }
        }
        return $removed;
    }
}

/* =============================================================================
 * HANDLERS DE AÇÕES
 * ========================================================================== */
add_action('admin_init', function() {
    if (!current_user_can('manage_options')) return;

    // Dismiss single alert
    if (isset($_POST['nw2_dismiss_alert']) && wp_verify_nonce($_POST['nw2_nonce'] ?? '', 'nw2_alerts')) {
        $alert_id = sanitize_text_field($_POST['nw2_dismiss_alert']);
        update_user_meta(get_current_user_id(), "nw2_hide_{$alert_id}_alert", true);
        wp_safe_redirect(admin_url('admin.php?page=nw2-security-alerts&dismissed=1'));
        exit;
    }

    // Dismiss all alerts
    if (isset($_POST['nw2_dismiss_all_alerts']) && wp_verify_nonce($_POST['nw2_nonce'] ?? '', 'nw2_alerts')) {
        $user_id = get_current_user_id();
        foreach (['curl_alert', 'permission_scan', 'file_changes', 'global', 'all'] as $alert_id) {
            update_user_meta($user_id, "nw2_hide_{$alert_id}_alert", true);
        }
        update_user_meta($user_id, 'nw2_hide_all_alerts', true);
        wp_safe_redirect(admin_url('admin.php?page=nw2-security-alerts&dismissed_all=1'));
        exit;
    }

    // Quick actions
    if (isset($_POST['nw2_scan_now']) && wp_verify_nonce($_POST['nw2_nonce'] ?? '', 'nw2_actions')) {
        $scan_result = nw2_scan_wordpress_permissions();
        set_transient('nw2_last_permission_scan_result', $scan_result, 24 * HOUR_IN_SECONDS);
        set_transient('nw2_scan_result', $scan_result['count'], 300);
        wp_safe_redirect(admin_url('admin.php?page=nw2-security-dashboard&scanned=1'));
        exit;
    }

    if (isset($_POST['nw2_harden_now']) && wp_verify_nonce($_POST['nw2_nonce'] ?? '', 'nw2_actions')) {
        $result = nw2_harden_htaccess();
        nw2_harden_uploads_htaccess();
        set_transient('nw2_harden_result', $result ? 'success' : 'error', 300);
        wp_safe_redirect(admin_url('admin.php?page=nw2-security-dashboard&hardened=1'));
        exit;
    }

    // Dismiss all from dashboard
    if (isset($_POST['nw2_dismiss_all']) && wp_verify_nonce($_POST['nw2_nonce'] ?? '', 'nw2_actions')) {
        $user_id = get_current_user_id();
        foreach (['curl_alert', 'permission_scan', 'file_changes', 'global', 'all'] as $alert_id) {
            update_user_meta($user_id, "nw2_hide_{$alert_id}_alert", true);
        }
        update_user_meta($user_id, 'nw2_hide_all_alerts', true);
        wp_safe_redirect(admin_url('admin.php?page=nw2-security-dashboard&dismissed_all=1'));
        exit;
    }

    // Clear old logs
    if (isset($_POST['nw2_clear_old_logs']) && wp_verify_nonce($_POST['nw2_nonce'] ?? '', 'nw2_logs')) {
        $removed = nw2_clear_old_logs();
        wp_safe_redirect(admin_url('admin.php?page=nw2-security-logs&cleared=' . intval($removed)));
        exit;
    }
});

/* =============================================================================
 * ADMIN NOTICE ÚNICO (LIMPO)
 * ========================================================================== */
add_action('admin_notices', function() {
    if (!current_user_can('manage_options')) return;
    $alerts = nw2_get_all_alerts();

    if ($alerts['count'] === 0 || get_user_meta(get_current_user_id(), 'nw2_hide_global_alert', true)) {
        return;
    }
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
        $('.nw2-global-alert .notice-dismiss').on('click', function() {
            $.post(ajaxurl, {
                action: 'nw2_dismiss_notice',
                nonce: '<?php echo wp_create_nonce('nw2_dismiss'); ?>'
            });
        });

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
    $user_id = get_current_user_id();
    foreach (['curl_alert', 'permission_scan', 'file_changes', 'global'] as $alert_id) {
        update_user_meta($user_id, "nw2_hide_{$alert_id}_alert", true);
    }
    update_user_meta($user_id, 'nw2_hide_all_alerts', true);
    wp_die();
});

/* =============================================================================
 * FIM DO PLUGIN
 * ========================================================================== */

if (!function_exists('nw2_security_version')) {
    function nw2_security_version(): string {
        return '3.2.0';
    }
}
