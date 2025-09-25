<?php

/**
 * Plugin Name: Bloqueador de Requisições Externas (MU)
 * Plugin URI:  https://www.nw2web.com.br
 * Description: Bloqueia conexões externas indesejadas, entrega stubs locais p/ Elementor Home, libera Google Site Kit e Cloudflare, e otimiza WooCommerce para catálogo.
 * Author:      Fausto - nw2web.com.br
 * Version:     1.7.0
 *
 * Recomenda-se instalar como MU-plugin:
 * wp-content/mu-plugins/bloqueador-requisicoes.php
 */

if (! defined('ABSPATH')) exit;

/* ============================================================================
 * 0) Recomendação MU (aviso leve se não estiver em mu-plugins)
 * ========================================================================== */
add_action('admin_init', function () {
    $in_mu = (strpos(__DIR__, 'mu-plugins') !== false);
    if (! $in_mu && current_user_can('manage_options')) {
        add_action('admin_notices', function () {
            echo '<div class="notice notice-warning"><p><strong>Bloqueador de Requisições Externas:</strong> recomenda-se mover este plugin para <code>wp-content/mu-plugins/</code> para impedir desativação acidental.</p></div>';
        });
    }
});

/* ============================================================================
 * 1) Bloqueio global e lista de hosts permitidos (para requests legítimos)
 * ========================================================================== */
if (! defined('WP_HTTP_BLOCK_EXTERNAL')) {
    define('WP_HTTP_BLOCK_EXTERNAL', true);
}

if (! defined('WP_ACCESSIBLE_HOSTS')) {
    $hosts_permitidos = [
        // WordPress core/updates
        'api.wordpress.org',
        'downloads.wordpress.org',

        // Google / Site Kit (Analytics, Search Console, AdSense, Tag Manager, PSI)
        '*.google.com',
        '*.googleapis.com',
        '*.gstatic.com',
        'www.googletagmanager.com',
        'sitekit.withgoogle.com',
        'page-speed-insights.appspot.com',

        // Elementor (apenas para que o nosso stub de rede possa interceptar)
        'elementor.com',
        'my.elementor.com',
        'pro.elementor.com',
        'elementor.cloud',
        'assets.elementor.com',
        'go.elementor.com',

        // Cloudflare (plugin oficial / OAuth / API v4 / IP lists)
        'api.cloudflare.com',
        'dash.cloudflare.com',
        'www.cloudflare.com',
    ];
    define('WP_ACCESSIBLE_HOSTS', implode(',', array_unique($hosts_permitidos)));
}

/* Força permissão explícita para Cloudflare mesmo com WP_HTTP_BLOCK_EXTERNAL */
add_filter('http_request_host_is_external', function ($is_external, $host) {
    if (preg_match('/(^|\.)cloudflare\.com$/i', (string)$host)) {
        return true;
    }
    return $is_external;
}, 10, 2);

/* ============================================================================
 * 2) Elementor Home — desabilitar UI e garantir dados seguros sem internet
 * ========================================================================== */

/* Esconde a Home do Elementor (quando suportado) */
add_filter('elementor/admin/show_home_screen', '__return_false', 0);

/* Remove o enqueue que inicializa a Home (evita Transformations_Manager) */
add_action('elementor/init', function () {
    if (! class_exists('\Elementor\Plugin')) return;
    $plugin = \Elementor\Plugin::$instance;
    if (! isset($plugin->modules_manager)) return;

    $modules = [];
    if (method_exists($plugin->modules_manager, 'get_modules')) {
        // Algumas versões aceitam 0 args; se não, trate como vazio
        try {
            $modules = $plugin->modules_manager->get_modules();
        } catch (\Throwable $e) {
            $modules = [];
        }
    }
    if (isset($modules['home'])) {
        $home = $modules['home'];
        remove_action('admin_print_scripts',   [$home, 'enqueue_home_screen_scripts']);
        remove_action('admin_enqueue_scripts', [$home, 'enqueue_home_screen_scripts']);
    }
}, 20);

/* Stub: qualquer chamada a elementor.* recebe JSON local consistente */
add_filter('pre_http_request', function ($pre, $args, $url) {
    $host = parse_url($url, PHP_URL_HOST) ?: '';
    if (preg_match('~(^|\.)elementor\.(com|cloud)$~i', $host)) {
        $stub = [
            'add_ons'                    => ['repeater' => []],
            'get_started'                => [],
            'sidebar_promotion_variants' => [],
            'top_with_licences'          => [],
            'promotions'                 => [],
            'banners'                    => [],
            'cards'                      => [],
            'items'                      => [],
            'status'                     => 'ok',
        ];
        return [
            'headers'  => ['content-type' => 'application/json; charset=UTF-8'],
            'body'     => wp_json_encode($stub),
            'response' => ['code' => 200, 'message' => 'OK'],
            'cookies'  => [],
            'filename' => null,
        ];
    }
    return $pre;
}, 0, 3);

/* Fallback: se algo ainda chamar os itens da Home, injeta esqueleto seguro */
add_filter('elementor/home_screen/items', function ($data) {
    if (!is_array($data)) $data = [];
    $defaults = [
        'add_ons'                    => ['repeater' => []],
        'get_started'                => [],
        'sidebar_promotion_variants' => [],
        'top_with_licences'          => [],
        'promotions'                 => [],
        'banners'                    => [],
        'cards'                      => [],
        'items'                      => [],
    ];
    return array_replace_recursive($defaults, $data);
}, 0);

/* Limpa transients/opções antigas da Home para evitar lixo com null */
add_action('admin_init', function () {
    foreach (
        [
            'elementor_remote_info_api_data',
            'e_home_screen_items',
            'elementor_home_screen_items',
            'elementor_remote_banners',
        ] as $k
    ) {
        delete_transient($k);
        delete_site_transient($k);
        delete_option($k);
    }
}, 20);

/* ============================================================================
 * 3) Bloqueio extra — blacklist de domínios indesejados/maliciosos
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {
    // Respeita qualquer resposta já produzida por um stub anterior
    if ($pre !== false) return $pre;

    $bloqueios = [
        'wpnull24.com',
        'wpnull24.net',
        'wplocker.com',
        'gpldl.com',
        'yukapo.com',
        '1nulled.com',
        'codelist.cc',
        'crackthemes.com',
        'gplastra.com',
        'jojo-themes.net',
        'nullphp.net',
        'null.market',
        'nulled.one',
        'nullphpscript.com',
        'nulledtemplates.com',
        'nulledscripts.net',
        'nulled-scripts.xyz',
        'nulledscripts.online',
        'nullfresh.com',
        'nulljungle.com',
        'nullscript.top',
        'nulleb.com',
        'nulled.cx',
        'nulleds.io',
        'nullscript.xyz',
        'nullphpscript.xyz',
        'nullradar.com',
        'phpnulled.cc',
        'proweblab.xyz',
        'socialgrowth.club',
        'upnull.com',
        'weadown.com',
        'weaplay.com',
        'woocrack.com',
        'wpnull.org',
        'festingervault.com',
        'wordpress-premium.net',
        'srmehranclub.com',
        'pluginsforwp.com',
        'gplvault.com',
        'worldpressit.com',
        'themecanal.com',
        'gpl.coffee',
        'gplchimp.com',
        'plugintheme.net',
        'gplplus.com',
        'gplhub.net',
        'gplplugins.club',
        'babia.to',

        // scanners/serviços indesejados
        'wp-plugin.sucuri.net',
        'sitecheck.sucuri.net',

        // builders/temas (updates externos não essenciais)
        'support.wpbakery.com',
        'sliderrevolution.com',
        'revslider',
        'slider-revolution',
        'revslider.php',
        'salient',
        'betheme',
        'bridge.qodeinteractive.com',
        'update.yithemes.com',
        'yithemes.com',
        // OBS: não bloqueamos elementor.* aqui (stub já lida acima).
    ];

    foreach ($bloqueios as $dominio) {
        if (stripos($url, $dominio) !== false) {
            if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
                error_log("🔒 Requisição bloqueada: $url");
            }
            return new WP_Error('bloqueado_politica', __('Conexão externa bloqueada por política de segurança.'));
        }
    }
    return $pre;
}, 1, 3);

/* ============================================================================
 * 4) WooCommerce — otimizações para uso como catálogo
 * ========================================================================== */
add_action('init', function () {
    add_filter('woocommerce_admin_disabled', '__return_true');
    add_filter('woocommerce_allow_marketplace_suggestions', '__return_false');
    add_filter('woocommerce_show_marketplace_suggestions', '__return_false');
    add_filter('woocommerce_tracker_send_event', '__return_false');
    add_filter('woocommerce_helper_suppress_admin_notices', '__return_true');
}, 10);

add_action('wp_enqueue_scripts', function () {
    wp_dequeue_script('wc-cart');
    wp_dequeue_script('wc-checkout');
    wp_dequeue_script('wc-add-to-cart');
}, 100);

/* ============================================================================
 * 5) (Opcional) Higiene de autoload em opções conhecidas (Elementor)
 *    - impede que opções de licença/breakpoints entrem no autoload
 * ========================================================================== */
add_action('admin_init', function () {
    global $wpdb;
    $opts = [
        '_elementor_pro_license_data',
        '_elementor_pro_license_v2_data',
        'elementor-custom-breakpoints-files',
    ];
    $placeholders = implode(',', array_fill(0, count($opts), '%s'));
    $wpdb->query(
        $wpdb->prepare(
            "UPDATE {$wpdb->options} SET autoload='no' WHERE option_name IN ($placeholders)",
            ...$opts
        )
    );
}, 30);
