<?php

/**
 * Plugin Name: Bloqueador de Requisições Externas
 * Plugin URI: https://www.nw2web.com.br
 * Description: Bloqueia conexões externas desnecessárias e maliciosas, e otimiza o WooCommerce para uso como catálogo.
 * Author: Fausto - nw2web.com.br
 * Version: 1.6.2
 */

// BLOQUEIO GLOBAL DE CONEXÕES EXTERNAS
if (!defined('WP_HTTP_BLOCK_EXTERNAL')) {
    define('WP_HTTP_BLOCK_EXTERNAL', true);
}

// 1) Esconde a Home do Elementor (quando suportado)
add_filter('elementor/admin/show_home_screen', '__return_false', 0);

// 2) Remove o enqueue da Home (evita chamar Transformations_Manager)
add_action('elementor/init', function () {
    if (!class_exists('\Elementor\Plugin')) return;
    $plugin = \Elementor\Plugin::$instance;

    if (!isset($plugin->modules_manager)) return;

    $modules_manager = $plugin->modules_manager;

    // Corrige a chamada do método com argumento vazio
    if (method_exists($modules_manager, 'get_modules')) {
        $modules = $modules_manager->get_modules([]);
    } else {
        $modules = [];
    }

    if (isset($modules['home'])) {
        $home = $modules['home'];
        remove_action('admin_print_scripts',  [$home, 'enqueue_home_screen_scripts']);
        remove_action('admin_enqueue_scripts', [$home, 'enqueue_home_screen_scripts']);
    }
}, 20);


// 3) Fallback: se mesmo assim pedirem os itens, garante estrutura segura
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

// 4) Stub de rede: qualquer request para elementor.* recebe JSON local válido
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

// 5) Define hosts permitidos para o stub funcionar antes do bloqueio global
if (!defined('WP_ACCESSIBLE_HOSTS')) {
    $hosts_permitidos = [
        'api.wordpress.org',
        'downloads.wordpress.org',
        '*.google.com',
        '*.googleapis.com',
        '*.gstatic.com',
        'www.googletagmanager.com',
        'sitekit.withgoogle.com',
        'page-speed-insights.appspot.com',
        'elementor.com',
        'my.elementor.com',
        'pro.elementor.com',
        'elementor.cloud',
        'assets.elementor.com',
        'go.elementor.com',
    ];
    define('WP_ACCESSIBLE_HOSTS', implode(',', array_unique($hosts_permitidos)));
}

// 6) Limpa transients e opções antigos do Elementor
add_action('admin_init', function () {
    $keys = [
        'elementor_remote_info_api_data',
        'e_home_screen_items',
        'elementor_home_screen_items',
        'elementor_remote_banners',
    ];
    foreach ($keys as $k) {
        delete_transient($k);
        delete_site_transient($k);
        delete_option($k);
    }

    // Remove aviso do Jetpack (se existir)
    if (class_exists('\Automattic\Jetpack\Jetpack')) {
        remove_action('admin_notices', ['Automattic\Jetpack\Jetpack', 'admin_notice']);
    }
}, 20);

// 7) BLOQUEIO DE REQUISIÇÕES EXTERNAS INDESEJADAS E MALICIOSAS
add_filter('pre_http_request', function ($pre, $args, $url) {
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

        // Scanners
        'wp-plugin.sucuri.net',
        'sitecheck.sucuri.net',

        // Builders/temas
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

// 8) OTIMIZAÇÕES PARA USO DO WOOCOMMERCE COMO CATÁLOGO
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
