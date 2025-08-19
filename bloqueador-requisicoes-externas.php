<?php
/**
 * Plugin Name: Bloqueador de Requisições Externas
 * Plugin URI: https://www.nw2web.com.br
 * Description: Bloqueia conexões externas desnecessárias e maliciosas, e otimiza o WooCommerce para uso como catálogo.
 * Author: Fausto - nw2web.com.br
 * Version: 1.6
 */

// BLOQUEIO GLOBAL DE CONEXÕES EXTERNAS
if (!defined('WP_HTTP_BLOCK_EXTERNAL')) {
    define('WP_HTTP_BLOCK_EXTERNAL', true);
}

// PERMITIR WORDPRESS.ORG + GOOGLE (GOOGLE SITE KIT)
if (!defined('WP_ACCESSIBLE_HOSTS')) {
    $hosts_permitidos = [
        // WordPress core/updates
        'api.wordpress.org',
        'downloads.wordpress.org',

        // Google Site Kit (usar curingas cobre todos os módulos: Analytics, Search Console, AdSense, Tag Manager, PSI etc.)
        '*.google.com',
        '*.googleapis.com',
        '*.gstatic.com',
        'www.googletagmanager.com',

        // Extras já usados
        'sitekit.withgoogle.com',
        'page-speed-insights.appspot.com',
    ];

    // Normaliza e define
    $hosts_permitidos = implode(',', array_unique($hosts_permitidos));
    define('WP_ACCESSIBLE_HOSTS', $hosts_permitidos);
}

// BLOQUEIO EXTRA — REQUISIÇÕES MALICIOSAS E DOMÍNIOS NÃO DESEJADOS
add_filter('pre_http_request', function ($pre, $args, $url) {
    $bloqueios = [
        'wpnull24.com','wpnull24.net','wplocker.com','gpldl.com','yukapo.com','1nulled.com','codelist.cc','crackthemes.com',
        'gplastra.com','jojo-themes.net','nullphp.net','null.market','nulled.one','nullphpscript.com','nulledtemplates.com',
        'nulledscripts.net','nulled-scripts.xyz','nulledscripts.online','nullfresh.com','nulljungle.com','nullscript.top',
        'nulleb.com','nulled.cx','nulleds.io','nullscript.xyz','nullphpscript.xyz','nullradar.com','phpnulled.cc',
        'proweblab.xyz','socialgrowth.club','upnull.com','weadown.com','weaplay.com','woocrack.com','wpnull.org',
        'festingervault.com','wordpress-premium.net','srmehranclub.com','pluginsforwp.com','gplvault.com','worldpressit.com',
        'themecanal.com','gpl.coffee','gplchimp.com','plugintheme.net','gplplus.com','gplhub.net','gplplugins.club','babia.to',

        // scanners/serviços indesejados
        'wp-plugin.sucuri.net','sitecheck.sucuri.net',

        // builders/temas (bloqueio de chamadas externas)
        'support.wpbakery.com',
        'elementor.com','elementor.cloud','my.elementor.com','pro.elementor.com',
        'sliderrevolution.com','revslider','slider-revolution','revslider.php',
        'salient','betheme','bridge.qodeinteractive.com',
        // yithemes (updates externos)
        'update.yithemes.com','yithemes.com',
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

// OTIMIZAÇÕES PARA USO DO WOOCOMMERCE COMO CATÁLOGO
add_action('init', function () {
    add_filter('woocommerce_admin_disabled', '__return_true');
    add_filter('woocommerce_allow_marketplace_suggestions', '__return_false');
    add_filter('woocommerce_show_marketplace_suggestions', '__return_false');

    remove_action('wp_enqueue_scripts', 'wc_enqueue_cart_fragments');
    wp_dequeue_script('wc-cart');
    wp_dequeue_script('wc-checkout');
    wp_dequeue_script('wc-add-to-cart');

    remove_action('admin_notices', ['Automattic\Jetpack\Jetpack', 'admin_notice']);
}, 100);

// BLOQUEAR TRACKING DO WOOCOMMERCE
add_filter('woocommerce_tracker_send_event', '__return_false');
add_filter('woocommerce_helper_suppress_admin_notices', '__return_true');
