<?php
/**
 * Plugin Name: Bloqueador de Requisições Externas (MU) — NW2
 * Plugin URI:  https://www.nw2web.com.br
 * Description: Fail-fast inteligente para requisições externas. Google Site Kit + Cloudflare reais. Elementor 100% stub. WooCommerce silencioso. Blacklist agressiva (original). Sem WP_HTTP_BLOCK_EXTERNAL.
 * Author:      Fausto — nw2web.com.br
 * Version:     2.7.0
 *
 * Instale como MU-plugin: wp-content/mu-plugins/bloqueador-requisicoes.php
 */

if (!defined('ABSPATH')) exit;

/* =============================================================================
 * HELPERS
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

if (!function_exists('nw2_is_google_or_cf')) {
	function nw2_is_google_or_cf(string $url): bool {
		return (
			stripos($url, 'withgoogle.com') !== false ||
			stripos($url, 'googleapis.com') !== false ||
			stripos($url, 'accounts.google.com') !== false ||
			stripos($url, 'googleusercontent.com') !== false ||
			stripos($url, 'googletagmanager.com') !== false ||
			stripos($url, 'cloudflare.com') !== false ||
			stripos($url, 'wordpress.org') !== false
		);
	}
}

/* =============================================================================
 * 0) AVISO LEVE SE NÃO ESTIVER EM MU-PLUGINS
 * ========================================================================== */
add_action('admin_init', function () {
	if (strpos(__DIR__, 'mu-plugins') === false && current_user_can('manage_options')) {
		add_action('admin_notices', function () {
			echo '<div class="notice notice-warning"><p><strong>NW2:</strong> mova para <code>wp-content/mu-plugins/</code>.</p></div>';
		});
	}
});

/* =============================================================================
 * 1) BYPASS TOTAL — GOOGLE + CLOUDFLARE (ANTES DE TUDO)
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {
	if (nw2_is_google_or_cf($url)) return false;
	return $pre;
}, -1000, 3);

/* =============================================================================
 * 2) SMTP SEMPRE LIBERADO
 * ========================================================================== */
add_filter('http_request_host_is_external', function ($external, $host) {
	$host = strtolower((string)$host);
	if (nw2_is_smtp_host($host)) return true;
	$cfg = nw2_get_post_smtp_host();
	if ($cfg && $host === $cfg) return true;
	return $external;
}, 10, 2);

/* =============================================================================
 * 3) ELEMENTOR — STUB TOTAL (NUNCA CONECTA)
 * ========================================================================== */
add_filter('elementor/admin/show_home_screen', '__return_false', 0);

add_filter('pre_http_request', function ($pre, $args, $url) {
	$host = parse_url($url, PHP_URL_HOST) ?: '';
	if (!preg_match('~(^|\.)elementor\.(com|cloud)$~i', $host)) return false;

	return [
		'headers'  => ['content-type' => 'application/json; charset=UTF-8'],
		'body'     => wp_json_encode([
			'success' => true,
			'status'  => 'ok',
			'data'    => [
				'license' => 'active',
				'expires' => '2099-12-31',
				'items'   => [],
			],
		]),
		'response' => ['code' => 200, 'message' => 'OK'],
		'cookies'  => [],
		'filename' => null,
	];
}, 0, 3);

/* =============================================================================
 * 4) FAIL-FAST — APENAS AJAX PURO (NUNCA REST / GOOGLE / CF)
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {
	if (!defined('DOING_AJAX') || !DOING_AJAX) return false;
	if (defined('REST_REQUEST') && REST_REQUEST) return false;
	if (nw2_is_google_or_cf($url)) return false;

	$host = parse_url($url, PHP_URL_HOST) ?: '';
	if (!$host) return false;

	if (nw2_is_smtp_host($host) || $host === nw2_get_post_smtp_host()) return false;

	return new WP_Error('nw2_fast_fail', 'Requisição externa bloqueada por política.');
}, 10, 3);

/* =============================================================================
 * 5) BLACKLIST — ORIGINAL COMPLETA (AGRESSIVA)
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {

	if (
		nw2_is_google_or_cf($url) ||
		nw2_is_smtp_host(parse_url($url, PHP_URL_HOST))
	) {
		return false;
	}

	$bloqueios = [
		'wpnull24.com','wpnull24.net','wplocker.com','gpldl.com','yukapo.com','1nulled.com',
		'codelist.cc','crackthemes.com','gplastra.com','jojo-themes.net','nullphp.net',
		'null.market','nulled.one','nullphpscript.com','nulledtemplates.com',
		'nulledscripts.net','nulled-scripts.xyz','nulledscripts.online','nullfresh.com',
		'nulljungle.com','nullscript.top','nulleb.com','nulled.cx','nulleds.io',
		'nullscript.xyz','nullphpscript.xyz','nullradar.com','phpnulled.cc',
		'proweblab.xyz','socialgrowth.club','upnull.com','weadown.com','weaplay.com',
		'woocrack.com','wpnull.org','festingervault.com','wordpress-premium.net',
		'srmehranclub.com','pluginsforwp.com','gplvault.com','worldpressit.com',
		'themecanal.com','gpl.coffee','gplchimp.com','plugintheme.net','gplplus.com',
		'gplhub.net','gplplugins.club','babia.to',
		'wp-plugin.sucuri.net','sitecheck.sucuri.net',
		'support.wpbakery.com','sliderrevolution.com','revslider','slider-revolution','revslider.php',
		'salient','betheme','bridge.qodeinteractive.com','update.yithemes.com','yithemes.com',
	];

	foreach ($bloqueios as $dominio) {
		if (stripos($url, $dominio) !== false) {
			return new WP_Error('nw2_blacklist', 'Conexão externa bloqueada por política de segurança.');
		}
	}

	return false;
}, 20, 3);

/* =============================================================================
 * 6) WOOCOMMERCE — SILÊNCIO TOTAL
 * ========================================================================== */
add_action('init', function () {
	add_filter('woocommerce_admin_disabled', '__return_true');
	add_filter('woocommerce_allow_marketplace_suggestions', '__return_false');
	add_filter('woocommerce_show_marketplace_suggestions', '__return_false');
	add_filter('woocommerce_tracker_send_event', '__return_false');
	add_filter('woocommerce_tracker_enabled', '__return_false');
	add_filter('woocommerce_helper_suppress_admin_notices', '__return_true');
}, 10);

add_action('wp_enqueue_scripts', function () {
	wp_dequeue_script('wc-cart');
	wp_dequeue_script('wc-checkout');
	wp_dequeue_script('wc-add-to-cart');
}, 100);

/* =============================================================================
 * 7) TIMEOUTS CONTROLADOS
 * ========================================================================== */
add_filter('http_request_args', function ($r) {
	$r['timeout'] = 15;
	$r['connect_timeout'] = 7;
	$r['redirection'] = 3;
	$r['sslverify'] = true;
	return $r;
});
