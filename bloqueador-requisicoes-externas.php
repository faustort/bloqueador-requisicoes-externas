<?php
/**
 * Plugin Name: Bloqueador de Requisições Externas (MU) — NW2
 * Description: Fail-fast inteligente com stub completo para Elementor. ZERO ping externo para elementor.com. Updates do WP liberados.
 * Author: Fausto — nw2web.com.br
 * Version: 2.1.0
 */

if (!defined('ABSPATH')) exit;

/* =============================================================================
 * Helpers
 * ========================================================================== */
function nw2_is_smtp_host(?string $host): bool {
	if (!$host) return false;
	$h = strtolower($host);
	return (
		str_contains($h, 'smtp') ||
		str_starts_with($h, 'mail.') ||
		str_contains($h, '.mail.') ||
		str_starts_with($h, 'mx.') ||
		str_contains($h, 'email-smtp.')
	);
}

function nw2_get_post_smtp_host(): string {
	foreach (['post_smtp', 'postman_options'] as $opt) {
		$data = get_option($opt);
		if (is_array($data) && !empty($data['hostname'])) {
			return preg_replace('~^(ssl|tls|tcp)://~i', '', strtolower($data['hostname']));
		}
	}
	return '';
}

/* =============================================================================
 * 1. Política global
 * ========================================================================== */
define('WP_HTTP_BLOCK_EXTERNAL', true);
define('WP_ACCESSIBLE_HOSTS', 'api.wordpress.org,downloads.wordpress.org');

/* =============================================================================
 * 2. SMTP sempre liberado
 * ========================================================================== */
add_filter('http_request_host_is_external', function ($external, $host) {
	if (nw2_is_smtp_host($host)) return true;
	if ($host === nw2_get_post_smtp_host()) return true;
	return $external;
}, 10, 2);

/* =============================================================================
 * 3. STUB TOTAL DO ELEMENTOR (licença, home, API, tudo)
 *    NÃO pinga elementor.com
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {

	$host = parse_url($url, PHP_URL_HOST);
	if (!$host) return false;

	if (!preg_match('~(^|\.)elementor\.com$~i', $host)) {
		return false;
	}

	$path = parse_url($url, PHP_URL_PATH) ?: '';

	$payload = [
		'success' => true,
		'status'  => 'ok',
		'data'    => [],
	];

	// Licença Pro
	if (str_contains($path, 'license')) {
		$payload['data'] = [
			'license' => 'valid',
			'status'  => 'active',
			'expires' => '2099-12-31',
			'renew'   => false,
		];
	}

	// Home / promo / banners / kits
	if (
		str_contains($path, 'home') ||
		str_contains($path, 'kits') ||
		str_contains($path, 'promotions') ||
		str_contains($path, 'banners')
	) {
		$payload['data'] = [
			'items' => [],
			'banners' => [],
			'kits' => [],
		];
	}

	return [
		'headers'  => ['content-type' => 'application/json; charset=UTF-8'],
		'body'     => wp_json_encode($payload),
		'response' => ['code' => 200, 'message' => 'OK'],
		'cookies'  => [],
		'filename' => null,
	];
}, 0, 3);

/* =============================================================================
 * 4. FAIL-FAST admin-ajax (sem quebrar updater)
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {

	// Nunca interferir em updates
	if (
		str_contains($url, 'downloads.wordpress.org') ||
		str_contains($url, 'api.wordpress.org')
	) {
		return false;
	}

	if (!defined('DOING_AJAX') || !DOING_AJAX) return false;

	$host = parse_url($url, PHP_URL_HOST);
	if (!$host) return false;

	// SMTP liberado
	if (nw2_is_smtp_host($host) || $host === nw2_get_post_smtp_host()) {
		return false;
	}

	return new WP_Error(
		'nw2_fast_fail',
		'Conexão externa bloqueada por política de segurança.'
	);

}, 1, 3);

/* =============================================================================
 * 5. Timeouts seguros
 * ========================================================================== */
add_filter('http_request_args', function ($r) {
	$r['timeout'] = 8;
	$r['connect_timeout'] = 4;
	$r['redirection'] = 2;
	$r['sslverify'] = true;
	return $r;
});

/* =============================================================================
 * 6. Blacklist nulled explícita (extra)
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {

	if (
		str_contains($url, 'wordpress.org') ||
		str_contains($url, 'elementor.com') ||
		nw2_is_smtp_host(parse_url($url, PHP_URL_HOST))
	) {
		return false;
	}

	$blocked = ['nulled', 'wpnull', 'gplvault', 'pluginsforwp', 'woocrack'];

	foreach ($blocked as $term) {
		if (stripos($url, $term) !== false) {
			return new WP_Error(
				'nw2_nulled',
				'Domínio bloqueado por política anti-nulled.'
			);
		}
	}

	return false;
}, 2, 3);
