<?php
/**
 * Plugin Name: Bloqueador de Requisições Externas (MU) — NW2
 * Plugin URI:  https://www.nw2web.com.br
 * Description: Fail-fast inteligente para requisições externas. Libera Google Site Kit, Cloudflare e QUALQUER provedor de e-mail (heurística SMTP/mail/mx + host do Post SMTP). Stub local para Elementor Home. Otimizações WooCommerce (catálogo). Blacklist de domínios nulled. Timeouts curtos e rejeição rápida em admin-ajax. Higiene de autoload.
 * Author:      Fausto — nw2web.com.br
 * Version:     1.8.0
 *
 * Instale como MU-plugin: wp-content/mu-plugins/bloqueador-requisicoes.php
 */

if (!defined('ABSPATH')) exit;

/* ============================================================================
 * Helpers
 * ========================================================================== */
if (!function_exists('nw2_is_smtp_host')) {
	function nw2_is_smtp_host(string $host): bool {
		$h = strtolower($host);
		return strpos($h, 'smtp') !== false;
	}
}
if (!function_exists('nw2_is_mail_host')) {
	function nw2_is_mail_host(?string $host): bool {
		if (!$host) return false;
		$h = strtolower($host);
		return (
			nw2_is_smtp_host($h) ||
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
		return trim((string)$host);
	}
}
if (!function_exists('nw2_allowed_hosts_raw')) {
	function nw2_allowed_hosts_raw(): array {
		$raw = defined('WP_ACCESSIBLE_HOSTS') ? WP_ACCESSIBLE_HOSTS : '';
		return array_values(array_filter(array_map('trim', explode(',', $raw))));
	}
}
if (!function_exists('nw2_host_matches_allowed')) {
	function nw2_host_matches_allowed(string $host, array $allowed): bool {
		$host = strtolower($host);
		foreach ($allowed as $pattern) {
			$pattern = strtolower($pattern);
			if ($pattern === '') continue;
			if (strpos($pattern, '*') !== false) {
				$needle = ltrim(str_replace('*', '', $pattern), '.');
				if ($needle === '') continue;
				if ($host === $needle) return true;
				if (substr($host, -strlen('.'.$needle)) === '.'.$needle) return true;
			} else {
				if ($host === $pattern) return true;
				if (substr($host, - (strlen($pattern) + 1)) === '.' . $pattern) return true;
			}
		}
		return false;
	}
}

/* ============================================================================
 * 0) Aviso leve se não estiver em mu-plugins
 * ========================================================================== */
add_action('admin_init', function () {
	if (strpos(__DIR__, 'mu-plugins') === false && current_user_can('manage_options')) {
		add_action('admin_notices', function () {
			echo '<div class="notice notice-warning"><p><strong>Bloqueador de Requisições Externas (NW2):</strong> mova para <code>wp-content/mu-plugins/</code> para impedir desativação acidental.</p></div>';
		});
	}
});

/* ============================================================================
 * 1) Bloqueio global + lista base de permitidos
 * ========================================================================== */
if (!defined('WP_HTTP_BLOCK_EXTERNAL')) {
	define('WP_HTTP_BLOCK_EXTERNAL', true);
}
if (!defined('WP_ACCESSIBLE_HOSTS')) {
	$hosts_permitidos = [
		// WordPress core
		'api.wordpress.org','downloads.wordpress.org',

		// Google / Site Kit
		'*.google.com','*.googleapis.com','*.gstatic.com',
		'www.googletagmanager.com','sitekit.withgoogle.com','page-speed-insights.appspot.com',

		// Elementor (para stub local interceptar)
		'elementor.com','my.elementor.com','pro.elementor.com','elementor.cloud','assets.elementor.com','go.elementor.com',

		// Cloudflare (plugin oficial / OAuth / API / IP lists)
		'api.cloudflare.com','dash.cloudflare.com','www.cloudflare.com',
	];
	define('WP_ACCESSIBLE_HOSTS', implode(',', array_unique($hosts_permitidos)));
}

/* Sempre permitir Cloudflare e QUALQUER host de e-mail (smtp/mail/mx + Post SMTP cfg) */
add_filter('http_request_host_is_external', function ($is_external, $host) {
	$host = strtolower((string)$host);
	if (!$host) return $is_external;

	if (preg_match('/(^|\.)cloudflare\.com$/i', $host)) return true;
	if (nw2_is_mail_host($host)) return true;

	$cfg = nw2_get_post_smtp_host();
	if ($cfg && $host === strtolower($cfg)) return true;

	return $is_external;
}, 10, 2);

/* Timeout sockets global (útil para PHPMailer) */
@ini_set('default_socket_timeout', '20');

/* ============================================================================
 * 2) Elementor Home — desligar UI + stub local + esqueleto seguro
 * ========================================================================== */
add_filter('elementor/admin/show_home_screen', '__return_false', 0);

add_action('elementor/init', function () {
	if (!class_exists('\Elementor\Plugin')) return;
	$plugin = \Elementor\Plugin::$instance;
	if (!isset($plugin->modules_manager)) return;

	$modules = [];
	if (method_exists($plugin->modules_manager, 'get_modules')) {
		try { $modules = $plugin->modules_manager->get_modules(); } catch (\Throwable $e) {}
	}
	if (isset($modules['home'])) {
		$home = $modules['home'];
		remove_action('admin_print_scripts',   [$home, 'enqueue_home_screen_scripts']);
		remove_action('admin_enqueue_scripts', [$home, 'enqueue_home_screen_scripts']);
	}
}, 20);

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

add_action('admin_init', function () {
	foreach ([
		'elementor_remote_info_api_data',
		'e_home_screen_items',
		'elementor_home_screen_items',
		'elementor_remote_banners',
	] as $k) {
		delete_transient($k);
		delete_site_transient($k);
		delete_option($k);
	}
}, 20);

/* ============================================================================
 * 3) Admin-AJAX fail-fast + timeouts curtos
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {
	if ($pre !== false) return $pre;

	// Só fail-fast no contexto admin-ajax
	if (!defined('DOING_AJAX') || !DOING_AJAX) return $pre;

	$host = parse_url($url, PHP_URL_HOST) ?: '';
	if (!$host) return $pre;

	// Permite e-mail/SMTP sempre (teste Post SMTP, diagnósticos, etc.)
	if (nw2_is_mail_host($host) || strtolower($host) === strtolower(nw2_get_post_smtp_host())) {
		return $pre;
	}

	// Checa whitelist via WP_ACCESSIBLE_HOSTS (com curingas)
	$allowed = nw2_allowed_hosts_raw();
	if (!nw2_host_matches_allowed($host, $allowed)) {
		if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
			error_log("[nw2-fastfail] ajax blocked host: {$host} — {$url}");
		}
		return new WP_Error('nw2_fast_fail', 'Remote host not allowed in AJAX context.');
	}
	return $pre;
}, 0, 3);

add_filter('http_request_args', function ($r, $url) {
	$is_ajax = defined('DOING_AJAX') && DOING_AJAX;
	$r['connect_timeout'] = max(1, (int)($is_ajax ? 2 : ($r['connect_timeout'] ?? 5)));
	$r['timeout']         = max(1, (int)($is_ajax ? 4 : ($r['timeout'] ?? 10)));
	$r['redirection']     = (int)($is_ajax ? 2 : ($r['redirection'] ?? 5));
	if (!isset($r['sslverify'])) $r['sslverify'] = true;
	return $r;
}, 10, 2);

add_action('http_api_curl', function ($handle, $r, $url) {
	$is_ajax = defined('DOING_AJAX') && DOING_AJAX;
	@curl_setopt($handle, CURLOPT_CONNECTTIMEOUT, (int)($is_ajax ? 2 : 5));
	@curl_setopt($handle, CURLOPT_TIMEOUT,         (int)($is_ajax ? 4 : 15));
	@curl_setopt($handle, CURLOPT_NOSIGNAL, 1);
	@curl_setopt($handle, CURLOPT_TCP_FASTOPEN, 0);
}, 10, 3);

/* Rate-limit básico para bursts de update via admin-ajax */
add_action('wp_ajax_update-plugin', function () {
	if (!current_user_can('update_plugins')) return;
	$last = get_transient('nw2_last_update_attempt');
	$now  = time();
	if ($last && ($now - $last) < 10) {
		wp_send_json_error(['message' => 'Too many update requests, try again shortly.'], 429);
	}
	set_transient('nw2_last_update_attempt', $now, 30);
}, 1);

/* ============================================================================
 * 4) Blacklist — domínios nulled/maliciosos (sem afetar SMTP/mail)
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {
	if ($pre !== false) return $pre;

	$host = parse_url($url, PHP_URL_HOST) ?: '';
	if (!$host) return $pre;

	// Nunca bloquear e-mail/SMTP
	if (nw2_is_mail_host($host) || strtolower($host) === strtolower(nw2_get_post_smtp_host())) {
		return $pre;
	}

	$bloqueios = [
		'wpnull24.com','wpnull24.net','wplocker.com','gpldl.com','yukapo.com','1nulled.com','codelist.cc','crackthemes.com',
		'gplastra.com','jojo-themes.net','nullphp.net','null.market','nulled.one','nullphpscript.com','nulledtemplates.com',
		'nulledscripts.net','nulled-scripts.xyz','nulledscripts.online','nullfresh.com','nulljungle.com','nullscript.top',
		'nulleb.com','nulled.cx','nulleds.io','nullscript.xyz','nullphpscript.xyz','nullradar.com','phpnulled.cc',
		'proweblab.xyz','socialgrowth.club','upnull.com','weadown.com','weaplay.com','woocrack.com','wpnull.org',
		'festingervault.com','wordpress-premium.net','srmehranclub.com','pluginsforwp.com','gplvault.com','worldpressit.com',
		'themecanal.com','gpl.coffee','gplchimp.com','plugintheme.net','gplplus.com','gplhub.net','gplplugins.club','babia.to',
		'wp-plugin.sucuri.net','sitecheck.sucuri.net',
		'support.wpbakery.com','sliderrevolution.com','revslider','slider-revolution','revslider.php',
		'salient','betheme','bridge.qodeinteractive.com','update.yithemes.com','yithemes.com',
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
 * 5) WooCommerce — modo catálogo
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
 * 6) Higiene de autoload (Elementor) — não carregar no boot
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
		$wpdb->prepare("UPDATE {$wpdb->options} SET autoload='no' WHERE option_name IN ($placeholders)", ...$opts)
	);
}, 30);
