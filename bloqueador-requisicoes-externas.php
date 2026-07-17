<?php
/**
 * Plugin Name: Bloqueador de Requisições Externas (MU) — NW2
 * Plugin URI:  https://www.nw2web.com.br
 * Description: Fail-fast inteligente para requisições externas. Google Site Kit 100% compatível. Elementor stub total. Cloudflare real. WooCommerce silencioso. Blacklist agressiva + WP-Cron bypass. Sem WP_HTTP_BLOCK_EXTERNAL.
 * Author:      Fausto — nw2web.com.br
 * Version:     2.8.0
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
			// Site Kit authentication proxy + docs
			stripos($url, 'withgoogle.com') !== false ||
			// Google APIs: oauth2.googleapis.com, www.googleapis.com, fonts.googleapis.com, etc
			stripos($url, 'googleapis.com') !== false ||
			// OAuth login
			stripos($url, 'accounts.google.com') !== false ||
			// Google user content / uploads
			stripos($url, 'googleusercontent.com') !== false ||
			// Google Tag Manager
			stripos($url, 'googletagmanager.com') !== false ||
			// Google Analytics measurement protocol (GA4)
			stripos($url, 'google-analytics.com') !== false ||
			// Google Ads / AdSense
			stripos($url, 'doubleclick.net') !== false ||
			stripos($url, 'googleadservices.com') !== false ||
			stripos($url, 'googlesyndication.com') !== false ||
			// Google static CDN (fonts.gstatic.com, ssl.gstatic.com, etc)
			stripos($url, 'gstatic.com') !== false ||
			// Google App Engine (Site Kit staging proxy: site-kit-dev.appspot.com)
			stripos($url, 'appspot.com') !== false ||
			// Google core (search.google.com, policies.google.com, etc)
			stripos($url, '.google.com') !== false ||
			// Cloudflare
			stripos($url, 'cloudflare.com') !== false ||
			// WordPress.org updates / API
			stripos($url, 'wordpress.org') !== false ||
			stripos($url, 'api.wordpress.org') !== false
		);
	}
}

/** Verifica se a requisicao eh do proprio site (localhost / mesmo dominio) */
if (!function_exists('nw2_is_local_request')) {
	function nw2_is_local_request(string $url): bool {
		$host = parse_url($url, PHP_URL_HOST);
		if (!$host) return true; // relative URL
		$home = parse_url(home_url(), PHP_URL_HOST);
		return ($host === $home);
	}
}

/** Verifica se esta rodando em WP-Cron */
if (!function_exists('nw2_is_cron')) {
	function nw2_is_cron(): bool {
		return defined('DOING_CRON') && DOING_CRON;
	}
}

/* =============================================================================
 * 0) AVISO LEVE SE NAO ESTIVER EM MU-PLUGINS
 * ========================================================================== */
add_action('admin_init', function () {
	if (strpos(__DIR__, 'mu-plugins') === false && current_user_can('manage_options')) {
		add_action('admin_notices', function () {
			echo '<div class="notice notice-warning"><p><strong>NW2:</strong> mova para <code>wp-content/mu-plugins/</code>.</p></div>';
		});
	}
});

/* =============================================================================
 * 1) BYPASS TOTAL — GOOGLE + CLOUDFLARE + LOCAL (ANTES DE TUDO)
 *    Este eh o segredo: se a URL eh Google/CF/WP/localhost, NUNCA bloqueia.
 *    O callback OAuth do Site Kit faz POST para sitekit.withgoogle.com
 *    e tambem para oauth2.googleapis.com — ambos passam aqui.
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {
	if (nw2_is_google_or_cf($url)) return false;   // Google, Cloudflare, WordPress.org
	if (nw2_is_local_request($url)) return false;   // proprio site (loopback)
	return $pre;
}, -1000, 3);

/* =============================================================================
 * 2) SMTP + GOOGLE HOSTS DECLARADOS COMO EXTERNOS
 *    Se algum plugin ou config definir WP_HTTP_BLOCK_EXTERNAL=true,
 *    WordPress bloqueia TUDO exceto hosts explicitamente declarados aqui.
 *    O callback OAuth do Site Kit precisa disto para o token exchange.
 * ========================================================================== */
add_filter('http_request_host_is_external', function ($external, $host) {
	$host = strtolower((string)$host);
	if (nw2_is_smtp_host($host)) return true;
	$cfg = nw2_get_post_smtp_host();
	if ($cfg && $host === $cfg) return true;

	// Garante que hosts Google sejam reconhecidos como externos
	// Essencial para o fluxo OAuth do Site Kit (token exchange)
	static $google_hosts = [
		'sitekit.withgoogle.com', 'oauth2.googleapis.com',
		'www.googleapis.com', 'accounts.google.com',
		'fonts.googleapis.com', 'www.google.com',
		'googleapis.com', 'withgoogle.com',
	];
	foreach ($google_hosts as $gh) {
		if (stripos($host, $gh) !== false) return true;
	}

	return $external;
}, 10, 2);

/* =============================================================================
 * 3) ELEMENTOR — STUB TOTAL (NUNCA CONECTA)
 *    Intercepta elementor.com, .cloud e .io — retorna fake 200 OK.
 *    Prioridade -500: roda DEPOIS do bypass Google, ANTES do fail-fast.
 * ========================================================================== */
add_filter('elementor/admin/show_home_screen', '__return_false', 0);

add_filter('pre_http_request', function ($pre, $args, $url) {
	$host = parse_url($url, PHP_URL_HOST) ?: '';

	// Bloqueia elementor.com, elementor.cloud, elementor.io e subdominios
	if (!preg_match('~(^|\.)elementor\.(com|cloud|io)$~i', $host)) return false;

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
}, -500, 3);

/* =============================================================================
 * 4) WP-CRON BYPASS — CRITICO PARA GOOGLE SITE KIT
 *    Site Kit agenda wp_schedule_single_event para refresh de token OAuth.
 *    Se o cron nao consegue fazer requisicoes, o token expira.
 *    No cron, permite tudo exceto Elementor + sites null.
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {
	if (!nw2_is_cron()) return false;

	$host = parse_url($url, PHP_URL_HOST) ?: '';
	if (!$host) return false;

	// No cron, bloqueia so Elementor + null
	$bloqueios_cron = [
		'elementor.com', 'elementor.cloud', 'elementor.io',
		'wpnull', 'nulled', 'gpl', 'crack', 'null.', 'festinger',
	];
	foreach ($bloqueios_cron as $kw) {
		if (stripos($url, $kw) !== false) {
			return new WP_Error('nw2_cron_blocked', 'Requisição bloqueada (cron).');
		}
	}

	return false; // permite todo o resto (Google OAuth, APIs, SMTP, etc)
}, -200, 3);

/* =============================================================================
 * 5) FAIL-FAST — APENAS AJAX PURO (NUNCA REST / GOOGLE / CF / CRON)
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {
	// So bloqueia requisicoes AJAX puras (nao-REST, nao-Google, nao-Cron)
	if (!defined('DOING_AJAX') || !DOING_AJAX) return false;
	if (defined('REST_REQUEST') && REST_REQUEST) return false;
	if (nw2_is_google_or_cf($url)) return false;
	if (nw2_is_cron()) return false;

	$host = parse_url($url, PHP_URL_HOST) ?: '';
	if (!$host) return false;

	if (nw2_is_smtp_host($host) || $host === nw2_get_post_smtp_host()) return false;

	return new WP_Error('nw2_fast_fail', 'Requisição externa bloqueada por política.');
}, 10, 3);

/* =============================================================================
 * 6) BLACKLIST — EXPANDIDA (AGRESSIVA)
 *    Bloqueia sites piratas/null, callbacks de licenca, trackers suspeitos.
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {

	// Nunca bloqueia Google / Cloudflare / WordPress / SMTP / localhost
	if (
		nw2_is_google_or_cf($url) ||
		nw2_is_local_request($url) ||
		nw2_is_smtp_host(parse_url($url, PHP_URL_HOST) ?: '')
	) {
		return false;
	}

	$bloqueios = [
		// === SITES DE PLUGINS/TEMAS NULLED ===
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
		// Adicionais
		'nulled.to','gpltimes.com','gplfile.com','nullfree.co','nulledfree.info',
		'wpgpl.net','wpthemeplugin.com','freeprosoftz.com','downld.org',
		'script-stack.com','nulledbb.com','scriptmags.com','nulledteam.com',
		'nulledfreescript.com','cracknull.com','gplnulled.co','nulledflix.com',
		'premiumgpl.com','wppluginsforyou.com','wpeden.com',

		// === SITES DE LICENCA / VERIFICACAO DE PURCHASE CODE ===
		'api.envato.com',          // Envato API (verifica purchase codes)
		'purchasekey.com',         // Verificacao de chave
		'license-check.',          // Generico: license-check.algumacoisa
		'check-license.',          // Generico: check-license.algumacoisa

		// === SUCURI / SCANNERS EXTERNOS ===
		'wp-plugin.sucuri.net','sitecheck.sucuri.net',

		// === TEMAS / PLUGINS PREMIUM (callbacks de update/licenca) ===
		'support.wpbakery.com','sliderrevolution.com','revslider','slider-revolution','revslider.php',
		'salient','betheme','bridge.qodeinteractive.com','update.yithemes.com','yithemes.com',
		// Temas adicionais
		'update.themeforest.net','api.themeforest.net',
		'update.avada.com','avada.theme-fusion.com',
		'update.divi.com','elegantthemes.com',
		'update.astra.com','bsf.io','brainstormforce.com',
		'update.oceanwp.org','oceanwp.org',
		'pixelyoursite.com',       // Pixel Your Site pro
		'pixtheme.com',            // Temas premium
		'update.the7.io','the7.io',

		// === TRACKERS / TELEMETRIA SUSPEITA ===
		'usage.tracking.',         // Telemetria generica
		'statistic.wp-',           // Estatisticas suspeitas
		'hotjar.com',              // Hotjar tracking
		'mouseflow.com',           // Mouseflow tracking
		'fullstory.com',           // FullStory tracking
		'luckyorange.com',         // Lucky Orange tracking
		'clarity.ms',              // Microsoft Clarity
	];

	foreach ($bloqueios as $dominio) {
		if (stripos($url, $dominio) !== false) {
			return new WP_Error('nw2_blacklist', 'Conexão externa bloqueada por política de segurança.');
		}
	}

	return false;
}, 20, 3);

/* =============================================================================
 * 7) WOOCOMMERCE — SILENCIO (tracking/marketplace) + PRESERVA CART
 *    Desativa telemetria, marketplace e sugestoes.
 *    NAO remove scripts de carrinho/checkout (cada site decide).
 * ========================================================================== */
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

// Descomente abaixo se quiser MODO CATALOGO (remove carrinho/checkout):
// add_action('wp_enqueue_scripts', function () {
// 	wp_dequeue_script('wc-cart');
// 	wp_dequeue_script('wc-checkout');
// 	wp_dequeue_script('wc-add-to-cart');
// }, 100);

/* =============================================================================
 * 8) TIMEOUTS CONTROLADOS
 * ========================================================================== */
add_filter('http_request_args', function ($r) {
	$r['timeout'] = 15;
	$r['connect_timeout'] = 7;
	$r['redirection'] = 3;
	$r['sslverify'] = true;
	return $r;
});

/* =============================================================================
 * 9) DEBUG MODE (OPCIONAL) — Loga requisicoes bloqueadas
 *    Defina: define('NW2_DEBUG_LOG', true); no wp-config.php
 *    Logs vao para: wp-content/nw2-blocked-requests.log
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
				error_log($log, 3, WP_CONTENT_DIR . '/nw2-blocked-requests.log');
			}
		}
	}, 10, 5);
}
