<?php
/**
 * Plugin Name: Bloqueador de Requisições Externas (MU) — NW2
 * Plugin URI:  https://www.nw2web.com.br
 * Description: Default Deny ligado por padrão + fail-fast inteligente. Google Site Kit 100% compatível. Elementor stub total (consistente em todos os contextos). WooCommerce pronto (checkout/pagamento/frete tratados como zona crítica, não dependem de lista de gateways). Cloudflare real. Anti-curl nativo. Sem WP_HTTP_BLOCK_EXTERNAL.
 * Author:      Fausto — nw2web.com.br
 * Version:     2.11.0
 *
 * Instale como MU-plugin: wp-content/mu-plugins/bloqueador-requisicoes.php
 *
 * FONTE SINCRONIZADA MANUALMENTE com a string embutida em
 * src/application/capabilities/DeployBlockerMuPluginCapability.ts do
 * projeto nw2-server-manager — qualquer mudança aqui precisa ser
 * replicada lá (e vice-versa).
 *
 * Changelog 2.11.0:
 * - CORREÇÃO CRÍTICA: a cadeia de filtros pre_http_request não preservava a
 *   decisão de um filtro de prioridade menor quando um filtro de prioridade
 *   maior não tinha opinião própria (cada callback retornava `false`/WP_Error
 *   incondicionalmente em vez de propagar $pre). Na prática isso fazia o
 *   stub do Elementor (fake 200 OK) nunca chegar ao WordPress core — em
 *   contexto AJAX (o mais comum) o Elementor recebia erro real. Corrigido
 *   com guard clause `if (false !== $pre) return $pre;` no topo de cada
 *   callback subsequente.
 * - Default Deny (NW2_DEFAULT_DENY) agora vem LIGADO por padrão — antes era
 *   opt-in. Pode ser desligado por site com define('NW2_DEFAULT_DENY', false)
 *   no wp-config.php.
 * - Novo modo de simulação NW2_DEFAULT_DENY_DRY_RUN: quando true, loga o que
 *   teria sido bloqueado sem bloquear de verdade — usar para auditar um site
 *   antes de confiar no bloqueio real (essencial em sites com WooCommerce).
 * - WooCommerce tratado como zona crítica por CONTEXTO (checkout, wc-ajax,
 *   REST /wc/, cron de assinatura, tela wc-settings) em vez de depender de
 *   uma lista fixa de domínios de gateway de pagamento — impossível manter
 *   completa (dezenas de gateways BR/globais). A blacklist de domínios
 *   nulled continua valendo mesmo nesse contexto.
 * - Whitelist expandida: Sucuri, Wordfence, iThemes/Solid Security,
 *   MalCare/BlogVault (WAF/segurança), WooCommerce.com/Jetpack/WordPress.com
 *   (WooCommerce Payments), Stripe/PayPal, viacep.com.br/brasilapi.com.br/
 *   correios.com.br (CEP/frete BR). Sucuri removido da blacklist (estava
 *   bloqueando o próprio scanner que agora é liberado).
 * - nw2_is_local_request() endurecida: antes tratava qualquer URL sem host
 *   reconhecível (inclusive malformada) como "local" e liberava antes de
 *   qualquer checagem — agora só trata como local um path relativo de
 *   verdade; URL ambígua cai no fluxo normal de bloqueio (fail-closed).
 * - Novo: DISALLOW_FILE_EDIT ligado por padrão (desativa editor de
 *   arquivos do wp-admin — reduz superfície de persistência de backdoor).
 * - Novo: XML-RPC desativado por padrão (fecha brute-force amplificado e
 *   pingback usado para SSRF/DDoS a partir do próprio site).
 *
 * Changelog 2.10.0:
 * - Matching de domínio por host real (parse_url + comparação exata/sufixo)
 *   em vez de stripos() na URL inteira — evita falso-positivo/negativo por
 *   substring (ex.: "gpl.coffee" batendo em qualquer URL que contenha essa
 *   string em qualquer parte, não só no host).
 * - Whitelist/blacklist agora expostas via apply_filters('nw2_blocker_whitelist', ...)
 *   e apply_filters('nw2_blocker_blacklist', ...), permitindo ajuste por site
 *   sem editar este arquivo.
 * - Log de requisições bloqueadas agora protegido por .htaccess (Deny from all)
 *   criado automaticamente na primeira escrita.
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

/**
 * Compara o HOST real (via parse_url) contra um domínio de referência —
 * bate exato ou como subdomínio (ex.: "api.googleapis.com" bate em
 * "googleapis.com", mas "evilgoogleapis.com" NÃO bate). Usar sempre no
 * lugar de stripos($url, $dominio) cru, que casa substring em qualquer
 * parte da URL (inclusive query string), gerando falso-positivo/negativo.
 */
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
		/**
		 * Filtro nw2_blocker_whitelist: domínios sempre liberados. Adicione via
		 * functions.php do tema ou outro mu-plugin, sem editar este arquivo:
		 *   add_filter('nw2_blocker_whitelist', fn($hosts) => [...$hosts, 'meudominio.com']);
		 * Gateways de pagamento BR específicos (Mercado Pago, PagSeguro, Cielo etc.)
		 * não entram aqui de propósito — ficam cobertos pela exceção de contexto
		 * nw2_is_woocommerce_critical_context() abaixo, e podem ser adicionados por
		 * site via esse mesmo filtro se precisar de liberação fora desse contexto.
		 */
		return apply_filters('nw2_blocker_whitelist', [
			// Google
			'withgoogle.com', 'googleapis.com', 'accounts.google.com',
			'googleusercontent.com', 'googletagmanager.com', 'google-analytics.com',
			'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
			'gstatic.com', 'appspot.com', 'google.com',
			// Cloudflare
			'cloudflare.com',
			// WordPress.org (core/plugins/temas/traduções)
			'wordpress.org', 'api.wordpress.org',
			// WAF / segurança (acesso remoto de scanner/firewall)
			'sucuri.net', 'wordfence.com', 'ithemes.com', 'solidwp.com',
			'malcare.io', 'blogvault.net',
			// WooCommerce / Automattic (updates de extensões compradas +
			// WooCommerce Payments, que depende de conexão Jetpack)
			'woocommerce.com', 'jetpack.com', 'wordpress.com', 'wp.com',
			// Gateways de alta confiança (globais)
			'stripe.com', 'paypal.com',
			// CEP / endereço (Brasil) — usado por quase todo plugin de frete nacional
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

/** Verifica se a requisicao eh do proprio site (localhost / mesmo dominio) */
if (!function_exists('nw2_is_local_request')) {
	function nw2_is_local_request(string $url): bool {
		$host = parse_url($url, PHP_URL_HOST);
		if (!$host) {
			// Só trata como local se for path relativo de verdade (começa com "/"
			// único). Antes, qualquer URL sem host reconhecível (inclusive
			// malformada/ambígua de propósito) era liberada aqui mesmo, ANTES de
			// qualquer outra checagem — uma brecha fail-open. Chamadas legítimas
			// de wp_remote_* sempre usam URL absoluta, então isso não quebra nada.
			return (bool) preg_match('~^/(?!/)~', $url);
		}
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

/**
 * Detecta se a requisição está acontecendo dentro de um fluxo crítico do
 * WooCommerce (checkout, gateway de pagamento, frete/CEP, renovação de
 * assinatura). Em vez de manter uma lista fixa de domínios de gateway
 * (impossível manter completa — dezenas de gateways BR/globais, cada um
 * com domínio próprio), esses contextos relaxam a exigência de whitelist
 * no fail-fast (seção 5) e no Default Deny (seção 8) — a blacklist de
 * domínios nulled (seção 6) continua valendo sempre, mesmo aqui.
 */
if (!function_exists('nw2_is_woocommerce_critical_context')) {
	function nw2_is_woocommerce_critical_context(): bool {
		if (!class_exists('WooCommerce')) return false;

		// Endpoint dedicado do WooCommerce — usado pela maioria dos gateways no
		// checkout, atualização de pedido etc. (WC_AJAX define DOING_AJAX=true
		// mesmo não sendo admin-ajax.php)
		if (isset($_REQUEST['wc-ajax'])) return true;

		// Webhook legado de gateway (ex.: boleto, PagSeguro)
		if (isset($_GET['wc-api'])) return true;

		// REST API do WooCommerce (Store API / Blocks checkout, gateways
		// modernos, webhooks REST)
		if (defined('REST_REQUEST') && REST_REQUEST) {
			$uri = $_SERVER['REQUEST_URI'] ?? '';
			if (strpos($uri, '/wc/') !== false || strpos($uri, '/wc-') !== false) return true;
		}

		// WP-Cron: renovação de assinatura (WooCommerce Subscriptions), fatura
		// recorrente, disparo de webhook agendado — cobram cartão salvo em
		// segundo plano
		if (nw2_is_cron()) return true;

		// Páginas de checkout/pedido fora de contexto AJAX (fallback quando a
		// query principal já rodou)
		if (function_exists('is_checkout') && did_action('wp') &&
			(is_checkout() || is_wc_endpoint_url('order-pay') || is_wc_endpoint_url('order-received'))) {
			return true;
		}

		// Tela de configurações do WooCommerce (teste de conexão de
		// gateway/frete feito pelo admin)
		if (is_admin() && isset($_GET['page']) && $_GET['page'] === 'wc-settings') return true;

		return false;
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
 *    O callback OAuth do Site Kit faz POST para sitekit.withgoogle.com
 *    e tambem para oauth2.googleapis.com — ambos passam aqui.
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {
	if (nw2_is_google_or_cf($url)) return false;
	if (nw2_is_local_request($url)) return false;
	return $pre;
}, -1000, 3);

/* =============================================================================
 * 2) SMTP + GOOGLE HOSTS DECLARADOS COMO EXTERNOS
 *    Este filtro (http_request_host_is_external) só é consultado pelo
 *    WordPress se a constante nativa WP_HTTP_BLOCK_EXTERNAL estiver definida
 *    como true em algum lugar — e este plugin PROPOSITALMENTE não define
 *    essa constante (por isso todo o bloqueio é feito via pre_http_request
 *    acima/abaixo, não pelo mecanismo nativo). Ou seja: hoje este filtro só
 *    tem efeito se o stack de hospedagem definir WP_HTTP_BLOCK_EXTERNAL de
 *    forma independente (alguns hosts gerenciados fazem isso) — nesse caso,
 *    ele garante que SMTP/Google continuem passando mesmo com a flag nativa
 *    ligada. Mantido como defesa em profundidade / compatibilidade.
 * ========================================================================== */
add_filter('http_request_host_is_external', function ($external, $host) {
	$host = strtolower((string)$host);
	if (nw2_is_smtp_host($host)) return true;
	$cfg = nw2_get_post_smtp_host();
	if ($cfg && $host === $cfg) return true;

	// Garante que hosts Google/CF sejam reconhecidos como externos
	foreach (nw2_google_or_cf_hosts() as $gh) {
		if ($host === $gh || str_ends_with($host, '.' . $gh)) return true;
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
	if (false !== $pre) return $pre;

	$host = parse_url($url, PHP_URL_HOST) ?: '';
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
 * 4) WP-CRON — FAIL-FAST DE DOMINIOS NULLED
 *    Site Kit agenda wp_schedule_single_event para refresh de token OAuth —
 *    já liberado pelo bypass (-1000) antes de chegar aqui. Elementor não
 *    precisa mais de tratamento especial aqui: o stub (seção 3, corrigido)
 *    já cobre cron de forma consistente. Com o Default Deny (seção 8) agora
 *    ligado por padrão e cobrindo cron também, este filtro vira apenas
 *    fail-fast/defesa em profundidade para os casos óbvios — não é mais a
 *    única proteção do contexto cron.
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {
	if (false !== $pre) return $pre;
	if (!nw2_is_cron()) return false;

	$host = parse_url($url, PHP_URL_HOST) ?: '';
	if (!$host) return false;

	$bloqueios_cron = [
		'wpnull', 'nulled', 'gpl', 'crack', 'null.', 'festinger',
	];
	foreach ($bloqueios_cron as $kw) {
		if (stripos($url, $kw) !== false) {
			return new WP_Error('nw2_cron_blocked', 'Requisição bloqueada (cron).');
		}
	}

	return false;
}, -200, 3);

/* =============================================================================
 * 5) FAIL-FAST — APENAS AJAX PURO (NUNCA REST / GOOGLE / CF / CRON / WOOCOMMERCE)
 * ========================================================================== */
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

/* =============================================================================
 * 6) BLACKLIST — EXPANDIDA (AGRESSIVA)
 *    Bloqueia sites piratas/null, callbacks de licenca, trackers suspeitos.
 *    Roda SEMPRE, mesmo em contexto crítico do WooCommerce (checkout etc.) —
 *    é a única camada que não recua por contexto.
 * ========================================================================== */
add_filter('pre_http_request', function ($pre, $args, $url) {
	if (false !== $pre) return $pre;

	if (
		nw2_is_google_or_cf($url) ||
		nw2_is_local_request($url) ||
		nw2_is_smtp_host(parse_url($url, PHP_URL_HOST) ?: '')
	) {
		return false;
	}

	/**
	 * Filtro nw2_blocker_blacklist: domínios sempre bloqueados. Ajuste por site via
	 * functions.php do tema ou outro mu-plugin, sem editar este arquivo:
	 *   add_filter('nw2_blocker_blacklist', fn($hosts) => [...$hosts, 'dominiosuspeito.com']);
	 * Nota: entradas sem "." (ex.: "salient", "betheme") são nomes de tema/slug, não
	 * domínio — continuam usando stripos() na URL de propósito, pois não são hosts.
	 */
	$bloqueios_dominio = apply_filters('nw2_blocker_blacklist', [
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
		'api.envato.com',

		// === TEMAS / PLUGINS PREMIUM (callbacks de update/licenca) ===
		'support.wpbakery.com','sliderrevolution.com',
		'bridge.qodeinteractive.com','update.yithemes.com','yithemes.com',
		'update.themeforest.net','api.themeforest.net',
		'update.avada.com','avada.theme-fusion.com',
		'update.divi.com','elegantthemes.com',
		'update.astra.com','bsf.io','brainstormforce.com',
		'update.oceanwp.org','oceanwp.org',
		'pixelyoursite.com',
		'pixtheme.com',
		'update.the7.io','the7.io',

		// === TRACKERS / TELEMETRIA SUSPEITA ===
		'hotjar.com',
		'mouseflow.com',
		'fullstory.com',
		'luckyorange.com',
		'clarity.ms',
	]);

	foreach ($bloqueios_dominio as $dominio) {
		if (nw2_host_matches($url, $dominio)) {
			return new WP_Error('nw2_blacklist', 'Conexão externa bloqueada por política de segurança.');
		}
	}

	// Entradas que são palavra-chave/slug (não domínio válido), continuam via substring de propósito
	$bloqueios_keyword = apply_filters('nw2_blocker_blacklist_keywords', [
		'revslider', 'slider-revolution', 'revslider.php',
		'salient', 'betheme',
		'purchasekey.com', 'license-check.', 'check-license.',
		'usage.tracking.', 'statistic.wp-',
	]);
	foreach ($bloqueios_keyword as $kw) {
		if (stripos($url, $kw) !== false) {
			return new WP_Error('nw2_blacklist', 'Conexão externa bloqueada por política de segurança.');
		}
	}

	return false;
}, 20, 3);

/* =============================================================================
 * 7) WOOCOMMERCE — SILENCIO (tracking/marketplace) + PRESERVA CART
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
 * 8) DEFAULT DENY — LIGADO POR PADRAO — BLOQUEIO IMEDIATO DE NAO-WHITELISTADOS
 *    Qualquer host externo que nao passou pelos bypasses acima (Google, CF,
 *    WP, SMTP, local, WAF/segurança, contexto crítico do WooCommerce) recebe
 *    WP_Error NA HORA, sem esperar timeout de 15s. É a linha de defesa
 *    central contra plugins/temas nulled com malware desconhecido — não
 *    depende de reconhecer o domínio malicioso, só de reconhecer o que é
 *    ESSENCIAL.
 *
 *    Para DESLIGAR num site especifico: define('NW2_DEFAULT_DENY', false);
 *    no wp-config.php desse site.
 *
 *    MODO DRY-RUN (recomendado para o primeiro deploy em qualquer site com
 *    WooCommerce ativo, ou qualquer site que você não conhece a fundo):
 *    define('NW2_DEFAULT_DENY_DRY_RUN', true); no wp-config.php — loga o que
 *    TERIA sido bloqueado (requer NW2_DEBUG_LOG também true pra escrever o
 *    log) mas deixa a requisição passar de verdade. Use por alguns dias (ou
 *    faça um pedido de teste completo) antes de desligar o dry-run.
 * ========================================================================== */
if (!defined('NW2_DEFAULT_DENY')) define('NW2_DEFAULT_DENY', true);
if (!defined('NW2_DEFAULT_DENY_DRY_RUN')) define('NW2_DEFAULT_DENY_DRY_RUN', false);

if (NW2_DEFAULT_DENY) {
	add_filter('pre_http_request', function ($pre, $args, $url) {
		if (false !== $pre) return $pre;

		$host = parse_url($url, PHP_URL_HOST) ?: '';
		if (!$host) return false;

		// Whitelist final: se nao eh Google/CF/WP/SMTP/local/WAF → bloqueia NA HORA
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
 * 9) HARDENING — DESATIVA EDITOR DE ARQUIVOS DO WP-ADMIN
 *    Reduz superficie de persistencia caso um backdoor de plugin nulled ja
 *    instalado consiga acesso admin. Nenhum plugin legitimo depende do
 *    editor nativo (Plugins > Editor / Aparencia > Editor) pra funcionar.
 * ========================================================================== */
if (!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true);

/* =============================================================================
 * 10) HARDENING — DESATIVA XML-RPC
 *     Fecha brute-force amplificado e pingback usado para SSRF/DDoS a partir
 *     do proprio site. Praticamente sem uso legitimo hoje (Jetpack e apps
 *     modernos usam REST API + application passwords).
 * ========================================================================== */
add_filter('xmlrpc_enabled', '__return_false');

/* =============================================================================
 * 11) TIMEOUTS CONTROLADOS + AVISO ANTI-CURL NATIVO
 * ========================================================================== */
add_filter('http_request_args', function ($r) {
	$r['timeout'] = 15;
	$r['connect_timeout'] = 7;
	$r['redirection'] = 3;
	$r['sslverify'] = true;
	return $r;
});

// Aviso no admin se curl_exec estiver habilitado (bypass do WP HTTP API)
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
 * 12) DEBUG MODE (OPCIONAL) — Loga requisicoes bloqueadas (e as do dry-run)
 *    Defina: define('NW2_DEBUG_LOG', true); no wp-config.php
 *    Logs vao para: wp-content/nw2-blocked-requests.log
 * ========================================================================== */
if (!function_exists('nw2_ensure_log_protected')) {
	function nw2_ensure_log_protected(): void {
		$htaccess = WP_CONTENT_DIR . '/.htaccess';
		// Não sobrescreve um .htaccess de wp-content já existente — só garante que
		// a regra de bloqueio do arquivo de log específico esteja presente.
		$marker = 'nw2-blocked-requests.log';
		$existing = is_file($htaccess) ? (string)file_get_contents($htaccess) : '';
		if (strpos($existing, $marker) !== false) return;
		// Cobre Apache <2.4 (mod_access) e >=2.4 (mod_authz_core) simultaneamente
		$rule = "\n# NW2 — protege log de requisições bloqueadas\n<Files \"{$marker}\">\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n</Files>\n";
		@file_put_contents($htaccess, $existing . $rule);
	}
}

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
