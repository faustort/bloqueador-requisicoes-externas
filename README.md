# 🔒 Bloqueador de Requisições Externas

Plugin WordPress para bloquear conexões externas desnecessárias, aumentar a segurança e otimizar o WooCommerce para uso como catálogo.

![WordPress](https://img.shields.io/badge/WordPress-Plugin-blue?logo=wordpress)  
![PHP](https://img.shields.io/badge/PHP-7.4%2B-8892BF?logo=php)  
![License](https://img.shields.io/badge/license-GPLv2-green)

---

## 🚀 Funcionalidades

- 🔒 **Default Deny ligado por padrão** — qualquer host não explicitamente liberado é bloqueado na hora. É a defesa central contra plugins/temas **nulled com malware desconhecido**: em vez de tentar catalogar todo domínio malicioso (lista que fica obsoleta em dias), só passa quem está na lista essencial.
- ✅ **Lista Branca de Domínios** — WordPress.org, Google (Site Kit, Analytics, Search Console, PageSpeed etc.), Cloudflare, plugins de segurança/WAF (Sucuri, Wordfence, iThemes/Solid Security, MalCare/BlogVault), WooCommerce.com/Jetpack/WordPress.com (WooCommerce Payments), Stripe/PayPal, e CEP/frete BR (ViaCEP, BrasilAPI, Correios).
- 🛒 **Pronto para WooCommerce** — checkout, gateway de pagamento, frete e renovação de assinatura são reconhecidos por **contexto** (`wc-ajax`, REST `/wc/`, cron, página de checkout, tela de configurações), não por uma lista fixa de domínios de gateway. Isso cobre Mercado Pago, PagSeguro, Cielo e qualquer outro gateway automaticamente, sem precisar cadastrar cada um — a lista negra continua valendo mesmo nesse contexto.
- 🧪 **Modo dry-run** — `NW2_DEFAULT_DENY_DRY_RUN` loga o que teria sido bloqueado sem bloquear de verdade. Use antes de confiar no bloqueio real em qualquer site que você não conhece a fundo (ver seção "Rollout seguro" abaixo).
- 🎭 **Stub total do Elementor/Elementor PRO** — nunca conecta de verdade, sempre recebe resposta fake de sucesso, de forma consistente em qualquer contexto (AJAX, cron, normal) — sem avisos de licença/conexão quebrada no admin.
- 🚫 **Lista Negra** — bloqueio de sites de plugins e temas nulled (wpnull, wplocker, gpldl etc.), mesmo em contexto de checkout.
- 🛡️ **Hardening extra** — editor de arquivos do wp-admin desativado (`DISALLOW_FILE_EDIT`) e XML-RPC desligado por padrão.
- 📊 **Compatibilidade com Google Site Kit** — garante funcionamento dos serviços Google.
- 🛡️ **Privacidade** — bloqueia tracking desnecessário do WooCommerce.

---

## 📦 Instalação

> ⚠️ **IMPORTANTE:** este plugin deve ser colocado na pasta `mu-plugins` para garantir que não possa ser desativado acidentalmente.

1. Copie o arquivo do plugin para:
   ```bash
   wp-content/mu-plugins/bloqueador-requisicoes.php
   ```

## 🧩 Personalização por site

A partir da 2.10.0, whitelist e blacklist são extensíveis via filtro, sem editar o arquivo do plugin:

```php
// No functions.php do tema ou em outro mu-plugin:
add_filter('nw2_blocker_whitelist', function ($hosts) {
    return [...$hosts, 'meudominio-parceiro.com'];
});

add_filter('nw2_blocker_blacklist', function ($hosts) {
    return [...$hosts, 'dominiosuspeito.com'];
});
```

Use isso para liberar um gateway de pagamento específico fora do contexto de checkout (ex.: teste manual em outra tela), ou qualquer plugin premium legitimamente comprado cuja checagem de licença precise passar — o Default Deny bloqueia esses casos por padrão, já que não distingue "premium comprado" de "nulled", só distingue "está na whitelist" ou não.

## ⚠️ Rollout seguro (Default Deny + dry-run)

O WordPress tem uma flag nativa (`WP_HTTP_BLOCK_EXTERNAL`) que faz a mesma coisa que este plugin — bloquear tudo por padrão — e é conhecida por **quebrar sites por completo** quando a lista de hosts permitidos não é abrangente o bastante (updates, validação de licença etc. param de funcionar). Este plugin nunca usa essa flag nativa (usa `pre_http_request`, mais granular), mas o risco de "bloquear algo essencial" existe da mesma forma se a whitelist não cobrir tudo que o site precisa — especialmente em lojas WooCommerce.

Antes de confiar no Default Deny (ligado por padrão a partir da 2.11.0) em produção, principalmente em qualquer site com WooCommerce ativo:

1. Adicione ao `wp-config.php` do site: `define('NW2_DEFAULT_DENY_DRY_RUN', true);` e `define('NW2_DEBUG_LOG', true);`
2. Navegue pelo site normalmente e, se houver loja, faça um pedido de teste completo (carrinho → checkout → pagamento).
3. Confira `wp-content/nw2-blocked-requests.log` — cada linha `nw2_default_deny_DRY_RUN` mostra um host que **teria sido bloqueado**.
4. Se aparecer algo legítimo (ex.: um gateway de pagamento ou plugin premium específico), libere via `nw2_blocker_whitelist` (ver seção acima) ou confirme que o fluxo de checkout/WooCommerce já deveria ter coberto automaticamente.
5. Só então remova o `NW2_DEFAULT_DENY_DRY_RUN` (ou defina como `false`) para o bloqueio valer de verdade.

## 📝 Changelog

### 2.11.0
- **Correção crítica**: a cadeia de filtros `pre_http_request` não preservava a decisão de um filtro anterior quando um filtro de prioridade maior não tinha opinião própria — isso fazia o stub do Elementor nunca chegar de fato ao WordPress core em contexto AJAX (o mais comum). Corrigido com guard clause em cada callback.
- `NW2_DEFAULT_DENY` agora vem **ligado por padrão** (antes era opt-in). Pode ser desligado por site com `define('NW2_DEFAULT_DENY', false);`.
- Novo modo `NW2_DEFAULT_DENY_DRY_RUN` para simular o bloqueio sem aplicá-lo de verdade (ver seção "Rollout seguro" acima).
- WooCommerce tratado como zona crítica por contexto (checkout, `wc-ajax`, REST `/wc/`, cron, tela de configurações) em vez de depender de lista fixa de gateways de pagamento.
- Whitelist expandida: Sucuri, Wordfence, iThemes/Solid Security, MalCare/BlogVault, WooCommerce.com/Jetpack/WordPress.com, Stripe/PayPal, ViaCEP/BrasilAPI/Correios. Sucuri removido da blacklist (estava bloqueando o próprio scanner).
- `nw2_is_local_request()` endurecida (fail-closed em vez de fail-open para URLs sem host reconhecível).
- Novo: `DISALLOW_FILE_EDIT` e XML-RPC desativados por padrão.

### 2.10.0
- Matching de domínio agora usa o host real da URL (`parse_url` + comparação exata/sufixo) em vez de `stripos()` na URL inteira — elimina falso-positivo/negativo por substring.
- Whitelist e blacklist expostas via `apply_filters('nw2_blocker_whitelist', ...)` / `apply_filters('nw2_blocker_blacklist', ...)`.
- Log de requisições bloqueadas (`wp-content/nw2-blocked-requests.log`) agora protegido por `.htaccess` (`Deny from all` / `Require all denied`), criado automaticamente na primeira escrita.

### 2.9.1
- Versão anterior: fail-fast + Default Deny opt-in, stub total do Elementor, compatibilidade Google Site Kit, otimização WooCommerce catálogo.
