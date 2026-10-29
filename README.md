# NW2 Security Suite Pro (MU) — v3.2.0

Substituto leve e definitivo do Sucuri em um único MU-plugin:
- **Bloqueador de requisições externas** 100% amigável ao **WordPress Core** (`wordpress.org`, `w.org`, `s.w.org`, `gravatar.com`) e ao **Google** (Site Kit, Analytics, GTM, Ads, Fonts, reCAPTCHA, Maps, YouTube oEmbed)
- **Stub Inteligente Total do Servidor do Elementor & Elementor Pro** (`elementor.com`, `elementor.cloud`, `elementor.io`, `elementor.net`, `elemnt.ro`) — intercepta chamadas de biblioteca, templates, telemetria e licença sem sair do servidor e sem gerar avisos no log
- **Limpeza Total do Dashboard do WordPress (`NW2_CLEAN_DASHBOARD`)** — remove todos os widgets pesados da tela inicial do `wp-admin/index.php` (Novidades do WP, Rascunho Rápido, Diagnóstico, Visão Geral do Elementor, etc.)
- **WAF Leve Anti-Enumeração (`NW2_PROTECT_USER_ENUM`)** — bloqueia varredura de usuários via `/?author=1` e `/wp-json/wp/v2/users` para visitantes não autenticados
- **Scanner de permissões** + detecção de `.php` em `wp-content/uploads`
- **Hardening `.htaccess` seguro** (não bloqueia Google Imagens, redes sociais ou `curl` legítimo) + bloqueio de execução de `.php` dentro de `wp-content/uploads/.htaccess`
- **Monitoramento de integridade** de arquivos críticos e **sanitização de uploads** (imagens, dupla extensão e SVG)

## Instalação

Copie `wp-security-super-mu.php` para:
```
wp-content/mu-plugins/wp-security-super-mu.php
```

> **Importante:** NUNCA defina `WP_HTTP_BLOCK_EXTERNAL=true` no `wp-config.php`. Este plugin gerencia tudo via `pre_http_request`.

## Constantes de Configuração (`wp-config.php`)

Todas vêm ativadas por padrão com valores seguros:

```php
define('NW2_DEFAULT_DENY', true);           // Bloqueia conexões externas não autorizadas
define('NW2_CLEAN_DASHBOARD', true);        // Deixa o Dashboard inicial do WP 100% limpo e rápido
define('NW2_PROTECT_USER_ENUM', true);      // Bloqueia enumeração de usuários (?author=1 e REST API)
define('NW2_SCAN_PERMISSIONS', true);       // Scanner diário de permissões
define('NW2_AUTO_HARDEN_HTACCESS', true);   // Hardening seguro do .htaccess e uploads/.htaccess
define('NW2_MONITOR_FILE_CHANGES', true);   // Monitora alterações em arquivos core críticos
define('NW2_SANITIZE_UPLOADS', true);       // Sanitiza uploads (imagens, dupla extensão, SVG)
define('NW2_DEFAULT_DENY_DRY_RUN', false);  // Se true, apenas loga sem bloquear
define('NW2_DEBUG_LOG', false);             // Se true, grava log de bloqueios em wp-content/
```

## Filtros Disponíveis

- `nw2_blocker_whitelist`: adiciona domínios liberados além do ecossistema Google/WordPress/Cloudflare.
- `nw2_blocker_blacklist`: adiciona domínios bloqueados explicitamente.
- `nw2_blocker_blacklist_keywords`: adiciona palavras-chave bloqueadas na URL.

## Requisitos

- WordPress 5.8+
- PHP 8.0+
