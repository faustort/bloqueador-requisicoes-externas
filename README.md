# 🔒 Bloqueador de Requisições Externas

Plugin WordPress para bloquear conexões externas desnecessárias, aumentar a segurança e otimizar o WooCommerce para uso como catálogo.

![WordPress](https://img.shields.io/badge/WordPress-Plugin-blue?logo=wordpress)  
![PHP](https://img.shields.io/badge/PHP-7.4%2B-8892BF?logo=php)  
![License](https://img.shields.io/badge/license-GPLv2-green)

---

## 🚀 Funcionalidades

- 🔒 **Bloqueio Global** — impede conexões externas não autorizadas.  
- ✅ **Lista Branca de Domínios** — libera apenas WordPress.org e serviços do Google (Site Kit, Analytics, Search Console, PageSpeed, etc).  
- 🚫 **Lista Negra** — bloqueio de sites de plugins e temas nulled (wpnull, wplocker, gpldl, etc).  
- ⚡ **Otimização WooCommerce** — desativa scripts de carrinho/checkout e marketplace para uso como **catálogo de produtos**.  
- 📊 **Compatibilidade com Google Site Kit** — garante funcionamento dos serviços Google.  
- 🛡️ **Privacidade** — bloqueia tracking desnecessário do WooCommerce.

---

## 📦 Instalação

> ⚠️ **IMPORTANTE:** este plugin deve ser colocado na pasta `mu-plugins` para garantir que não possa ser desativado acidentalmente.

1. Copie o arquivo do plugin para:
   ```bash
   wp-content/mu-plugins/bloqueador-requisicoes.php
