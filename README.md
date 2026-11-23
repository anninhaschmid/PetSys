# 🐾 PetSys — Sistema de Gestão e Cibersegurança Veterinária

> **Projeto Final A3 — Unidade Curricular: Sistemas Computacionais e Segurança (2026)**  
> **Organização Alvo:** PetShop & Clínica Veterinária Amigo Fiel Ltda.

---

## 📋 Sobre o Projeto

O **PetSys** é uma proposta de sistema computacional para modernizar e proteger as operações clínicas e administrativas do **PetShop & Clínica Veterinária Amigo Fiel**. Substitui fichas físicas em papel e planilhas descentralizadas e adota uma arquitetura de **Defesa em Profundidade (*Defense-in-Depth*)** para proteger o Prontuário Eletrônico do Pet (PEP) e os dados pessoais dos tutores, com referência à **LGPD**, **ISO/IEC 27001:2022**, **NIST SP 800-53** e **OWASP Top 10:2021**.

O repositório contém um **protótipo** que demonstra os principais controles de segurança. Ele não implementa o sistema completo (cadastros, agenda e vendas). Os limites do protótipo estão descritos na seção *Limitações do protótipo*.

---

## 🗂️ Estrutura de Arquivos

```text
PetSys/
├── index.html      # Painel web (SPA) offline: contexto, arquitetura, riscos e laboratório interativo
├── banco.py        # Protótipo em Python 3: login, lockout, RBAC, HMAC e log de auditoria
├── README.md       # Documentação do projeto
└── .gitignore      # Impede o envio da chave, do banco e dos logs ao repositório
```

Arquivos gerados automaticamente ao executar `banco.py` (não devem ser versionados):

```text
petsys_producao.db     # Banco SQLite com usuários e prontuários
petsys_auditoria.log   # Log de auditoria (RFC 5424, encadeado por hash)
petsys_chave.key       # Chave HMAC gerada localmente (permissão 600)
```

---

## 🛡️ Arquitetura e Controles de Segurança (projeto)

### 1. Segmentação de Rede e Perímetro
* **Borda:** Firewall de Próxima Geração (NGFW) com Web Application Firewall (**ModSecurity**) e tráfego cifrado com **TLS 1.3**.
* **Isolamento por 4 VLANs:**
  * **VLAN 10 (Recepção):** terminais de atendimento e vendas, sem acesso aos prontuários clínicos.
  * **VLAN 20 (Consultórios):** acesso do corpo veterinário ao Prontuário Eletrônico (PEP).
  * **VLAN 30 (Servidores / DMZ):** aplicação e banco de dados, com criptografia em repouso (**AES-256**) e **RAID 1**.
  * **VLAN 40 (Wi-Fi Visitantes):** rede isolada, sem comunicação com a infraestrutura interna.

### 2. Princípios da Segurança da Informação (CIAAN)

| Princípio | Como o projeto atende | Implementado no protótipo |
| :--- | :--- | :---: |
| **Confidencialidade** | RBAC com Menor Privilégio e Separação de Deveres (Atendente e Admin não leem prontuários); AES-256 em repouso e TLS 1.3 em trânsito | RBAC ✅ / AES e TLS ❌ |
| **Integridade** | Assinatura **HMAC-SHA256** em cada prontuário; consultas parametrizadas contra SQL Injection; log encadeado por hash | ✅ |
| **Disponibilidade** | Nobreak 1200VA, RAID 1 e backup 3-2-1 | ❌ (somente projeto) |
| **Autenticidade** | Senhas com **PBKDF2-HMAC-SHA256** (600.000 iterações, salt aleatório de 16 bytes por usuário) e bloqueio de conta após 5 falhas | ✅ |
| **Não-repúdio** | Log de auditoria em formato **RFC 5424** com horário UTC, usuário e ação, encadeado por hash | Parcial ✅ (veja limitações) |

---

## 💻 Protótipo em Python (`banco.py`)

Usa apenas a biblioteca padrão do Python 3.8+ (`sqlite3`, `hashlib`, `hmac`, `json`, `os`).

| Controle | Como funciona no código |
| :--- | :--- |
| **Autenticação** | PBKDF2-HMAC-SHA256, 600.000 iterações, salt aleatório de 16 bytes por usuário. Para usuário inexistente, calcula um hash de mesmo custo para dificultar a enumeração de contas. |
| **Account Lockout** | Após 5 falhas seguidas, a conta é bloqueada por 60 segundos. Quando o bloqueio expira, o contador é reiniciado. |
| **RBAC** | Tabela de permissões por perfil. Somente `VETERINARIA` possui `LER_PRONTUARIO`; `ATENDENTE` e `ADMIN` recebem `HTTP 403`. |
| **Integridade** | Cada prontuário é assinado com HMAC-SHA256 sobre uma representação JSON. Alterações diretas no banco são detectadas na leitura. |
| **Gestão da chave** | A chave HMAC não fica no código: vem da variável de ambiente `PETSYS_HMAC_KEY` ou de um arquivo local gerado automaticamente. |
| **Log de auditoria** | Formato RFC 5424. Cada linha inclui o hash da linha anterior, e `verificar_integridade_log()` detecta qualquer edição. Valores são escapados para evitar *log injection*. |

---

## 🌐 Painel Web (`index.html`)

Página única e **100% offline**, sem dependências externas, que usa `textContent` e `createTextNode` para evitar XSS baseado em DOM. Possui 7 abas: Contexto, Arquitetura, Mecanismos, Ativos & Ameaças, Matriz de Riscos, Autoavaliação e Laboratório Prático. Os itens relacionados aos entregáveis são apresentados dentro das seções já existentes.

O **Laboratório Prático** reúne simuladores de força bruta com lockout, SQL Injection (concatenação vs. consulta parametrizada), HMAC-SHA256 ao vivo e controle RBAC. Os simuladores do painel são **independentes** do `banco.py`: rodam no navegador, em JavaScript.

---

## 🚀 Como Executar

### Painel web
Abra o `index.html` com duplo clique em qualquer navegador moderno. Não precisa de servidor nem de internet.

### Protótipo Python

Abra o PowerShell ou o CMD na pasta do projeto. No Windows, use os comandos abaixo.

#### PowerShell

```powershell
# Opcional: apaga o banco e o log de uma execução anterior (não apaga a chave HMAC)
Remove-Item .\petsys_producao.db, .\petsys_auditoria.log -ErrorAction SilentlyContinue

# Opcional: defina a chave HMAC apenas para esta janela do PowerShell
$env:PETSYS_HMAC_KEY = "troque-por-uma-chave-longa-e-aleatoria"

python .\banco.py
```

#### Prompt de Comando (CMD)

```cmd
REM Opcional: apaga o banco e o log de uma execução anterior (não apaga a chave HMAC)
del petsys_producao.db petsys_auditoria.log 2>nul

REM Opcional: defina a chave HMAC apenas para esta janela do CMD
set PETSYS_HMAC_KEY=troque-por-uma-chave-longa-e-aleatoria

python banco.py
```

No macOS/Linux, os comandos equivalentes são:

```bash
# Opcional: apaga o banco e o log de uma execução anterior (não apaga a chave HMAC)
rm -f petsys_producao.db petsys_auditoria.log

# Opcional: defina a chave HMAC para esta sessão
export PETSYS_HMAC_KEY="troque-por-uma-chave-longa-e-aleatoria"

python banco.py
```

Se `PETSYS_HMAC_KEY` não estiver definida, o programa gera `petsys_chave.key` automaticamente. **Não envie esse arquivo ao repositório.** A remoção do banco apaga os dados locais da demonstração; pule esse comando se quiser preservá-los.

### Resultado esperado

| Teste | O que demonstra |
| :--- | :--- |
| 1 | Veterinária acessa o prontuário (`ACESSO AUTORIZADO`, HMAC válido) |
| 2 | Administrador de TI é bloqueado (`HTTP 403`, Separação de Deveres) |
| 3 | Cinco senhas erradas ativam o bloqueio de 60s, mesmo com a senha correta depois |
| 4 | Após o bloqueio expirar, o contador reinicia e o login correto funciona |
| 5 | Prontuário alterado direto no banco é detectado pelo HMAC (`ALERTA CRÍTICO`) |
| 6 | Log original íntegro; cópia editada é detectada pela cadeia de hashes |

---

## 👥 Credenciais de Demonstração

> ⚠️ **Somente para demonstração acadêmica.** Em produção, as senhas seriam definidas pelo próprio usuário, com troca obrigatória no primeiro acesso, e nunca ficariam em documentação ou código.

| Usuário | Perfil | Senha de Teste | Acesso ao Prontuário (PEP) |
| :--- | :--- | :--- | :--- |
| `dra_carla` | `VETERINARIA` | `VetSenha2026!` | ✅ Autorizado (`HTTP 200`) |
| `atendente_ana` | `ATENDENTE` | `SenhaAna2026!` | ❌ Bloqueado (`HTTP 403`) |
| `admin_ti` | `ADMIN` | `AdminPass2026!` | ❌ Bloqueado (`HTTP 403`, Separação de Deveres) |

---

## ⚠️ Limitações do protótipo

O protótipo demonstra os controles principais, mas simplifica o projeto em alguns pontos:

* **Banco de dados:** o projeto prevê PostgreSQL com AES-256 em repouso; o protótipo usa **SQLite sem criptografia**.
* **Criptografia em trânsito:** TLS 1.3 faz parte do projeto, mas não é implementado no protótipo.
* **Autenticação:** não há MFA nem política de complexidade e expiração de senhas.
* **Log de auditoria:** o encadeamento por hash permite **detectar** adulteração, mas o arquivo continua local. Quem tem acesso total ao servidor pode apagar ou refazer a cadeia inteira. O projeto recomenda envio dos logs a um servidor SIEM isolado.
* **Não-repúdio:** o HMAC usa chave compartilhada, então não prova a autoria de uma ação. Para não-repúdio pleno seriam necessárias **assinaturas digitais** (chave assimétrica).
* **Rede e disponibilidade:** VLANs, firewall, RAID, nobreak e backup 3-2-1 são parte do projeto, mas não são simulados no código.
* **Arquitetura:** o desenho coloca o banco de dados na mesma VLAN da aplicação (DMZ). O recomendável é manter só a aplicação na DMZ e o banco em rede interna.
* **Funcionalidades do negócio:** cadastro de tutores e pets, agenda e vendas não estão implementados.

---

## 📚 Referências Normativas e Técnicas
* **ISO/IEC 27001:2022** — *Information security management systems — Requirements*.
* **NIST SP 800-53 (Rev. 5)** — *Security and Privacy Controls for Information Systems and Organizations*.
* **OWASP Top 10:2021** — *The Ten Most Critical Web Application Security Risks*.
* **RFC 5424** — *The Syslog Protocol*.
* **Lei Geral de Proteção de Dados (LGPD — Lei nº 13.709/2018)**.