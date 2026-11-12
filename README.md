# 🐾 PetSys — Sistema de Gestão e Cibersegurança Veterinária

> **Projeto Final A3 — Unidade Curricular: Sistemas Computacionais e Segurança (2026)**  
> **Organização Alvo:** PetShop & Clínica Veterinária Amigo Fiel Ltda.

---

## 📋 Sobre o Projeto

O **PetSys** é uma solução computacional projetada para modernizar e proteger as operações clínicas e administrativas do **PetShop & Clínica Veterinária Amigo Fiel**. Substituindo fichas físicas em papel e planilhas descentralizadas, o sistema implementa uma arquitetura de **Defesa em Profundidade (*Defense-in-Depth*)** para resguardar o Prontuário Eletrônico do Pet (PEP) e os Dados Pessoais Identificáveis (PII) dos tutores, em estrita conformidade com a **LGPD**, **ISO/IEC 27001:2022**, **NIST SP 800-53** e **OWASP Top 10:2021**.

---

## 🗂️ Estrutura de Arquivos do Repositório

```text
petsys-security-project/
├── index.html                        # Painel Web SPA interativo e 100% offline (Frontend + Laboratório)
├── petsys_sistema.py                 # Backend funcional em Python 3 com SQLite e controles de segurança
├── petsys_schema.sql                 # Script DDL relacional (PostgreSQL / SQLite)
├── petsys_dados.json                 # Base de dados estruturada de exemplo (JSON)
├── relatorio_projeto_petsys_web.html # Relatório técnico completo formatado para impressão/PDF
└── README.md                         # Documentação oficial do projeto
```

---

## 🛡️ Arquitetura e Controles de Cibersegurança

### 1. Segmentação de Rede e Perímetro
* **Borda Protegida:** Firewall de Próxima Geração (NGFW) acoplado a Web Application Firewall (**WAF ModSecurity**) e tráfego encriptado via **TLS 1.3**.
* **Isolamento por 4 VLANs:**
  * **VLAN 10 (Recepção):** Terminais de atendimento e vendas (sem acesso aos prontuários clínicos).
  * **VLAN 20 (Consultórios Médicos):** Acesso exclusivo do corpo veterinário ao Prontuário Eletrônico (PEP).
  * **VLAN 30 (Servidores DMZ):** Hospeda a aplicação e o banco de dados com encriptação em repouso (**AES-256**) e espelhamento **RAID 1**.
  * **VLAN 40 (Wi-Fi Visitantes):** Rede isolada para clientes, sem comunicação com a infraestrutura interna.

### 2. Princípios da Segurança da Informação (CIAAN)
* **Confidencialidade:** Controle de Acesso Baseado em Perfis (**RBAC**) com aplicação do **Princípio do Menor Privilégio (PoLP)** e **Separação de Deveres** (nem Atendentes nem Administradores de TI têm permissão de leitura sobre prontuários médicos).
* **Integridade:** Assinaturas criptográficas **HMAC-SHA256** para detectar adulteração nos prontuários e uso obrigatório de *Prepared Statements* contra *SQL Injection*.
* **Disponibilidade:** Nobreak UPS 1200VA, arranjo de discos RAID 1 e rotina automatizada de **Backup 3-2-1**.
* **Autenticidade:** Armazenamento de senhas com algoritmo **PBKDF2-HMAC-SHA256** (100.000 iterações + *Salt* individual de 16 bytes) e bloqueio automático de conta (**Account Lockout**) após 5 tentativas falhadas.
* **Não-repúdio:** Trilha de auditoria contínua no padrão **Syslog (RFC 5424)** com carimbo de data/hora em **UTC**.

---

## 💻 Módulos da Aplicação Web (`index.html`)

A interface web foi construída sem dependências externas (100% *offline* e protegida contra ataques *DOM-based XSS* utilizando `textContent` e `createTextNode`), contendo 8 abas funcionais:

1. **Contexto:** Apresentação da clínica Amigo Fiel, objetivos, LGPD e perfis de usuários.
2. **Arquitetura:** Diagrama interativo de rede com inspetor de regras por VLAN.
3. **Mecanismos:** Mapeamento técnico dos 5 princípios CIAAN.
4. **Ativos & Ameaças:** Levantamento de ativos críticos e vetores de ataque.
5. **Matriz de Riscos:** Avaliação qualitativa/quantitativa dos 5 principais riscos e suas mitigações.
6. **Autoavaliação:** Análise crítica apontando 3 fragilidades arquiteturais e recomendações de melhoria.
7. **Laboratório Prático:**
   * Simulador de **Força Bruta & Account Lockout** (com bateria automatizada de 5 falhas).
   * Simulador comparativo de **SQL Injection** (*Concatenação Vulnerável* vs. *Prepared Statement*).
   * Calculadora **HMAC-SHA256 ao vivo** utilizando a API nativa do navegador (`window.crypto.subtle`).
   * Simulador de **Controle RBAC & Separação de Deveres** (`HTTP 403 Forbidden` para Atendente e Admin).
8. **Entregáveis:** Visualização integrada do relatório acadêmico, roteiro de apresentação e código Python.

---

## 🚀 Como Executar o Projeto

### Opção 1: Painel Web e Laboratório Interativo (Frontend)
Não requer instalação de servidor ou conexão com a internet:
1. Localize o arquivo `index.html`.
2. Dê um duplo clique para abri-lo diretamente em qualquer navegador moderno (Chrome, Edge, Firefox ou Safari).
3. Navegue pelas abas e utilize a **Aba 7: Laboratório Prático** acompanhando os eventos no console Syslog no rodapé.

### Opção 2: Motor de Segurança e Banco de Dados (Backend Python)
Requer **Python 3.8+** instalado (utiliza apenas bibliotecas nativas: `sqlite3`, `hashlib`, `hmac`, `time`, `datetime`):

```bash
# 1. Acesse a pasta do projeto
cd petsys-security-project

# 2. Execute o protótipo funcional
python petsys_sistema.py
```

Ao executar o script, serão criados automaticamente na pasta local:
* `petsys_producao.db`: Banco de dados relacional SQLite populado com usuários e prontuários assinados via HMAC.
* `petsys_auditoria.log`: Arquivo físico contendo os registros de auditoria gerados durante os testes.

---

## 👥 Credenciais de Demonstração

| Usuário | Perfil | Senha de Teste | Acesso ao Prontuário (PEP) |
| :--- | :--- | :--- | :--- |
| `dra_carla` | `VETERINARIA` | `VetSenha2026!` | ✅ **Autorizado** (`HTTP 200 OK`) |
| `atendente_ana` | `ATENDENTE` | `SenhaAna2026!` | ❌ **Bloqueado** (`HTTP 403 Forbidden`) |
| `admin_ti` | `ADMIN` | `AdminPass2026!` | ❌ **Bloqueado** (`HTTP 403 Forbidden` — Separação de Deveres) |

---

## 📚 Referências Normativas e Técnicas
* **ISO/IEC 27001:2022** — *Information security management systems — Requirements*.
* **NIST SP 800-53 (Rev. 5)** — *Security and Privacy Controls for Information Systems and Organizations*.
* **OWASP Top 10:2021** — *The Ten Most Critical Web Application Security Risks*.
* **Lei Geral de Proteção de Dados (LGPD — Lei nº 13.709/2018)**.
