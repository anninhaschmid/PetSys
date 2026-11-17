"""
PetSys - Protótipo de segurança (Projeto A3 - Sistemas Computacionais e Segurança)

Controles demonstrados:
  - Autenticação com PBKDF2-HMAC-SHA256 (salt aleatório por usuário)
  - Account Lockout (5 falhas -> 60s), com reinício do contador após o bloqueio
  - RBAC com Menor Privilégio e Separação de Deveres
  - Integridade dos prontuários com HMAC-SHA256
  - Log de auditoria em formato RFC 5424, encadeado por hash (detecta adulteração)

Observação: este é um protótipo. O design prevê PostgreSQL com AES-256 em repouso
e TLS 1.3; aqui usamos SQLite (biblioteca padrão) apenas para demonstração.
"""
import sqlite3
import hashlib
import hmac
import json
import os
import shutil
import socket
import tempfile
import time
from datetime import datetime, timezone

ARQUIVO_DB = "petsys_producao.db"
ARQUIVO_LOG = "petsys_auditoria.log"
ARQUIVO_CHAVE = "petsys_chave.key"

ITERACOES_PBKDF2 = 600_000   # recomendação OWASP (2023) para PBKDF2-HMAC-SHA256
MAX_FALHAS = 5
TEMPO_BLOQUEIO = 60          # segundos
HASH_GENESIS = "0" * 64
HOSTNAME = socket.gethostname()

# Permissões por perfil (RBAC). Quem não está na lista não tem acesso.
PERMISSOES = {
    "VETERINARIA": {"LER_PRONTUARIO", "ESCREVER_PRONTUARIO"},
    "ATENDENTE": {"CADASTRAR_TUTOR", "AGENDAR_CONSULTA", "REGISTRAR_VENDA"},
    "ADMIN": {"GERENCIAR_USUARIOS", "GERENCIAR_BACKUP"},  # sem acesso clínico (separação de deveres)
}


# ---------------------------------------------------------------------------
# Chave HMAC: nunca fica no código-fonte
# ---------------------------------------------------------------------------
def carregar_chave_hmac():
    """Ordem: variável de ambiente PETSYS_HMAC_KEY -> arquivo local (permissão 600) -> gera nova."""
    env = os.environ.get("PETSYS_HMAC_KEY")
    if env:
        return env.encode()
    if os.path.exists(ARQUIVO_CHAVE):
        with open(ARQUIVO_CHAVE, "rb") as f:
            return f.read()
    chave = os.urandom(32)
    fd = os.open(ARQUIVO_CHAVE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(chave)
    return chave


CHAVE_HMAC_MESTRE = carregar_chave_hmac()


# ---------------------------------------------------------------------------
# Log de auditoria: RFC 5424 + encadeamento por hash (tamper-evident)
# ---------------------------------------------------------------------------
def _sd_escape(valor):
    """Escapa valores de STRUCTURED-DATA (RFC 5424) e remove caracteres de controle (log injection)."""
    v = str(valor).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
    return "".join(c if c.isprintable() else "?" for c in v)


def _severidade(status):
    if status == "ALERTA_CRITICO":
        return 2   # critical
    if status in ("FALHA", "BLOQUEADO", "NEGADO_HTTP_403", "DEFESA_ATIVADA"):
        return 4   # warning
    return 6       # informational


def _ultimo_hash_log(caminho=ARQUIVO_LOG):
    ultimo = HASH_GENESIS
    if os.path.exists(caminho):
        with open(caminho, encoding="utf-8") as f:
            for linha in f:
                linha = linha.rstrip("\n")
                if " h=" in linha:
                    ultimo = linha.rsplit(" h=", 1)[1]
    return ultimo


def gravar_log_auditoria(username, acao, status, detalhes=""):
    """Grava uma linha RFC 5424 (facility 4 = auth) encadeada ao hash da linha anterior."""
    pri = 4 * 8 + _severidade(status)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    corpo = (
        f'<{pri}>1 {ts} {HOSTNAME} petsys {os.getpid()} {acao} '
        f'[petsys@32473 user="{_sd_escape(username)}" status="{_sd_escape(status)}"] '
        f'{_sd_escape(detalhes)}'
    )
    anterior = _ultimo_hash_log()
    h = hashlib.sha256((anterior + corpo).encode("utf-8")).hexdigest()
    linha = f"{corpo} h={h}"
    with open(ARQUIVO_LOG, "a", encoding="utf-8") as f:
        f.write(linha + "\n")
    print(f"   [SYSLOG] {linha}")


def verificar_integridade_log(caminho=ARQUIVO_LOG):
    """Percorre a cadeia de hashes. Retorna (True, None) ou (False, número_da_linha_adulterada)."""
    anterior = HASH_GENESIS
    if not os.path.exists(caminho):
        return True, None
    with open(caminho, encoding="utf-8") as f:
        for n, linha in enumerate(f, start=1):
            linha = linha.rstrip("\n")
            if " h=" not in linha:
                return False, n
            corpo, h = linha.rsplit(" h=", 1)
            esperado = hashlib.sha256((anterior + corpo).encode("utf-8")).hexdigest()
            if not hmac.compare_digest(h, esperado):
                return False, n
            anterior = h
    return True, None


# ---------------------------------------------------------------------------
# Banco de dados
# ---------------------------------------------------------------------------
def _hash_senha(senha, salt_hex):
    return hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), bytes.fromhex(salt_hex), ITERACOES_PBKDF2
    ).hex()


def _assinar_prontuario(nome, especie, tutor, historico):
    """HMAC sobre uma representação canônica (JSON), sem ambiguidade de separador."""
    conteudo = json.dumps([nome, especie, tutor, historico], ensure_ascii=False)
    return hmac.new(CHAVE_HMAC_MESTRE, conteudo.encode("utf-8"), hashlib.sha256).hexdigest()


def inicializar_banco_dados():
    conn = sqlite3.connect(ARQUIVO_DB)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            nome TEXT NOT NULL,
            perfil TEXT NOT NULL,
            salt TEXT NOT NULL,
            senha_hash TEXT NOT NULL,
            tentativas_erradas INTEGER DEFAULT 0,
            bloqueado_ate REAL DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS prontuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pet_nome TEXT NOT NULL,
            especie TEXT NOT NULL,
            tutor TEXT NOT NULL,
            historico_clinico TEXT NOT NULL,
            hmac_checksum TEXT NOT NULL
        )
    ''')

    cursor.execute("SELECT COUNT(*) FROM usuarios")
    if cursor.fetchone()[0] == 0:
        # Senhas de DEMONSTRAÇÃO. Em produção: troca obrigatória no primeiro acesso.
        usuarios_demo = [
            ("atendente_ana", "Ana Souza", "ATENDENTE", "SenhaAna2026!"),
            ("dra_carla", "Dra. Carla Lima", "VETERINARIA", "VetSenha2026!"),
            ("admin_ti", "Administrador TI", "ADMIN", "AdminPass2026!"),
        ]
        for user, nome, perfil, senha in usuarios_demo:
            salt = os.urandom(16).hex()   # 16 bytes aleatórios por usuário
            cursor.execute(
                "INSERT INTO usuarios (username, nome, perfil, salt, senha_hash) VALUES (?, ?, ?, ?, ?)",
                (user, nome, perfil, salt, _hash_senha(senha, salt)),
            )

    cursor.execute("SELECT COUNT(*) FROM prontuarios")
    if cursor.fetchone()[0] == 0:
        pets_demo = [
            ("Thor", "Cão", "Marcos Silva", "Vacina V10 aplicada. Sem histórico de alergias."),
            ("Mimi", "Gato", "Beatriz Mendes", "Tratamento para otite em andamento."),
        ]
        for nome, especie, tutor, historico in pets_demo:
            cursor.execute(
                "INSERT INTO prontuarios (pet_nome, especie, tutor, historico_clinico, hmac_checksum) "
                "VALUES (?, ?, ?, ?, ?)",
                (nome, especie, tutor, historico, _assinar_prontuario(nome, especie, tutor, historico)),
            )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Autenticação com Account Lockout
# ---------------------------------------------------------------------------
def autenticar_utilizador(username, senha):
    conn = sqlite3.connect(ARQUIVO_DB)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, nome, perfil, salt, senha_hash, tentativas_erradas, bloqueado_ate "
        "FROM usuarios WHERE username = ?", (username,)
    )
    user = cursor.fetchone()

    if not user:
        _hash_senha(senha, "00" * 16)  # gasta o mesmo tempo, dificultando enumeração de usuários
        gravar_log_auditoria(username, "AUTENTICACAO", "FALHA", "Usuário não encontrado")
        conn.close()
        return None, "Credenciais inválidas."

    uid, nome, perfil, salt, senha_hash_bd, falhas, bloqueado_ate = user
    agora = time.time()

    # CORREÇÃO: se o bloqueio já expirou, reinicia o contador (antes, 1 erro bloqueava de novo)
    if bloqueado_ate and bloqueado_ate <= agora:
        falhas, bloqueado_ate = 0, 0
        cursor.execute("UPDATE usuarios SET tentativas_erradas = 0, bloqueado_ate = 0 WHERE id = ?", (uid,))
        conn.commit()
        gravar_log_auditoria(username, "ACCOUNT_LOCKOUT", "INFO", "Bloqueio expirado; contador reiniciado")

    if bloqueado_ate > agora:
        restante = int(bloqueado_ate - agora)
        gravar_log_auditoria(username, "AUTENTICACAO", "BLOQUEADO", f"Tentativa durante lockout ({restante}s restantes)")
        conn.close()
        return None, f"DEFESA ATIVADA: Conta bloqueada. Tente em {restante} segundos."

    if hmac.compare_digest(_hash_senha(senha, salt), senha_hash_bd):
        cursor.execute("UPDATE usuarios SET tentativas_erradas = 0, bloqueado_ate = 0 WHERE id = ?", (uid,))
        conn.commit()
        conn.close()
        gravar_log_auditoria(username, "AUTENTICACAO", "SUCESSO", f"Perfil: {perfil}")
        return {"username": username, "nome": nome, "perfil": perfil}, f"Bem-vindo(a), {nome}!"

    falhas += 1
    novo_bloqueio = 0
    if falhas >= MAX_FALHAS:
        novo_bloqueio = agora + TEMPO_BLOQUEIO
        gravar_log_auditoria(username, "ACCOUNT_LOCKOUT", "DEFESA_ATIVADA",
                             f"{MAX_FALHAS} falhas consecutivas. Conta bloqueada por {TEMPO_BLOQUEIO}s.")
        msg = f"DEFESA ATIVADA: {MAX_FALHAS} tentativas falhadas excedidas. Conta BLOQUEADA por {TEMPO_BLOQUEIO} segundos."
    else:
        gravar_log_auditoria(username, "AUTENTICACAO", "FALHA", f"Tentativa falhada {falhas}/{MAX_FALHAS}")
        msg = f"Credenciais inválidas. Tentativas restantes: {MAX_FALHAS - falhas}"

    cursor.execute("UPDATE usuarios SET tentativas_erradas = ?, bloqueado_ate = ? WHERE id = ?",
                   (falhas, novo_bloqueio, uid))
    conn.commit()
    conn.close()
    return None, msg


# ---------------------------------------------------------------------------
# RBAC + integridade do prontuário
# ---------------------------------------------------------------------------
def tem_permissao(sessao_usuario, permissao):
    return permissao in PERMISSOES.get(sessao_usuario["perfil"], set())


def consultar_prontuario_rbac(sessao_usuario, pet_id):
    print(f"\n---> [RBAC] Solicitante: {sessao_usuario['nome']} ({sessao_usuario['perfil']})")

    if not tem_permissao(sessao_usuario, "LER_PRONTUARIO"):
        gravar_log_auditoria(sessao_usuario["username"], "ACESSO_PRONTUARIO", "NEGADO_HTTP_403",
                             f"Perfil '{sessao_usuario['perfil']}' sem a permissão LER_PRONTUARIO")
        return (f"DEFESA ATIVADA [HTTP 403 Forbidden]: O perfil '{sessao_usuario['perfil']}' "
                f"não possui permissão para consultar dados clínicos sensíveis.")

    conn = sqlite3.connect(ARQUIVO_DB)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT pet_nome, especie, tutor, historico_clinico, hmac_checksum FROM prontuarios WHERE id = ?",
        (pet_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return "Registro não encontrado."

    nome, especie, tutor, historico, hmac_bd = row
    if hmac.compare_digest(hmac_bd, _assinar_prontuario(nome, especie, tutor, historico)):
        gravar_log_auditoria(sessao_usuario["username"], "ACESSO_PRONTUARIO", "SUCESSO",
                             f"Prontuário Pet ID {pet_id} verificado e íntegro")
        return (f"ACESSO AUTORIZADO:\n[Paciente: {nome} ({especie}) | Tutor: {tutor}]\n"
                f"Histórico: {historico}\n[Integridade HMAC-SHA256: VÁLIDA]")

    gravar_log_auditoria(sessao_usuario["username"], "INTEGRIDADE_DADOS", "ALERTA_CRITICO",
                         f"HMAC inválido no Pet ID {pet_id}")
    return "DEFESA ATIVADA: ALERTA CRÍTICO! Adulteração de dados detectada na base de dados."


# ---------------------------------------------------------------------------
# Demonstração
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    inicializar_banco_dados()
    print("=========================================================")
    print("      PETSYS - SISTEMA DE GESTÃO & CIBERSEGURANÇA        ")
    print("=========================================================\n")

    print("--- TESTE 1: Veterinária (perfil autorizado) ---")
    user_vet, msg = autenticar_utilizador("dra_carla", "VetSenha2026!")
    print(f"Status Login: {msg}")
    if user_vet:
        print(consultar_prontuario_rbac(user_vet, 1))

    print("\n--- TESTE 2: Administrador de TI (bloqueado por Separação de Deveres) ---")
    user_admin, msg = autenticar_utilizador("admin_ti", "AdminPass2026!")
    print(f"Status Login: {msg}")
    if user_admin:
        print(consultar_prontuario_rbac(user_admin, 1))

    print("\n--- TESTE 3: Força bruta e Account Lockout ---")
    for i in range(1, MAX_FALHAS + 1):
        _, res_msg = autenticar_utilizador("atendente_ana", f"SenhaErrada{i}")
        print(f"Tentativa {i}: {res_msg}")
    _, res_lockout = autenticar_utilizador("atendente_ana", "SenhaAna2026!")
    print(f"Tentativa {MAX_FALHAS + 1} (senha correta durante o lockout): {res_lockout}")

    print("\n--- TESTE 4: Bloqueio expira e o contador é reiniciado (correção) ---")
    conn = sqlite3.connect(ARQUIVO_DB)
    conn.execute("UPDATE usuarios SET bloqueado_ate = ? WHERE username = 'atendente_ana'", (time.time() - 1,))
    conn.commit()
    conn.close()  # simula a passagem dos 60 segundos
    _, res = autenticar_utilizador("atendente_ana", "SenhaErradaPosBloqueio")
    print(f"1ª falha após o bloqueio: {res}")
    user_ana, res = autenticar_utilizador("atendente_ana", "SenhaAna2026!")
    print(f"Login correto em seguida: {res}")

    print("\n--- TESTE 5: Adulteração de prontuário detectada pelo HMAC ---")
    conn = sqlite3.connect(ARQUIVO_DB)
    original = conn.execute("SELECT historico_clinico FROM prontuarios WHERE id = 2").fetchone()[0]
    conn.execute("UPDATE prontuarios SET historico_clinico = 'Alterado por atacante' WHERE id = 2")
    conn.commit()
    conn.close()
    print(consultar_prontuario_rbac(user_vet, 2))
    conn = sqlite3.connect(ARQUIVO_DB)  # restaura o dado original
    conn.execute("UPDATE prontuarios SET historico_clinico = ? WHERE id = 2", (original,))
    conn.commit()
    conn.close()

    print("\n--- TESTE 6: Integridade do log de auditoria (cadeia de hashes) ---")
    ok, linha = verificar_integridade_log()
    print(f"Log original: {'ÍNTEGRO' if ok else f'ADULTERADO na linha {linha}'}")
    copia = os.path.join(tempfile.gettempdir(), "petsys_log_adulterado.log")
    shutil.copy(ARQUIVO_LOG, copia)
    with open(copia, encoding="utf-8") as f:
        linhas = f.readlines()
    linhas[1] = linhas[1].replace("SUCESSO", "FALHA ")  # atacante tenta apagar rastro
    with open(copia, "w", encoding="utf-8") as f:
        f.writelines(linhas)
    ok, linha = verificar_integridade_log(copia)
    print(f"Cópia editada: {'ÍNTEGRO' if ok else f'ADULTERADO detectado na linha {linha}'}")
    os.remove(copia)