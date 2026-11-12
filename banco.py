import sqlite3
import hashlib
import hmac
import time
import os
from datetime import datetime, timezone

ARQUIVO_DB = "petsys_producao.db"
ARQUIVO_LOG = "petsys_auditoria.log"
CHAVE_HMAC_MESTRE = b"ChaveSecretaHMACPetSys2026AmigoFiel"

def gravar_log_auditoria(username, acao, status, detalhes=""):
    """Grava registo imutável de auditoria com timestamp UTC."""
    agora = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    linha_log = f"[{agora}] UTILIZADOR='{username}' | AÇÃO='{acao}' | STATUS='{status}' | {detalhes}\n"
    with open(ARQUIVO_LOG, "a", encoding="utf-8") as f:
        f.write(linha_log)
    print(f"   [SYSLOG] {linha_log.strip()}")

def inicializar_banco_dados():
    """Cria a estrutura relacional em SQLite com dados iniciais."""
    conn = sqlite3.connect(ARQUIVO_DB)
    cursor = conn.cursor()

    # Tabela de Utilizadores com suporte a Lockout
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

    # Tabela de Prontuários Médicos com Assinatura HMAC de Integridade
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

    # Cadastrar Utilizadores Iniciais se a tabela estiver vazia
    cursor.execute("SELECT COUNT(*) FROM usuarios")
    if cursor.fetchone()[0] == 0:
        usuarios_demo = [
            ("atendente_ana", "Ana Souza", "ATENDENTE", "a1b2c3d4e5f67890", "SenhaAna2026!"),
            ("dra_carla", "Dra. Carla Lima", "VETERINARIA", "f6e5d4c3b2a10987", "VetSenha2026!"),
            ("admin_ti", "Administrador TI", "ADMIN", "1234567890abcdef", "AdminPass2026!")
        ]
        for user, nome, perfil, salt, senha in usuarios_demo:
            senha_hash = hashlib.pbkdf2_hmac('sha256', senha.encode(), salt.encode(), 100000).hex()
            cursor.execute('''
                INSERT INTO usuarios (username, nome, perfil, salt, senha_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', (user, nome, perfil, salt, senha_hash))

    # Cadastrar Paciente Iniciais se a tabela estiver vazia
    cursor.execute("SELECT COUNT(*) FROM prontuarios")
    if cursor.fetchone()[0] == 0:
        pets_demo = [
            ("Thor", "Cão", "Marcos Silva", "Vacina V10 aplicada. Sem histórico de alergias."),
            ("Mimi", "Gato", "Beatriz Mendes", "Tratamento para otite em andamento.")
        ]
        for nome, especie, tutor, historico in pets_demo:
            conteudo = f"{nome}|{especie}|{tutor}|{historico}"
            checksum = hmac.new(CHAVE_HMAC_MESTRE, conteudo.encode(), hashlib.sha256).hexdigest()
            cursor.execute('''
                INSERT INTO prontuarios (pet_nome, especie, tutor, historico_clinico, hmac_checksum)
                VALUES (?, ?, ?, ?, ?)
            ''', (nome, especie, tutor, historico, checksum))

    conn.commit()
    conn.close()

def autenticar_utilizador(username, senha):
    """Realiza o login validando PBKDF2 e aplicando bloqueio após 5 falhas."""
    conn = sqlite3.connect(ARQUIVO_DB)
    cursor = conn.cursor()

    cursor.execute("SELECT id, nome, perfil, salt, senha_hash, tentativas_erradas, bloqueado_ate FROM usuarios WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        gravar_log_auditoria(username, "AUTENTICACAO", "FALHA", "Utilizador não encontrado")
        conn.close()
        return None, "Credenciais inválidas."

    uid, nome, perfil, salt, senha_hash_bd, falhas, bloqueado_ate = user
    agora = time.time()

    if bloqueado_ate > agora:
        restante = int(bloqueado_ate - agora)
        gravar_log_auditoria(username, "AUTENTICACAO", "BLOQUEADO", f"Tentativa durante lockout ({restante}s restantes)")
        conn.close()
        return None, f"DEFESA ATIVADA: Conta bloqueada. Tente em {restante} segundos."

    hash_input = hashlib.pbkdf2_hmac('sha256', senha.encode(), salt.encode(), 100000).hex()

    if hmac.compare_digest(hash_input, senha_hash_bd):
        cursor.execute("UPDATE usuarios SET tentativas_erradas = 0, bloqueado_ate = 0 WHERE id = ?", (uid,))
        conn.commit()
        conn.close()
        gravar_log_auditoria(username, "AUTENTICACAO", "SUCESSO", f"Perfil: {perfil}")
        return {"username": username, "nome": nome, "perfil": perfil}, f"Bem-vindo(a), {nome}!"
    else:
        falhas += 1
        novo_bloqueio = 0
        if falhas >= 5:
            novo_bloqueio = agora + 60
            gravar_log_auditoria(username, "ACCOUNT_LOCKOUT", "DEFESA_ATIVADA", "5 falhas consecutivas. Conta bloqueada por 60s.")
            msg = "DEFESA ATIVADA: 5 tentativas falhadas excedidas. Conta BLOQUEADA por 60 segundos."
        else:
            gravar_log_auditoria(username, "AUTENTICACAO", "FALHA", f"Tentativa falhada {falhas}/5")
            msg = f"Credenciais inválidas. Tentativas restantes: {5 - falhas}"

        cursor.execute("UPDATE usuarios SET tentativas_erradas = ?, bloqueado_ate = ? WHERE id = ?", (falhas, novo_bloqueio, uid))
        conn.commit()
        conn.close()
        return None, msg

def consultar_prontuario_rbac(sessao_usuario, pet_id):
    """Aplica o Princípio do Menor Privilégio (PoLP) para acesso ao Prontuário Médico."""
    print(f"\n---> [RBAC VERIFICATION] Solicitante: {sessao_usuario['nome']} ({sessao_usuario['perfil']})")

    # Apenas VETERINARIA tem acesso. ATENDENTE e ADMIN são bloqueados.
    if sessao_usuario["perfil"] != "VETERINARIA":
        gravar_log_auditoria(
            sessao_usuario["username"],
            "ACESSO_PRONTUARIO",
            "NEGADO_HTTP_403",
            f"Acesso negado para o perfil '{sessao_usuario['perfil']}' (PoLP Enforcement)"
        )
        return f"DEFESA ATIVADA [HTTP 403 Forbidden]: O perfil '{sessao_usuario['perfil']}' não possui permissão para consultar dados clínicos sensíveis."

    conn = sqlite3.connect(ARQUIVO_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT pet_nome, especie, tutor, historico_clinico, hmac_checksum FROM prontuarios WHERE id = ?", (pet_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        nome, especie, tutor, historico, hmac_bd = row
        conteudo = f"{nome}|{especie}|{tutor}|{historico}"
        hmac_calculado = hmac.new(CHAVE_HMAC_MESTRE, conteudo.encode(), hashlib.sha256).hexdigest()

        if hmac.compare_digest(hmac_bd, hmac_calculado):
            gravar_log_auditoria(sessao_usuario["username"], "ACESSO_PRONTUARIO", "SUCESSO", f"Prontuário Pet ID {pet_id} verificado e íntegro")
            return f"ACESSO AUTORIZADO:\n[Paciente: {nome} ({especie}) | Tutor: {tutor}]\nHistórico: {historico}\n[Integridade HMAC-SHA256: VÁLIDA]"
        else:
            gravar_log_auditoria(sessao_usuario["username"], "INTEGRIDADE_DADOS", "ALERTA_CRITICO", f"HMAC inválido no Pet ID {pet_id}")
            return "DEFESA ATIVADA: ALERTA CRÍTICO! Adulteração de dados detetada na base de dados."

    return "Registro não encontrado."

if __name__ == "__main__":
    inicializar_banco_dados()
    print("=========================================================")
    print("      PETSYS - SISTEMA DE GESTÃO & CIBERSEGURANÇA       ")
    print("=========================================================\n")

    # TESTE 1: Login de Médica Veterinária e Acesso Concedido
    print("--- TESTE 1: Acesso de Médica Veterinária (Perfil Autorizado) ---")
    user_vet, msg = autenticar_utilizador("dra_carla", "VetSenha2026!")
    print(f"Status Login: {msg}")
    if user_vet:
        print(consultar_prontuario_rbac(user_vet, 1))

    # TESTE 2: Tentativa de Acesso por Administrador de TI (Bloqueado por PoLP)
    print("\n---------------------------------------------------------")
    print("--- TESTE 2: Acesso de Administrador de TI (Bloqueado por PoLP) ---")
    user_admin, msg = autenticar_utilizador("admin_ti", "AdminPass2026!")
    print(f"Status Login: {msg}")
    if user_admin:
        print(consultar_prontuario_rbac(user_admin, 1))

    # TESTE 3: Ataque de Força Bruta e Account Lockout (5 falhas)
    print("\n---------------------------------------------------------")
    print("--- TESTE 3: Bateria de Força Bruta (5 Tentativas Incorretas) ---")
    for i in range(1, 6):
        _, res_msg = autenticar_utilizador("atendente_ana", f"SenhaErrada{i}")
        print(f"Tentativa {i}: {res_msg}")

    # Tentativa extra durante lockout
    _, res_lockout = autenticar_utilizador("atendente_ana", "SenhaAna2026!")
    print(f"Tentativa 6 (Senha correta durante lockout): {res_lockout}")
