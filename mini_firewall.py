import time

# Configurações de Defesa
ARQUIVO_LOG = "06_defesa/registro_acesso.log"
LIMITE_TENTATIVAS = 3  # Quantos erros permitimos antes do bloqueio

def analisar_e_bloquear():
    print("--- INICIANDO DEFESA ATIVA (NÍVEL 1) ---")
    print(f"[*] Analisando o arquivo de histórico: {ARQUIVO_LOG}")
    print(f"[*] Limite de tolerância: {LIMITE_TENTATIVAS} erros de login.\n")
    
    # Dicionário para contar quantos erros cada IP cometeu
    contador_erros = {}
    # Lista para salvar os IPs que serão banidos pelo firewall
    lista_negra = []
    
    try:
        with open(ARQUIVO_LOG, "r") as f:
            for linha in f:
                # Limpa a linha e separa o IP do status do login
                partes = linha.strip().split(" - ")
                if len(partes) != 2:
                    continue
                    
                ip, status = partes[0], partes[1]
                
                # Se o status for de erro, contamos no nosso sistema
                if status == "LOGIN_ERRO":
                    contador_erros[ip] = contador_erros.get(ip, 0) + 1
                    print(f"[!] Erro detectado do IP {ip} (Total atual: {contador_erros[ip]})")
                    
                    # Se o IP passar do limite tolerado, ele entra na lista negra
                    if contador_erros[ip] >= LIMITE_TENTATIVAS and ip not in lista_negra:
                        lista_negra.append(ip)
                        print(f"🚨 [BLOQUEIO INTERNO] O IP {ip} estourou o limite e foi banido pelo Firewall!")
                        
        print("\n---------------------------------")
        print("[🔒 RELATÓRIO FINAL DO FIREWALL]")
        print(f"IPs Ativos Bloqueados: {lista_negra}")
        print("---------------------------------")
        
    except FileNotFoundError:
        print(f"[❌ ERRO] O arquivo {ARQUIVO_LOG} não foi encontrado!")

if __name__ == "__main__":
    analisar_e_bloquear()
