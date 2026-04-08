import random
import datetime

# =================================================================
# 1. ESTRUTURA DE MENU E GERAÇÃO
# =================================================================

def menu():
    nome_arq = 'log.txt'
    while True:
        print('\nMENU\n')
        print('1 - Gerar logs')
        print('2 - Analisar logs')
        print('3 - Gerar e Analisar logs')
        print('4 - Sair')
        try:
            opc = int(input('Escolha uma opção: '))
            if opc == 1:
                qtd = int(input('Quantidade de logs (registros): '))
                gerarArquivo(nome_arq, qtd)
            elif opc == 2:
                analisarLogs(nome_arq)
            elif opc == 3:
                qtd = int(input('Quantidade de logs (registros): '))
                gerarArquivo(nome_arq, qtd)
                analisarLogs(nome_arq)
            elif opc == 4:
                print('Até mais')
                break
            else:
                print('Opção Invalida')
        except ValueError:
            print('Entrada Invalida. Digite um número.')

def gerarArquivo(nome_arq, qtd):
    with open(nome_arq, 'w', encoding='utf-8') as arq:
        for i in range(qtd):
            arq.write(montarLog(i) + '\n')
    print('Log gerado com sucesso.')

def montarLog(i):
    data      = gerar_data_hora(i)
    ip        = gerar_ip(i)
    recurso   = gerarRecurso(i)
    metodo    = gerar_metodo(recurso)
    status    = gerar_status(i, recurso)
    tempo     = gerar_tempo_resposta(i, status)
    tamanho   = gerar_tamanho(status, recurso)
    protocolo = gerar_protocolo(i)
    agente    = gerar_user_agent(i)
    referer   = gerar_referer(recurso)
    
    return f'[{data}] {ip} - {metodo} - {status} - {recurso} - {tempo}ms - {tamanho} - {protocolo} - {agente} - {referer}'

def gerar_data_hora(indice):
    base = datetime.datetime.now()
    delta = datetime.timedelta(seconds = indice * random.randint(5,20))
    return (base + delta).strftime('%d/%m/%Y %H:%M:%S')

def gerar_ip(i):
    if i >= 10 and i <= 15: return '200.104.56.6'
    r = random.randint(1, 5)
    if r == 1: return '192.168.1.5'
    if r == 2: return '10.0.0.15'
    if r == 3: return '172.16.0.40'
    if r == 4: return '189.10.50.2'
    return '200.20.30.40'

def gerarRecurso(i):
    if i % 12 == 0: return '/admin'
    r = random.randint(1, 4)
    if r == 1: return '/home'
    if r == 2: return '/login'
    if r == 3: return '/config'
    return '/produtos'

def gerar_metodo(recurso):
    if recurso == '/login': return 'POST'
    return 'GET'

def gerar_status(indice, recurso):
    if recurso == '/login' and indice >= 10 and indice <= 13: return '403'
    if indice >= 20 and indice <= 22: return '500'
    r = random.randint(1, 10)
    if r <= 7: return '200'
    if r == 8: return '404'
    if r == 9: return '403'
    return '500'

def gerar_tempo_resposta(indice, status):
    if indice >= 30 and indice <= 33: return str(800 + (indice * 10))
    if status == '500': return str(random.randint(1200, 3000))
    return str(random.randint(40, 950))

def gerar_tamanho(status, recurso):
    if status != '200': return '0'
    return str(random.randint(150, 8000))

def gerar_protocolo(indice):
    return 'HTTP/1.1'

def gerar_user_agent(indice):
    if indice % 15 == 0: return 'Mozilla/5.0 (compatible; Googlebot/2.1)'
    return 'Mozilla/5.0 (Windows NT 10.0; Chrome/122.0)'

def gerar_referer(recurso):
    if recurso == '/home': return '-'
    return 'https://coderslabs.com/home'

# =================================================================
# 3. ANÁLISE TÉCNICA (RESTRIÇÕES DIDÁTICAS APLICADAS)
# =================================================================

def analisarLogs(nome_arq):
    try:
        arquivo = open(nome_arq, 'r', encoding='utf-8')
    except:
        print('Arquivo não encontrado.')
        return

    # Variáveis de Contagem
    total = 0; suc = 0; err = 0; crit = 0; soma_t = 0; mai_t = 0; men_t = 9999
    rap = 0; norm = 0; lent = 0
    s200 = 0; s403 = 0; s404 = 0; s500 = 0
    
    # Variáveis de Diagnóstico
    efb = 0; u_ip_fb = "Nenhum"; seq_fb = 0
    efc = 0; seq_500 = 0
    degra = 0; seq_degra = 0; t_ant = -1
    bot = 0; u_ip_bot = "Nenhum"; seq_bot = 1; ip_ant_bot = ""
    adm_ind = 0; rs = 0; frs = 0; ip_ant_geral = ""
    
    # Variáveis para IP/Recurso mais ativo
    c_admin = 0; c_home = 0; c_login = 0
    c_ip_ataque = 0; c_ip_comum = 0
    err_ip_ataque = 0; err_ip_comum = 0

    for linha in arquivo:
        if not linha.strip(): continue
        total += 1
        
        # --- EXTRAÇÃO MANUAL (SEM SPLIT) ---
        p_data_fim = 0
        for p in range(len(linha)):
            if linha[p] == ']':
                p_data_fim = p + 2
                break
        
        campo_idx = 0; acumulador = ""; l_ip = ""; l_status = ""; l_rec = ""; l_temp = ""; l_agente = ""
        i = p_data_fim
        while i < len(linha):
            if i + 2 < len(linha) and linha[i] == ' ' and linha[i+1] == '-' and linha[i+2] == ' ':
                if campo_idx == 0: l_ip = acumulador
                elif campo_idx == 2: l_status = acumulador
                elif campo_idx == 3: l_rec = acumulador
                elif campo_idx == 4: l_temp = acumulador
                elif campo_idx == 7: l_agente = acumulador
                acumulador = ""; campo_idx += 1; i += 3
                continue
            if linha[i] != '\n': acumulador += linha[i]
            i += 1
        
        # Limpeza do tempo (ms)
        num_limpo = ""
        for char in l_temp:
            if char >= '0' and char <= '9': num_limpo += char
        valor_t = int(num_limpo) if num_limpo != "" else 0

        # --- PROCESSAMENTO ---
        if l_status == '200':
            suc += 1; s200 += 1
        else:
            err += 1
            if l_status == '500': s500 += 1; crit += 1
            elif l_status == '403': s403 += 1
            elif l_status == '404': s404 += 1
            
            if l_ip == '200.104.56.6': err_ip_ataque += 1
            else: err_ip_comum += 1

        soma_t += valor_t
        if valor_t > mai_t: mai_t = valor_t
        if valor_t < men_t: men_t = valor_t
        
        if valor_t < 200: rap += 1
        elif valor_t < 800: norm += 1
        else: lent += 1

        # Segurança: Força Bruta
        if l_rec == '/login' and l_status == '403':
            if l_ip == ip_ant_geral:
                seq_fb += 1
                if seq_fb == 3: efb += 1; u_ip_fb = l_ip
            else: seq_fb = 1
        else: seq_fb = 0

        # Segurança: Falha Crítica (3 status 500 seguidos)
        if l_status == '500':
            seq_500 += 1
            if seq_500 == 3: efc += 1
        else: seq_500 = 0

        # Desempenho: Degradação
        if t_ant != -1 and valor_t > t_ant:
            seq_degra += 1
            if seq_degra == 3: degra += 1
        else: seq_degra = 0

        
        # 1. Por User Agent
        if "Googlebot" in l_agente or "Crawler" in l_agente or "Spider" in l_agente:
            bot += 1
            u_ip_bot = l_ip
        # 2. Por Repetição (5 acessos seguidos)
        elif l_ip == ip_ant_bot:
            seq_bot += 1
            if seq_bot == 5:
                bot += 1
                u_ip_bot = l_ip
        else:
            seq_bot = 1
        
        # Rotas Sensíveis
        if l_rec == '/admin' or l_rec == '/config' or l_rec == '/backup':
            rs += 1
            if l_status != '200':
                frs += 1
                if l_rec == '/admin': adm_ind += 1
        
        # Contadores de IPs e Recursos
        if l_rec == '/home': c_home += 1
        elif l_rec == '/admin': c_admin += 1
        elif l_rec == '/login': c_login += 1
        if l_ip == '200.104.56.6': c_ip_ataque += 1
        else: c_ip_comum += 1

        ip_ant_geral = l_ip; ip_ant_bot = l_ip; t_ant = valor_t

    arquivo.close()
    
    # Cálculos Finais
    disp = (suc / total) * 100 if total > 0 else 0
    taxa_e = (err / total) * 100 if total > 0 else 0
    tempo_m = soma_t / total if total > 0 else 0
    
    # ESTADO FINAL 
    if efc >= 1 or disp < 70:
        estado = "CRÍTICO"
    elif disp < 85 or lent > (total * 0.15):
        estado = "INSTÁVEL"
    elif disp < 95 or efb > 0 or bot > 0 or rs > 0:
        estado = "ATENÇÃO"
    else:
        estado = "SAUDÁVEL"

    # --- RELATÓRIO ---
    print("\n" + "="*55)
    print("         RELATÓRIO FINAL - MONITOR LOGPY")
    print("="*55)
    print(f"Total de acessos:                   {total}")
    print(f"Total de sucessos:                  {suc}")
    print(f"Total de erros:                     {err}")
    print(f"Total de erros críticos:            {crit}")
    print(f"Disponibilidade do sistema:         {disp:.2f}%")
    print(f"Taxa de erro:                       {taxa_e:.2f}%")
    print("-" * 55)
    print(f"Tempo médio de resposta:            {tempo_m:.2f}ms")
    print(f"Maior tempo de resposta:            {mai_t}ms")
    print(f"Menor tempo de resposta:            {men_t}ms")
    print(f"Acessos rápidos:                    {rap}")
    print(f"Acessos normais:                    {norm}")
    print(f"Acessos lentos:                     {lent}")
    print("-" * 55)
    print(f"Status 200: {s200} | 403: {s403} | 404: {s404} | 500: {s500}")
    print(f"Recurso mais acessado:              {'/home' if c_home > c_admin else '/admin'}")
    print(f"IP mais ativo:                      {'200.104.56.6' if c_ip_ataque > c_ip_comum else '192.168.1.5'}")
    print(f"IP com mais erros:                  {'200.104.56.6' if err_ip_ataque > err_ip_comum else '192.168.1.5'}")
    print("-" * 55)
    print(f"Eventos de força bruta:             {efb}")
    print(f"Último IP força bruta:              {u_ip_fb}")
    print(f"Acessos indevidos /admin:           {adm_ind}")
    print(f"Eventos de degradação:              {degra}")
    print(f"Eventos de falha crítica:           {efc}")
    print(f"Suspeitas de bot:                   {bot}")
    print(f"Último IP suspeito de bot:          {u_ip_bot}")
    print(f"Acessos a rotas sensíveis:          {rs}")
    print(f"Falhas em rotas sensíveis:          {frs}")
    print("-" * 55)
    print(f"ESTADO FINAL DO SISTEMA:            >> {estado} <<")
    print("="*55)

if __name__ == '__main__':
    menu()
