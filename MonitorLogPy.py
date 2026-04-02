import random
import datetime

def menu():
    nome_arq = 'log.txt'
    while True:
        print('MENU\n')
        print('1 - Gerar logs')
        print('2 - Analisar logs')
        print('3 - Gerar e Analisar logs')
        print('4 - Sair')
        opc = int(input('Escolha uma opção: '))
        if opc == 1:
            try: 
                qtd = int(input('Quantidade de logs (registros): '))
                gerarArquivo(nome_arq, qtd)
            except:
                print('Entrada Invalida.')
        elif opc == 2:
            analisarLogs(nome_arq)
        
        elif opc == 3:
           try: 
                qtd = int(input('Quantidade de logs (registros): '))
                gerarArquivo(nome_arq, qtd)
                analisarLogs(nome_arq)
           except:
                print('Entrada Invalida.')
        elif opc == 4:
            print('Até mais')
            break
        else:
            print('Opção Invalida')

def gerarArquivo(nome_arq, atd):
    with open(nome_arq, 'w', encoding='utf-8') as arq:
        for i in range(qtd):
            arq.write(montarLog(i) + '\n')
    print('Log gerado')

def montarLog(i):
    data    = gerarData(i)
    ip      = gerarIp(i)
    recurso = gerarRecurso(i)
    metodo  = gerarMetodo(i)
    status  = gerarStatus(i)
    tempo   = gerarTempo(i)
    agente  = gerarAgente(i)
    protocolo = gerarProtocolo(i)
    tamanho = gerarTamanho(i)
    return f'[{data}] {ip} - {metodo} - {status} - {recurso} - {tempo}ms - {tamanho} - {protocolo} - {agente} - /home'

def gerarData(i):
    base = datetime.datetime.now()
    delta = datetime.timedelta(seconds = i * random.randint(5,20))
    return {base + delta}.strftime('%d/%m/%Y %H:%M:%S')

def gerarIp(i):
    r = random.randint(1,6)
    if i  >= 20 and i <= 50:
        return '200.104.56.6'
    
    if r == 1:
        return '192.187.56.7'
    elif r == 2:
        return '192.100.40.3'
    elif r == 3:
        return '192.101.40.5'
    elif r == 4:
        return '192.103.40.0'
    elif r == 5:
        return '192.101.40.9'
    elif r == 6:
        return '192.101.40.8'
    

menu()