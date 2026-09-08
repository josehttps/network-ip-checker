from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from dotenv import load_dotenv
import subprocess
import ipaddress
import re
import time
import socket
import os

load_dotenv()

app = FastAPI()


PORTAS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    9100: "Impressão"
}


REDE_PERMITIDA = ipaddress.ip_network(
    os.getenv("NETWORK_CIDR", "192.168.1.0/24")
)


# Rate limiting
LIMITE_REQUISICOES = 30
JANELA_RATE_LIMIT = 60

requisicoes = {}


def ip_permitido(valor: str) -> bool:
    try:
        ip = ipaddress.ip_address(valor)
    except ValueError:
        return False

    return (
        ip.version == 4
        and ip in REDE_PERMITIDA
        and ip not in (
            REDE_PERMITIDA.network_address,
            REDE_PERMITIDA.broadcast_address
        )
    )


def verificar_rate_limit(ip_origem: str) -> bool:
    agora = time.time()

    if ip_origem not in requisicoes:
        requisicoes[ip_origem] = []

    # Remove registros com mais de 60 segundos
    requisicoes[ip_origem] = [
        momento
        for momento in requisicoes[ip_origem]
        if agora - momento < JANELA_RATE_LIMIT
    ]

    # Verifica se atingiu o limite
    if len(requisicoes[ip_origem]) >= LIMITE_REQUISICOES:
        return False

    # Registra a nova requisição
    requisicoes[ip_origem].append(agora)

    return True


def testar_porta(ip, porta):
    try:
        resultado = subprocess.run(
            ["nc", "-z", "-w", "1", ip, str(porta)],
            capture_output=True,
            timeout=2
        )

        return resultado.returncode == 0

    except subprocess.TimeoutExpired:
        return False


def descobrir_hostname(ip):
    hostname = "Não encontrado"

    # Tentativa 1: mDNS / Avahi
    try:
        resultado_hostname = subprocess.check_output(
            ["avahi-resolve-address", ip],
            text=True,
            timeout=2
        ).strip()

        partes = resultado_hostname.split()

        if len(partes) >= 2:
            hostname = partes[1]

    except (
        subprocess.CalledProcessError,
        IndexError,
        subprocess.TimeoutExpired
    ):
        pass

    # Tentativa 2: DNS reverso
    if hostname == "Não encontrado":
        try:
            hostname_dns = socket.gethostbyaddr(ip)[0]

            if hostname_dns:
                hostname = hostname_dns

        except (
            socket.herror,
            socket.gaierror,
            OSError
        ):
            pass

    return hostname


@app.get("/")
def inicio():
    return FileResponse("templates/index.html")


@app.get("/verificar/{ip}")
def verificar_ip(ip: str, request: Request):

    # Identificar IP de origem da requisição
    ip_origem = request.client.host

    # Rate limiting
    if not verificar_rate_limit(ip_origem):
        return {
            "ip": ip,
            "status": "LIMITE ATINGIDO",
            "mensagem": "Limite de consultas atingido. Aguarde alguns segundos e tente novamente."
        }

    # Validação do IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {
            "ip": ip,
            "status": "IP inválido"
        }

    # Verificação da rede permitida
    if not ip_permitido(ip):
        return {
            "ip": ip,
            "status": "IP não autorizado",
            "mensagem": "Apenas endereços da rede configurada podem ser consultados."
        }

    # Teste de ping
    resultado = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],
        capture_output=True,
        text=True
    )

    ping_online = resultado.returncode == 0

    # Descobrir hostname
    hostname = descobrir_hostname(ip)

    # Testar portas
    portas = {}

    for porta, nome in PORTAS.items():
        portas[porta] = {
            "servico": nome,
            "aberta": testar_porta(ip, porta)
        }

    # Verifica se pelo menos uma porta está aberta
    alguma_porta_aberta = any(
        dados["aberta"]
        for dados in portas.values()
    )

    # O equipamento está ONLINE se:
    # - o ping respondeu
    # OU
    # - alguma porta está aberta
    equipamento_online = ping_online or alguma_porta_aberta

    # Se o ping respondeu, tenta obter o tempo
    if ping_online:

        match = re.search(r"time[=<]([\d.]+)", resultado.stdout)

        if match:
            ping = float(match.group(1))
        else:
            ping = None

    else:
        ping = None

    return {
        "ip": ip,
        "status": "ONLINE" if equipamento_online else "OFFLINE",
        "ping_ms": ping,
        "hostname": hostname,
        "portas": portas
    }
