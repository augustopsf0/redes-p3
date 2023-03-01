from iputils import *
import ipaddress

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.contador = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        dest_addr = ipaddress.ip_address(dest_addr)

        for cidr, next_hop in self.tabela:
            if dest_addr in ipaddress.ip_network(cidr):
                return str(next_hop)
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento_tcp, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr) # para qual roteador será enviado o segmento

        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        # Enviar só é chamado pela camada de transporte, não pela própria camada de rede
        # Segmento é o pacote como ele foi montado quando ele passou somente pela camada de aplicação e transporte
        # Montar o cabeçalho IP na frente de 'segmento' , o que dará origem ao datagrama, que é o pacote enquanto ele se encontra na camada de rede

        # Somente campos obrigatórios (20 bytes de cabeçalho)
        # Version (4 bits, sempre será 4 pois é ipv4) e IHL (4 bits, tamanho sempre será 5) são o primeiro byte 
        # DSCP (6 bits) e ECN (2 bits) são 0 e são o segundo byte
        # Total Lenght (16 bits) é o tamanho do cabeçalho IP + o payload do protocolo IP (que é o segmento) equivale a 2 bytes, tamanho total será 20 bytes + o que veio da camada acima
        # Identification tem que ser diferente para cada pacote IP e tem 2 bytes, pode ser gerado por um contador

        # Passo 2 - Montar o cabeçalho IP
        versao = 4
        IHL = 5
        tipo_servico = 0
        comprimento_total = IHL*4 + len(segmento_tcp)
        identificacao = self.contador
        flags = 0
        offset = 0
        tempo_de_vida = 64
        protocolo = IPPROTO_TCP
        checksum = 0
        endereco_origem = str2addr(self.meu_endereco)
        endereco_destino = str2addr(dest_addr)
        cabecalho = struct.pack('!BBHHHBBH4s4s', (versao << 4) + IHL, tipo_servico, comprimento_total, identificacao, (flags << 13) + offset, tempo_de_vida, protocolo, checksum, endereco_origem, endereco_destino)
        # Calcular o checksum do cabeçalho IP
        checksum = calc_checksum(cabecalho)

        # Acrescentar o checksum ao cabeçalho e montar o datagrama IP
        cabecalho = struct.pack('!BBHHHBBH4s4s', (versao << 4) + IHL, tipo_servico, comprimento_total, identificacao, (flags << 13) + offset, tempo_de_vida, protocolo, checksum, endereco_origem, endereco_destino)
        self.contador += 1

        # Passo 2 - Enviar o datagrama IP para a camada de enlace
        self.enlace.enviar(cabecalho + segmento_tcp, next_hop)
