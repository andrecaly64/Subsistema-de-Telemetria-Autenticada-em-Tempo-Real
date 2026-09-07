from dataclasses import dataclass
from typing import Final
import struct

"""
Modulo de definicao do protocolo de telemetria segura
Representacao da estrutura binaria de dados transmitida pelo esp32
"""

# Constantes de alinhamento e sincronismo do protocolo
MAGIC_WORD: Final[int] = 0xEB90        # Preâmbulo de sincronismo (2 bytes)
HEADER_SIZE: Final[int] = 8            # Tamanho do cabeçalho (8 bytes)
PAYLOAD_SIZE: Final[int] = 14          # Tamanho do payload (14 bytes)
HMAC_SIZE: Final[int] = 16             # Tamanho do HMAC (16 bytes / 128 bits)
FRAME_SIZE: Final[int] = HEADER_SIZE +PAYLOAD_SIZE + HMAC_SIZE       # Tamanho total do quadro 38 bytes

#formato binario little-endian (<) sem pdding de alinhamento:
#H = uint16 (2B), I = uint32 (4B), h = int16 (2B), 16s = 16 bytes
FRAME_FORMAT: Final[str] = "<HHIIhhhhhhH16s"
HEADER_PAYLOAD_FORMAT: Final[str] = "<HHIIhhhhhhH"


@dataclass(slots=True)
class TelemetryFrame:

    """ 
    Representacao tipica do frame binario de telemetria (38 bytes).
    
    Header (8 bytes):
        magic_word: uint16 (deve ser 0xEB90)
        sequence_id: uint16 (contador monotonico anti-replay)
        timestamp: uint32 (tempo de operacao do no em ms)
        
    payload inercial (14 bytes):
        accel_x: int16 (aceleracao bruta no eixo x)
        accel_y: int16 (aceleracao bruta no eixo y)
        accel_z: int16 (aceleracao bruta no eixo z)
        gyro_x: int16 (velocidade angular bruta no eixo x)
        gyro_y: int16 (velocidade angular bruta no eixo y)
        gyro_z: int16 (velocidade angular bruta no eixo z)
        status_flags: uint16 (flags de integridade e estado do no)
        
    Footer de seguranca (16 bytes):
        hmac_tag: bytes (resumo criptografico calculado sobre header + payload)    
    """

    magic_word: int
    sequence_id: int
    timestamp: int
    accel_x: int
    accel_y: int
    accel_z: int
    gyro_x: int
    gyro_y: int
    gyro_z: int
    status_flags: int
    hmac_tag: bytes = b"\x00" * HMAC_SIZE

    def is_valid_magic(self) -> bool:
        """Verifica se o identificador inicial corresponde ao padrao do protocolo."""
        return self.magic_word == MAGIC_WORD

def pack_frame(frame: TelemetryFrame) -> bytes:
    """
    Serializa a instacia de TelemetryFrame em uma sequencia de 38 bytes binarios.
    """

    if len(frame.hmac_tag) != HMAC_SIZE:
        raise ValueError(f"Tamanho de hmac_tag invalido: esperado {HMAC_SIZE} bytes, recebido {len(frame.hmac_tag)}. ")

    return struct.pack(
        FRAME_FORMAT,
        frame.magic_word,
        frame.sequence_id,
        frame.timestamp_ms,
        frame.accel_x,
        frame.accel_y,
        frame.accel_z,
        frame.gyro_x,
        frame.gyro_y,
        frame.gyro_z,
        frame.status_flags,
        frame.hmac_tag,
    )

def pack_authenticated_payload(frame: TelemetryFrame) -> bytes:
    """
    Serializa apenas o header + payload (22 bytes) que servem de entrada para o calculo do HMAC.
    """

    return struct.pack(
        HEADER_PAYLOAD_FORMAT,
        frame.magic_word,
        frame.sequence_id,
        frame.timestamp_ms,
        frame.accel_x,
        frame.accel_y,
        frame.accel_z,
        frame.gyro_x,
        frame.gyro_y,
        frame.gyro_z,
        frame.status_flags,
    )