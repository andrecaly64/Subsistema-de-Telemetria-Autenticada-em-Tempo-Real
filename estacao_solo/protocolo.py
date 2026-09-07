from dataclasses import dataclass
from typing import Final

# Constantes de alinhamento e sincronismo do protocolo
MAGIC_WORD: Final[int] = 0xEB90        # Preâmbulo de sincronismo (2 bytes)
HEADER_SIZE: Final[int] = 8            # Tamanho do cabeçalho (8 bytes)
PAYLOAD_SIZE: Final[int] = 14          # Tamanho do payload (14 bytes)
HMAC_SIZE: Final[int] = 16             # Tamanho do HMAC (16 bytes / 128 bits)
FRAME_SIZE: Final[int] = HEADER_SIZE +PAYLOAD_SIZE + HMAC_SIZE       # Tamanho total do quadro 38 bytes

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

