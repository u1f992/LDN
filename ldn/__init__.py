
from __future__ import annotations

from Crypto.Cipher import AES

from ldn import streams, wlan, queue, util
from netlink import route

from dataclasses import dataclass

import contextlib
import copy
import hashlib
import hmac
import os
import random
import secrets
import socket
import struct
import trio
import typing

import logging
logger = logging.getLogger(__name__)


MACAddress = wlan.MACAddress


# Station accept policy
ACCEPT_ALL = 0
ACCEPT_NONE = 1
ACCEPT_BLACKLIST = 2
ACCEPT_WHITELIST = 3

# Advertisement frame format
ADVERTISE_FORMAT_PLAIN = 1
ADVERTISE_FORMAT_AES_CTR = 2
ADVERTISE_FORMAT_AES_GCM = 3

# Authentication status code
AUTH_SUCCESS = 0
AUTH_DENIED_BY_POLICY = 1
AUTH_MALFORMED_REQUEST = 2
AUTH_TIMEOUT = 3
AUTH_INVALID_VERSION = 4
AUTH_UNEXPECTED = 5
AUTH_CHALLENGE_FAILURE = 6

# Authentication frame format
AUTH_FORMAT_PLAIN = 0
AUTH_FORMAT_AES_GCM = 1

# Disconnect reason
DISCONNECT_NETWORK_DESTROYED = 3
DISCONNECT_NETWORK_DESTROYED_FORCEFULLY = 4
DISCONNECT_STATION_REJECTED_BY_HOST = 5
DISCONNECT_CONNECTION_LOST = 6

# Platform type
PLATFORM_NX = 0
PLATFORM_OUNCE = 1

# Security mode
SECURITY_MODE_PROD = 1 # Everything is encrypted
SECURITY_MODE_DEBUG = 2 # Advertisement frames are encrypted, data frames are not
SECURITY_MODE_SYSTEM_DEBUG = 3 # Neither advertisement nor data frames are encrypted


CHALLENGE_KEY = bytes.fromhex("f84b487fb37251c263bf11609036589266af70ca79b44c93c7370c5769c0f602")


ChannelBands = {
	1: 2,
	6: 2,
	11: 2,
	36: 5,
	40: 5,
	44: 5,
	48: 5,
}


def load_keys(path: str) -> dict[str, bytes]:
	path = os.path.expanduser(path)

	with open(path) as f:
		lines = f.readlines()

	keys = {}
	for line in lines:
		line = line.strip()
		if line:
			name, key = line.split("=")
			keys[name.strip()] = bytes.fromhex(key)
	return keys


class AuthenticationError(Exception):
	status_code: int

	def __init__(self, status_code: int):
		self.status_code = status_code
	
	def __str__(self):
		return f"Authentication failed with status {self.status_code}"


class KeyDerivation:
	_keys: dict[str, bytes]
	_protocol: int

	_override_advertise_key: bytes
	_override_data_key: bytes

	def __init__(self, keys: dict[str, bytes], protocol: int, *, override_advertise_key: bytes = None, override_data_key: bytes = None):
		self._keys = keys
		self._protocol = protocol

		self._override_advertise_key = override_advertise_key
		self._override_data_key = override_data_key
	
	def _decrypt_key(self, key: bytes, kek: bytes) -> bytes:
		aes = AES.new(kek, AES.MODE_ECB)
		return aes.decrypt(key)
	
	def _select_master_key(self) -> bytes:
		if self._protocol == 1:
			return self._keys["master_key_00"]
		elif self._protocol == 3:
			return self._keys["master_key_12"]
		raise ValueError(f"Key derivation for protocol version {self._protocol} is not supported")
	
	def _derive_key(self, data: bytes, source: bytes) -> bytes:
		aes_kek_generation_source = self._keys["aes_kek_generation_source"]
		aes_key_generation_source = self._keys["aes_key_generation_source"]

		key = self._select_master_key()
		key = self._decrypt_key(aes_kek_generation_source, key)
		key = self._decrypt_key(source, key)
		key = self._decrypt_key(aes_key_generation_source, key)
		return self._decrypt_key(hashlib.sha256(data).digest()[:16], key)
	
	def derive_authentication_key(self, client_random: bytes) -> bytes:
		source = bytes.fromhex("f1e7018419a84f711da714c2cf919c9c")
		return self._derive_key(client_random, source)
	
	def derive_data_key(self, server_random: bytes, password: bytes) -> bytes:
		source = bytes.fromhex("f1e7018419a84f711da714c2cf919c9c")
		return self._derive_key(server_random + password, source)
	
	def derive_advertise_key(self, data: bytes) -> bytes:
		source = bytes.fromhex("191884743e24c77d87c69e4207d0c438")
		return self._derive_key(data, source)


class NetworkId:
	"""
	A 32-byte struct that contains the local communication id, game mode and SSID of the network.
	"""

	local_communication_id: int
	scene_id: int
	ssid: bytes

	def __init__(self):
		self.local_communication_id = None
		self.scene_id = None
		self.ssid = None
	
	def encode(self, endianness: str) -> bytes:
		stream = streams.StreamOut(endianness)
		stream.u64(self.local_communication_id)
		stream.pad(2)
		stream.u16(self.scene_id)
		stream.pad(4)
		stream.write(self.ssid)
		return stream.get()
	
	def decode(self, data: bytes, endianness: str) -> None:
		stream = streams.StreamIn(data, endianness)
		self.local_communication_id = stream.u64()
		stream.pad(2)
		self.scene_id = stream.u16()
		stream.pad(4)
		self.ssid = stream.read(16)


class ParticipantInfo:
	"""
	Holds information about a network node
	"""

	ip_address: str
	mac_address: MACAddress
	connected: bool
	name: bytes
	app_version: int
	platform: int

	def __init__(self):
		self.ip_address = "0.0.0.0"
		self.mac_address = MACAddress()
		self.connected = False
		self.name = b""
		self.app_version = 0
		self.platform = PLATFORM_NX


class AdvertisementInfo:
	server_random: bytes
	security_mode: int
	station_accept_policy: int

	app_version: int

	band: int
	channel: int

	max_participants: int
	num_participants: int
	participants: list[ParticipantInfo]
	application_data: bytes

	challenge: int

	def __init__(self):
		self.server_random = None
		self.security_mode = None
		self.station_accept_policy = None

		self.app_version = None

		# Band and channel were added in 20.0.0
		self.band = None
		self.channel = None

		self.max_participants = None
		self.num_participants = None
		self.participants = None
		self.application_data = None

		# The challenge was added in 6.0.0
		self.challenge = None


class AdvertisementInfoEncoder(typing.Protocol):
	def encode(self, info: AdvertisementInfo) -> bytes:
		...
	
	def decode(self, data: bytes) -> AdvertisementInfo:
		...


class AdvertisementInfoEncoderV1:
	"""
	Advertisement encoder when AES-CTR or plaintext encryption is used
	"""

	def encode(self, info: AdvertisementInfo) -> bytes:
		stream = streams.StreamOut(">")
		stream.write(info.server_random)
		stream.u16(info.security_mode)
		stream.u8(info.station_accept_policy)
		stream.pad(1)
		stream.u16((info.band << 10) | info.channel)
		stream.u8(info.max_participants)
		stream.u8(info.num_participants)

		for participant in info.participants:
			name = participant.name
			stream.write(socket.inet_aton(participant.ip_address))
			stream.write(participant.mac_address.encode())
			stream.bool(participant.connected)
			stream.u8(participant.platform)
			stream.write(name + b"\0" * (32 - len(name)))
			stream.u16(participant.app_version)
			stream.pad(10)
		
		stream.pad(2)
		stream.u16(len(info.application_data))
		stream.write(info.application_data + b"\0" * (384 - len(info.application_data)))
		stream.pad(412)
		stream.u64(info.challenge)
		return stream.get()
	
	def decode(self, data: bytes) -> AdvertisementInfo:
		stream = streams.StreamIn(data, ">")

		info = AdvertisementInfo()
		info.server_random = stream.read(16)
		info.security_mode = stream.u16()
		info.station_accept_policy = stream.u8()
		stream.pad(1)

		value = stream.u16()
		info.band = value >> 10
		info.channel = value & 0x3FF

		info.max_participants = stream.u8()
		info.num_participants = stream.u8()
		
		info.participants = []
		for i in range(8):
			participant = ParticipantInfo()
			participant.ip_address = socket.inet_ntoa(stream.read(4))
			participant.mac_address = MACAddress(stream.read(6))
			participant.connected = stream.bool()
			participant.platform = stream.u8()
			participant.name = stream.read(32).rstrip(b"\0")
			participant.app_version = stream.u16()
			stream.pad(10)
			info.participants.append(participant)
		
		info.app_version = info.participants[0].app_version
		
		stream.pad(2)
		
		beacon_size = stream.u16()
		beacon_data = stream.read(384)
		info.application_data = beacon_data[:beacon_size]
		
		stream.pad(412)
		
		info.challenge = stream.u64()
		return info


class AdvertisementInfoEncoderV2:
	"""
	Advertisement encoder when AES-GCM encryption is used
	"""

	def encode(self, info: AdvertisementInfo) -> bytes:
		stream = streams.StreamOut(">")
		stream.write(info.server_random)
		stream.u64(info.challenge)
		stream.u8(info.security_mode)
		stream.u8(info.station_accept_policy)
		stream.u16(info.app_version)
		stream.pad(8)
		stream.u16((info.band << 10) | info.channel)
		stream.u8(info.max_participants)
		stream.u8(info.num_participants)

		for index, participant in enumerate(info.participants):
			if participant.connected:
				name = participant.name
				stream.write(socket.inet_aton(participant.ip_address))
				stream.write(participant.mac_address.encode())
				stream.u8(index)
				stream.u8(participant.platform)
				stream.write(name + b"\0" * (32 - len(name)))
				stream.pad(4)
		
		stream.u16(len(info.application_data))
		stream.write(info.application_data)
		return stream.get()
	
	def decode(self, data: bytes) -> AdvertisementInfo:
		stream = streams.StreamIn(data, ">")

		info = AdvertisementInfo()
		info.server_random = stream.read(16)
		info.challenge = stream.u64()
		info.security_mode = stream.u8()
		info.station_accept_policy = stream.u8()
		info.app_version = stream.u16()
		stream.pad(8)
		
		value = stream.u16()
		info.band = value >> 10
		info.channel = value & 0x3FF

		info.max_participants = stream.u8()
		info.num_participants = stream.u8()
		
		info.participants = [ParticipantInfo() for i in range(8)]
		for i in range(info.num_participants):
			participant = ParticipantInfo()
			participant.ip_address = socket.inet_ntoa(stream.read(4))
			participant.mac_address = MACAddress(stream.read(6))
			index = stream.u8()
			participant.platform = stream.u8()
			participant.name = stream.read(32).rstrip(b"\0")
			stream.pad(4)

			participant.connected = True
			participant.app_version = info.app_version

			if index < len(info.participants):
				info.participants[index] = participant
		
		info.application_data = stream.read(stream.u16())
		return info


class AdvertisementFrame:
	_key_derivation: KeyDerivation
	_protocol: int

	network_id: NetworkId
	version: int
	format: int
	nonce: bytes
	payload: AdvertisementInfo

	def __init__(self, key_derivation: KeyDerivation, protocol: int):
		self._key_derivation = key_derivation
		self._protocol = protocol

		self.network_id = None
		self.version = None
		self.format = None
		self.nonce = None
		self.payload = None

	def _derive_key(self):
		return self._key_derivation.derive_advertise_key(self.network_id.encode(">"))
	
	def _encrypt_aes_ctr(self, payload: bytes) -> bytes:
		key = self._derive_key()
		aes = AES.new(key, AES.MODE_CTR, nonce=self.nonce)
		return aes.encrypt(payload)
	
	def _encrypt_aes_gcm(self, header: bytes, payload: bytes) -> bytes:
		key = self._derive_key()
		nonce = self.nonce + bytes(8)
		aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
		aes.update(header)
		payload, mac = aes.encrypt_and_digest(payload)
		return mac + payload
	
	def _decrypt_aes_ctr(self, payload: bytes) -> bytes:
		key = self._derive_key()
		aes = AES.new(key, AES.MODE_CTR, nonce=self.nonce)
		return aes.decrypt(payload)
	
	def _decrypt_aes_gcm(self, header: bytes, payload: bytes) -> bytes:
		key = self._derive_key()
		nonce = self.nonce + bytes(8)
		aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
		aes.update(header)
		return aes.decrypt_and_verify(payload[16:], payload[:16])
	
	def _make_payload_encoder(self) -> AdvertisementInfoEncoder:
		if self.format == ADVERTISE_FORMAT_AES_GCM:
			return AdvertisementInfoEncoderV2()
		return AdvertisementInfoEncoderV1()
	
	def encode(self) -> bytes:
		stream = streams.StreamOut(">")
		stream.u8(0x7F) # Vendor-specific
		stream.u24(0x0022AA) # Nintendo
		stream.u8(4) # LDN
		stream.pad(1)
		stream.u16(0x101) # Advertisement frame
		stream.pad(4)

		encoder = self._make_payload_encoder()
		plaintext = encoder.encode(self.payload)
		plaintext_len = len(plaintext)

		substream = streams.StreamOut(">")
		substream.write(self.network_id.encode(">"))
		substream.u8(self.version)
		substream.u8(self.format)
		substream.u16(plaintext_len)
		substream.write(self.nonce)
		header = substream.get()

		# A SHA-256 is added before the payload in plain and AES-CTR mode
		if self.format in [ADVERTISE_FORMAT_PLAIN, ADVERTISE_FORMAT_AES_CTR]:
			data = header + bytes(32) + plaintext
			sha = hashlib.sha256(data).digest()
			plaintext = sha + plaintext
		
		if self.format == ADVERTISE_FORMAT_PLAIN:
			ciphertext = plaintext
		elif self.format == ADVERTISE_FORMAT_AES_CTR:
			ciphertext = self._encrypt_aes_ctr(plaintext)
		elif self.format == ADVERTISE_FORMAT_AES_GCM:
			ciphertext = self._encrypt_aes_gcm(header, plaintext)
		else:
			raise ValueError("An invalid advertisement format was specified")
		
		stream.write(header)
		stream.write(ciphertext)
		return stream.get()
	
	def decode(self, data: bytes) -> None:
		stream = streams.StreamIn(data, ">")
		if stream.u8() != 0x7F:
			raise ValueError("Action frame is not vendor-specific")
		if stream.u24() != 0x0022AA:
			raise ValueError("Action frame has wrong OUI")
		
		if stream.u8() != 4:
			raise ValueError("Action frame is not for LDN")
		
		stream.pad(1)
		if stream.u16() != 0x101:
			raise ValueError("Action frame is not an advertisement frame")
		stream.pad(4)
		
		header = stream.peek(0x28)
		
		self.network_id = NetworkId()
		self.network_id.decode(stream.read(32), ">")
		
		self.version = stream.u8()
		if self.version not in [2, 3, 4]:
			raise ValueError("Advertisement frame has unsupported version number")
		
		self.format = stream.u8()
		if self.format not in [ADVERTISE_FORMAT_PLAIN, ADVERTISE_FORMAT_AES_CTR, ADVERTISE_FORMAT_AES_GCM]:
			raise ValueError("Advertisement frame has unsupported format")
		
		size = stream.u16()

		if self.format in [ADVERTISE_FORMAT_PLAIN, ADVERTISE_FORMAT_AES_CTR] and size != 0x500:
			raise ValueError("Advertisement frame has unexpected size field")
		
		self.nonce = stream.read(4)

		expected_format = ADVERTISE_FORMAT_AES_CTR if self._protocol == 1 else ADVERTISE_FORMAT_AES_GCM
		if self.format != ADVERTISE_FORMAT_PLAIN and self.format != expected_format:
			raise ValueError("Advertisement frame has invalid encryption algorithm for the current protocol")

		if self.format == ADVERTISE_FORMAT_PLAIN:
			plaintext = stream.read(32 + size)
		elif self.format == ADVERTISE_FORMAT_AES_CTR:
			plaintext = self._decrypt_aes_ctr(stream.read(32 + size))
		elif self.format == ADVERTISE_FORMAT_AES_GCM:
			plaintext = self._decrypt_aes_gcm(header, stream.read(16 + size))
		else:
			raise ValueError("Advertisement frame has invalid encryption algorithm")
		
		if self.format in [ADVERTISE_FORMAT_PLAIN, ADVERTISE_FORMAT_AES_CTR]:
			sha = plaintext[:32]
			plaintext = plaintext[32:]
			data = header + bytes(32) + plaintext
			if hashlib.sha256(data).digest() != sha:
				raise ValueError("Advertisement frame has wrong SHA-256 hash")

		encoder = self._make_payload_encoder()
		self.payload = encoder.decode(plaintext)
		
		
class ChallengeRequest:
	flags: int
	token: int
	nonce: int
	device_id: int
	unk: bytes
	params1: list[int]
	params2: list[int]

	def __init__(self):
		self.flags = None
		self.token = None
		self.nonce = None
		self.device_id = None

		self.unk = bytes(16) # Only set on S2.
		self.params1 = []
		self.params2 = []
	
	def encode(self) -> bytes:
		stream = streams.StreamOut("<")
		stream.u8(0) # Always 0
		stream.u8(0) # Always 0
		stream.u8(len(self.params1))
		stream.u8(len(self.params2))
		stream.u8(self.flags)
		stream.pad(3)
		
		stream.u64(self.token)
		stream.u64(self.nonce)
		stream.u64(self.device_id)
		stream.write(self.unk)

		stream.pad(0x60)
		
		stream.repeat(self.params1, stream.u64)
		stream.pad(8 * (8 - len(self.params1)))
		
		stream.repeat(self.params2, stream.u64)
		stream.pad(8 * (64 - len(self.params2)))
		
		body = stream.get()
		
		mac = hmac.digest(CHALLENGE_KEY, body, "sha256")
		
		stream = streams.StreamOut("<")
		stream.u32(0)
		stream.write(mac)
		stream.pad(12)
		stream.write(body)
		
		return stream.get()
	
	def decode(self, data: bytes) -> None:
		if len(data) != 0x300:
			raise ValueError("Challenge request has wrong size")
		
		stream = streams.StreamIn(data, "<")
		stream.pad(4)
		mac = stream.read(32)
		stream.pad(12)
		body = stream.read(0x2D0)
		
		if mac != hmac.digest(CHALLENGE_KEY, body, "sha256"):
			raise ValueError("Challenge request has wrong HMAC")
		
		stream = streams.StreamIn(body, "<")
		stream.pad(2)
		n1 = stream.u8()
		n2 = stream.u8()
		self.flags = stream.u8()
		stream.pad(3)
		
		self.token = stream.u64()
		self.nonce = stream.u64()
		self.device_id = stream.u64()
		self.unk = stream.read(16)
		
		stream.pad(0x60)
		
		self.params1 = stream.repeat(stream.u64, 8)[:n1]
		self.params2 = stream.repeat(stream.u64, 8)[:n2]


class ChallengeResponse:
	flags: int
	nonce: int
	device_id: int
	device_id_host: int
	unk: bytes
	unk_host: bytes

	def __init__(self):
		self.flags = None
		self.nonce = None
		self.device_id = None
		self.device_id_host = None
		self.unk = None
		self.unk_host = bytes(16)
	
	def encode(self) -> bytes:
		stream = streams.StreamOut("<")
		stream.u8(0) # Always 0
		stream.u8(0) # Always 0
		stream.pad(2)
		stream.u32(self.flags)
		stream.u64(self.nonce)
		stream.u64(self.device_id)
		stream.u64(self.device_id_host)
		stream.write(self.unk)
		stream.write(self.unk_host)
		stream.pad(0x90)
		
		body = stream.get()
	
		mac = hmac.digest(CHALLENGE_KEY, body, "sha256")
		
		stream = streams.StreamOut("<")
		stream.u32(0)
		stream.write(mac)
		stream.pad(12)
		stream.write(body)
		return stream.get()
	
	def decode(self, data: bytes) -> None:
		if len(data) != 0x100:
			raise ValueError("Challenge response has wrong size")
		
		stream = streams.StreamIn(data, "<")
		stream.pad(4)
		mac = stream.read(32)
		stream.pad(12)
		body = stream.read(0xD0)
		
		if mac != hmac.digest(CHALLENGE_KEY, body, "sha256"):
			raise ValueError("Challenge response has wrong HMAC")
		
		stream = streams.StreamIn(body, "<")
		stream.pad(4)
		self.flags = stream.u32()
		self.nonce = stream.u64()
		self.device_id = stream.u64()
		self.device_id_host = stream.u64()
		self.unk = stream.read(16)
		self.unk_host = stream.read(16)
		stream.pad(0x90)


class AuthenticationRequest:
	username: bytes
	app_version: int
	platform: int
	challenge: bytes

	def __init__(self):
		self.username = None
		self.app_version = None
		self.platform = None
		self.challenge = None
	
	def encode(self, version: int) -> bytes:
		stream = streams.StreamOut(">")
		
		name = self.username
		stream.write(name + b"\0" * (32 - len(name)))
		stream.u16(self.app_version)
		stream.u8(self.platform)
		stream.pad(29)
		
		if version >= 3:
			stream.pad(0x24)
			if self.challenge is not None:
				stream.write(self.challenge)
		return stream.get()
	
	def decode(self, data: bytes, version: int) -> None:
		stream = streams.StreamIn(data, ">")
		
		self.username = stream.read(32).rstrip(b"\0")
		self.app_version = stream.u16()
		self.platform = stream.u8()
		stream.pad(29)
		
		if version >= 3:
			stream.pad(0x24)
			if not stream.eof():
				self.challenge = stream.read(0x300)


class AuthenticationResponse:
	platform: int
	challenge: bytes

	def __init__(self):
		self.platform = None
		self.challenge = None
	
	def encode(self, version: int) -> bytes:
		stream = streams.StreamOut(">")
		if version >= 3:
			stream.u8(self.platform)
			stream.pad(0x83)
			if self.challenge is not None:
				stream.write(self.challenge)
		return stream.get()
	
	def decode(self, data: bytes, version: int) -> None:
		stream = streams.StreamIn(data, ">")
		if version >= 3:
			self.platform = stream.u8()
			stream.pad(0x83)
			if not stream.eof():
				self.challenge = stream.read(0x100)


class AuthenticationFrame:
	version: int
	status_code: int
	network_id: NetworkId
	server_random: bytes
	client_random: bytes
	payload: AuthenticationRequest | AuthenticationResponse

	_key_derivation: KeyDerivation
	_protocol: int

	def __init__(self, key_derivation: KeyDerivation, protocol: int):
		self._key_derivation = key_derivation
		self._protocol = protocol

		self.version = None
		self.status_code = None
		self.network_id = None
		self.server_random = None
		self.client_random = None
		self.payload = None

	def _encrypt_aes_gcm(self, header: bytes, payload: bytes) -> bytes:
		key = self._key_derivation.derive_authentication_key(self.client_random)

		aes = AES.new(key, AES.MODE_GCM, nonce=header[:12])
		aes.update(header)

		return aes.encrypt_and_digest(payload)

	def _decrypt_aes_gcm(self, header: bytes, payload: bytes, tag: bytes) -> bytes:
		key = self._key_derivation.derive_authentication_key(self.client_random)

		aes = AES.new(key, AES.MODE_GCM, nonce=header[:12])
		aes.update(header)

		return aes.decrypt_and_verify(payload, tag)
	
	def _expected_format(self) -> int:
		if self._protocol == 1:
			return AUTH_FORMAT_PLAIN
		return AUTH_FORMAT_AES_GCM

	def encode(self) -> bytes:
		payload = self.payload.encode(self.version)
		
		stream = streams.StreamOut(">")
		stream.u24(0x0022AA) # Nintendo
		stream.u16(0x102) # Authentication frame
		stream.pad(1)

		substream = streams.StreamOut(">")
		substream.u8(self.version)
		substream.u8(len(payload) & 0xFF)
		substream.u8(self.status_code)
		substream.u8(isinstance(self.payload, AuthenticationResponse))
		substream.u8(len(payload) >> 8)
		substream.u8(self._expected_format())
		substream.pad(2)
		
		substream.write(self.network_id.encode("<"))
		substream.write(self.server_random)
		substream.write(self.client_random)

		header = substream.get()
		stream.write(header)

		if self._protocol == 3:
			payload, tag = self._encrypt_aes_gcm(header, payload)
			stream.write(tag)

		stream.write(payload)
		return stream.get()
	
	def decode(self, data: bytes) -> None:
		stream = streams.StreamIn(data, ">")
		if stream.u24() != 0x0022AA:
			raise ValueError("Data frame has wrong OUI")
		if stream.u16() != 0x102:
			raise ValueError("Data frame is not an authentication frame")
		stream.pad(1)

		header = stream.peek(0x48)

		self.version = stream.u8()
		size_lo = stream.u8()
		self.status_code = stream.u8()
		is_response = stream.u8()
		size_hi = stream.u8()
		format = stream.u8()
		stream.pad(2)

		if format != self._expected_format():
			raise ValueError("Authentication frame has wrong format for the current protocol")

		self.network_id = NetworkId()
		self.network_id.decode(stream.read(32), "<")

		self.server_random = stream.read(16)
		self.client_random = stream.read(16)

		tag = None
		if format == AUTH_FORMAT_AES_GCM:
			tag = stream.read(16)

		size = (size_hi << 8) | size_lo
		if stream.available() != size:
			raise ValueError("Authentication frame has wrong size")
		
		if is_response:
			self.payload = AuthenticationResponse()
		else:
			self.payload = AuthenticationRequest()

		data = stream.read(size)
		if format == AUTH_FORMAT_AES_GCM:
			data = self._decrypt_aes_gcm(header, data, tag)
		
		self.payload.decode(data, self.version)


class DisconnectFrame:
	reason: int

	def __init__(self):
		self.reason = None
	
	def encode(self) -> bytes:
		stream = streams.StreamOut(">")
		stream.u24(0x0022AA) # Nintendo
		stream.u16(0x103) # Disconnect frame
		stream.pad(1)
		
		stream.u8(self.reason)
		stream.pad(31)
		return stream.get()
	
	def decode(self, data: bytes) -> None:
		stream = streams.StreamIn(data, ">")
		if stream.u24() != 0x0022AA:
			raise ValueError("Data frame has wrong OUI")
		if stream.u16() != 0x103:
			raise ValueError("Data frame is not a disconnect frame")
		stream.pad(1)
		
		self.reason = stream.u8()
		stream.pad(31)


class NetworkInfo:
	protocol: int

	address: MACAddress
	band: int
	channel: int

	local_communication_id: int
	scene_id: int
	ssid: bytes

	version: int
	server_random: bytes
	security_mode: int

	app_version: int

	accept_policy: int
	max_participants: int
	num_participants: int
	participants: list[ParticipantInfo]
	application_data: bytes

	challenge: int

	nonce: bytes

	def __init__(self, protocol: int):
		self.protocol = protocol

		self.address = None
		self.band = None
		self.channel = None

		self.local_communication_id = None
		self.scene_id = None
		self.ssid = None
		
		self.version = None
		self.server_random = None
		self.security_mode = None

		self.app_version = None

		self.accept_policy = None
		self.max_participants = None
		self.num_participants = None
		self.participants = None
		self.application_data = None

		self.challenge = None

		self.nonce = None

	def is_same_network(self, other: NetworkInfo) -> bool:
		if self.address != other.address: return False
		if self.band != other.band: return False
		if self.channel != other.channel: return False

		if self.local_communication_id != other.local_communication_id: return False
		if self.scene_id != other.scene_id: return False
		if self.ssid != other.ssid: return False

		if self.version != other.version: return False
		if self.server_random != other.server_random: return False
		if self.security_mode != other.security_mode: return False

		return True
	
	def parse_advertisement(self, frame: AdvertisementFrame) -> None:
		self.local_communication_id = frame.network_id.local_communication_id
		self.scene_id = frame.network_id.scene_id
		self.ssid = frame.network_id.ssid

		self.version = frame.version
		self.server_random = frame.payload.server_random
		self.security_mode = frame.payload.security_mode

		self.app_version = frame.payload.app_version

		self.accept_policy = frame.payload.station_accept_policy
		self.max_participants = frame.payload.max_participants
		self.num_participants = frame.payload.num_participants
		self.participants = frame.payload.participants
		self.application_data = frame.payload.application_data
		
		self.challenge = frame.payload.challenge
		self.nonce = frame.nonce
	
	def build_advertisement(self, key_derivation: KeyDerivation) -> AdvertisementFrame:
		network_id = NetworkId()
		network_id.local_communication_id = self.local_communication_id
		network_id.scene_id = self.scene_id
		network_id.ssid = self.ssid
		
		info = AdvertisementInfo()
		info.server_random = self.server_random
		info.security_mode = self.security_mode
		info.station_accept_policy = self.accept_policy
		info.app_version = self.app_version

		info.band = self.band
		info.channel = self.channel

		info.max_participants = self.max_participants
		info.num_participants = self.num_participants
		info.participants = self.participants
		info.application_data = self.application_data
		info.challenge = self.challenge
		
		frame = AdvertisementFrame(key_derivation, self.protocol)
		frame.network_id = network_id
		frame.version = self.version

		frame.format = ADVERTISE_FORMAT_PLAIN
		if self.security_mode != SECURITY_MODE_SYSTEM_DEBUG:
			frame.format = ADVERTISE_FORMAT_AES_CTR if self.protocol == 1 else ADVERTISE_FORMAT_AES_GCM

		frame.nonce = self.nonce
		frame.payload = info
		return frame


class ConnectNetworkParam:
	ifname: str
	phyname: str

	network: NetworkInfo
	password: bytes

	name: bytes
	app_version: int
	platform: int

	enable_challenge: bool
	device_id: int

	client_random: bytes

	keys: dict[str, bytes]

	override_data_key: bytes
	override_advertise_key: bytes

	def __init__(self):
		self.ifname = "ldn"
		self.phyname = "phy0"
		
		self.network = None
		self.password = b""
		
		self.name = b""
		self.app_version = 0
		self.platform = PLATFORM_NX
		
		self.enable_challenge = True
		self.device_id = random.randint(0, 0xFFFFFFFFFFFFFFFF)

		self.client_random = None

		self.keys = None

		self.override_advertise_key = None
		self.override_data_key = None

	def check(self) -> None:
		if self.network is None: raise ValueError("network is required")
		if self.network.version not in [2, 3, 4]:
			raise ValueError("Network version not supported")
		
		if self.keys is None:
			raise ValueError("keys is required")


class CreateNetworkParam:
	ifname: str
	ifname_monitor: str
	phyname: str
	phyname_monitor: str

	local_communication_id: int
	scene_id: int

	max_participants: int
	application_data: bytes
	accept_policy: int
	accept_filter: list[MACAddress]
	security_mode: int
	ssid: bytes

	name: bytes
	app_version: int
	platform: int

	channel: int
	server_random: bytes
	password: bytes

	version: int
	enable_challenge: bool
	device_id: int

	protocol: int
	
	keys: dict[str, bytes]

	override_data_key: bytes
	override_advertise_key: bytes

	def __init__(self):
		self.ifname = "ldn"
		self.ifname_monitor = "ldn-mon"
		self.phyname = "phy0"
		self.phyname_monitor = "phy0"
		
		self.local_communication_id = None
		self.scene_id = None

		self.max_participants = 8
		self.application_data = b""
		self.accept_policy = ACCEPT_ALL
		self.accept_filter = []
		self.security_mode = 1
		self.ssid = None
		
		self.name = b""
		self.app_version = 0
		self.platform = PLATFORM_NX
		
		self.channel = None
		self.server_random = None
		self.password = b""
		
		self.version = 4
		self.enable_challenge = True
		self.device_id = random.randint(0, 0xFFFFFFFFFFFFFFFF)

		self.protocol = 1

		self.keys = None

		self.override_advertise_key = None
		self.override_data_key = None

	def check(self):
		if self.local_communication_id is None: raise ValueError("local_communication_id is required")
		if self.scene_id is None: raise ValueError("scene_id is required")

		if self.max_participants > 8: raise ValueError("max_participants is too high")

		if len(self.application_data) > 0x180: raise ValueError("application_data is too large")

		if self.ssid is not None and len(self.ssid) != 16:
			raise ValueError("ssid has wrong size")

		if self.channel is not None and not wlan.is_valid_channel(self.channel):
			raise ValueError("channel is invalid")
		
		if self.server_random is not None and len(self.server_random) != 16:
			raise ValueError("server_random has wrong size")
		
		if self.version not in [2, 3, 4]:
			raise ValueError("version is invalid")
		
		if self.protocol not in [1, 3]:
			raise ValueError("protocol is not supported")
		
		if self.keys is None:
			raise ValueError("keys is required")


@dataclass
class DisconnectEvent:
	reason: int

@dataclass
class JoinEvent:
	index: int
	participant: ParticipantInfo

@dataclass
class LeaveEvent:
	index: int
	participant: ParticipantInfo

@dataclass
class ApplicationDataChanged:
	old: bytes
	new: bytes

@dataclass
class AcceptPolicyChanged:
	old: int
	new: int


class AdvertisementMonitor:
	_protocols: dict[int, KeyDerivation]
	_monitor: wlan.Monitor

	def __init__(self, protocols: dict[int, KeyDerivation], monitor: wlan.Monitor):
		self._protocols = protocols
		self._monitor = monitor
	
	async def receive(self) -> NetworkInfo:
		# Vendor-specific, Nintendo OUI, LDN, Advertisement
		header = bytes([0x7F, 0x00, 0x22, 0xAA, 0x04, 0x00, 0x01, 0x01])
		while True:
			# Receive a single frame
			radiotap = await self._monitor.recv()
			
			# Check if we received an action frame
			if len(radiotap.data) < 2 or struct.unpack_from(">H", radiotap.data)[0] != 0xD000:
				continue
			
			action = wlan.ActionFrame()
			try: action.decode(radiotap.data)
			except Exception:
				continue # Skip invalid frames

			# Check if we received an advertisement frame from LDN
			if not action.action.startswith(header):
				continue
			
			# Decode the frame itself
			for protocol, key_derivation in self._protocols.items():
				frame = AdvertisementFrame(key_derivation, protocol)
				try: frame.decode(action.action)
				except Exception:
					continue # Skip invalid frames
				
				info = NetworkInfo(protocol)
				info.address = action.source
				info.channel = wlan.map_frequency(radiotap.frequency)
				info.band = ChannelBands[info.channel]
				info.parse_advertisement(frame)
				return info

	async def scan(self, channels: list[int], dwell_time: float) -> list[NetworkInfo]:
		networks = []
		async def scan_frames():
			addresses = []
			while True:
				network = await self.receive()
				if network.address not in addresses:
					addresses.append(network.address)
					networks.append(network)
		
		async with util.background_task(scan_frames):
			for channel in channels:
				await self._monitor.set_channel(channel)
				await trio.sleep(dwell_time)
		return networks

		
class STANetwork:
	_key_derivation: KeyDerivation
	_interface: wlan.STAInterface
	_router: route.RouteController
	_param: ConnectNetworkParam

	_network: NetworkInfo
	_keys: dict[str, bytes]

	_events: queue.Queue
	_advertisements: queue.Queue

	_network_id: int
	_participant_id: int

	def __init__(self,
		key_derivation: KeyDerivation, interface: wlan.STAInterface,
		router: route.RouteController, param: ConnectNetworkParam
	):
		self._key_derivation = key_derivation
		self._interface = interface
		self._router = router
		self._param = param

		self._network = param.network
		self._keys = param.keys
		
		self._events = queue.create()
		self._advertisements = queue.create()
		
		self._network_id = None
		self._participant_id = None
	
	def _check_authentication_response(self, address: MACAddress, data: bytes) -> bool:
		if address != self._network.address: return False
		
		frame = AuthenticationFrame(self._key_derivation, self._network.protocol)
		try:
			frame.decode(data)
		except Exception:
			logger.warning("Failed to parse authentication response")
			return False
		
		if not isinstance(frame.payload, AuthenticationResponse): return False
		
		if frame.network_id.local_communication_id != self._network.local_communication_id: return False
		if frame.network_id.scene_id != self._network.scene_id: return False
		if frame.network_id.ssid != self._network.ssid: return False
		
		if frame.server_random != self._network.server_random: return False
		if frame.client_random != self._param.client_random: return False
		
		if frame.status_code != 0:
			raise AuthenticationError(frame.status_code)
		
		return True
	
	def info(self) -> NetworkId:
		return self._network
	
	def participant(self) -> ParticipantInfo:
		return self._network.participants[self._participant_id]
	
	async def next_event(self) -> object:
		return await self._events.get()
	
	@contextlib.asynccontextmanager
	async def start(self) -> None:
		await self._authenticate()
		async with util.background_task(self._process_events):
			await self._initialize_network()
			async with util.background_task(self._monitor_network):
				yield
	
	async def _process_events(self) -> None:
		while True:
			event = await self._interface.next_event()

			if isinstance(event, wlan.FrameEvent):
				if event.frame.source != self._network.address:
					continue # Only process frames from the host
				
				frame = AdvertisementFrame(self._key_derivation, self._network.protocol)
				try: frame.decode(event.frame.action)
				except Exception:
					continue # Skip invalid frames
				
				info = NetworkInfo(self._network.protocol)
				info.address = event.frame.source
				info.channel = wlan.map_frequency(event.frequency)
				info.band = ChannelBands[info.channel]
				info.parse_advertisement(frame)

				if not self._network.is_same_network(info):
					raise ConnectionError("Received incompatible advertisement frame from host")
				
				await self._advertisements.put(info)
			
			elif isinstance(event, wlan.DataFrameEvent):
				frame = DisconnectFrame()
				frame.decode(event.data)
				await self._events.put(DisconnectEvent(frame.reason))
			
			elif isinstance(event, wlan.DisassociationEvent):
				await self._events.put(DisconnectEvent(DISCONNECT_CONNECTION_LOST))
	
	async def _authenticate(self) -> None:
		request = AuthenticationRequest()
		request.username = self._param.name
		request.app_version = self._param.app_version
		request.platform = self._param.platform
		
		if self._param.enable_challenge:
			challenge = ChallengeRequest()
			challenge.flags = 0
			challenge.token = self._network.challenge
			challenge.nonce = random.randint(0, 0xFFFFFFFFFFFFFFFF)
			challenge.device_id = self._param.device_id
			request.challenge = challenge.encode()
		
		network_id = NetworkId()
		network_id.local_communication_id = self._network.local_communication_id
		network_id.scene_id = self._network.scene_id
		network_id.ssid = self._network.ssid
		
		frame = AuthenticationFrame(self._key_derivation, self._network.protocol)
		frame.version = self._network.version
		frame.status_code = 0
		frame.network_id = network_id
		frame.server_random = self._network.server_random
		frame.client_random = self._param.client_random
		frame.payload = request
		
		# Attempt authentication up to three times
		for i in range(3):
			await self._interface.send_data_frame(self._network.address, frame.encode())
			
			# Resend the authentication request if we do not
			# receive a response after 700 milliseconds
			with trio.move_on_after(.7):
				while True:
					event = await self._interface.next_event()
					if isinstance(event, wlan.DataFrameEvent):
						if self._check_authentication_response(event.address, event.data):
							return
					elif isinstance(event, wlan.DisassociationEvent):
						raise ConnectionError("Station was disassociated")
		raise ConnectionError("Authentication timeout (password may be wrong)")
	
	async def _wait_for_network(self) -> tuple[NetworkInfo, int]:
		while True:
			network = await self._advertisements.get()
			for index, participant in enumerate(network.participants):
				if participant.mac_address == self._interface.address:
					return network, index
	
	async def _initialize_network(self) -> None:
		await self._interface.set_authorized()
		
		# Wait until the host has updated the advertisement frame
		network = None
		with trio.move_on_after(1):
			network, index = await self._wait_for_network()
		
		if network is None:
			raise ConnectionError("Failed to obtain IP address after joining network (timeout)")
		
		# Initialize local state
		self._network = network
		self._network_id = int(network.participants[0].ip_address.split(".")[2])
		self._participant_id = index
		
		# Initialize interface address
		attrs = {
			route.IFA_LOCAL: socket.inet_aton(network.participants[index].ip_address),
			route.IFA_BROADCAST: socket.inet_aton("169.254.%i.255" %self._network_id)
		}
		await self._router.add_address(
			socket.AF_INET, 24, route.IFA_F_PERMANENT, route.RT_SCOPE_UNIVERSE,
			self._interface.index, attrs
		)
		
		# Create a static neighbor entry for each participant
		for participant in network.participants:
			if participant.connected:
				attrs = {
					route.NDA_DST: socket.inet_aton(participant.ip_address),
					route.NDA_LLADDR: participant.mac_address.encode()
				}
				await self._router.add_neighbor(socket.AF_INET, self._interface.index, route.NUD_PERMANENT, 0, 0, attrs)
	
	async def _monitor_network(self) -> None:
		# Monitors advertisement frames to get
		# notified when the network changes
		while True:
			network = await self._advertisements.get()
			
			# Check if the accept policy has changed
			if network.accept_policy != self._network.accept_policy:
				await self._events.put(AcceptPolicyChanged(self._network.accept_policy, network.accept_policy))
			
			# Check if the application data has changed
			if network.application_data != self._network.application_data:
				await self._events.put(ApplicationDataChanged(self._network.application_data, network.application_data))
			
			# Remove participants that are gone
			for i in range(8):
				old = self._network.participants[i]
				new = network.participants[i]
				if old.connected and old.mac_address != new.mac_address:
					attrs = {
						route.NDA_DST: socket.inet_aton(old.ip_address),
						route.NDA_LLADDR: old.mac_address.encode()
					}
					await self._router.remove_neighbor(socket.AF_INET, self._interface.index, route.NUD_PERMANENT, 0, 0, attrs)
					await self._events.put(LeaveEvent(i, old))
			
			# Register new participants
			for i in range(8):
				old = self._network.participants[i]
				new = network.participants[i]
				if new.connected and old.mac_address != new.mac_address:
					attrs = {
						route.NDA_DST: socket.inet_aton(new.ip_address),
						route.NDA_LLADDR: new.mac_address.encode()
					}
					await self._router.add_neighbor(socket.AF_INET, self._interface.index, route.NUD_PERMANENT, 0, 0, attrs)
					await self._events.put(JoinEvent(i, new))
			
			# Update local state
			self._network = network


class APNetwork:
	_key_derivation: KeyDerivation
	_interface: wlan.APInterface
	_monitor: wlan.Monitor
	_router: route.RouteController
	_param: CreateNetworkParam

	_accept_filter: list[MACAddress]
	_enable_challenge: bool
	_device_id: int
	_platform: int

	_nonce: int
	_network_id: int

	_network: NetworkInfo

	_events: queue.Queue

	def __init__(self,
		key_derivation: KeyDerivation, interface: wlan.APInterface,
		monitor: wlan.Monitor, router: route.RouteController,
		param: CreateNetworkParam
	):
		self._key_derivation = key_derivation
		self._interface = interface
		self._monitor = monitor
		self._router = router
		self._param = param
		
		self._accept_filter = param.accept_filter
		self._enable_challenge = param.enable_challenge
		self._device_id = param.device_id
		self._platform = param.platform
		
		self._nonce = random.randint(0, 0xFFFFFFFF)
		self._network_id = random.randint(1, 127)
		
		participant = ParticipantInfo()
		participant.ip_address = "169.254.%i.1" %self._network_id
		participant.mac_address = interface.address
		participant.connected = True
		participant.name = param.name
		participant.app_version = param.app_version
		participant.platform = param.platform
		
		participants = [participant]
		for i in range(7):
			participants.append(ParticipantInfo())
		
		self._network = NetworkInfo(param.protocol)
		self._network.address = interface.address
		self._network.channel = param.channel
		self._network.band = ChannelBands[param.channel]
		self._network.local_communication_id = param.local_communication_id
		self._network.scene_id = param.scene_id
		self._network.ssid = param.ssid
		self._network.version = param.version
		self._network.server_random = param.server_random
		self._network.security_mode = param.security_mode
		self._network.accept_policy = param.accept_policy
		self._network.max_participants = param.max_participants
		self._network.num_participants = 1
		self._network.participants = participants
		self._network.application_data = param.application_data
		self._network.app_version = param.app_version
		self._network.challenge = 0
		if param.enable_challenge:
			self._network.challenge = random.randint(0, 0xFFFFFFFFFFFFFFFF)
		self._network.nonce = struct.pack(">I", self._nonce)
		self._network.protocol = param.protocol

		self._events = queue.create()
	
	def _make_authentication_response(self, status: int, version: int, client_random: bytes, challenge: bytes=b"") -> AuthenticationFrame:
		network_id = NetworkId()
		network_id.local_communication_id = self._network.local_communication_id
		network_id.scene_id = self._network.scene_id
		network_id.ssid = self._network.ssid
		
		response = AuthenticationResponse()
		response.platform = self._platform
		response.challenge = challenge
		
		frame = AuthenticationFrame(self._key_derivation, self._param.protocol)
		frame.version = version
		frame.status_code = status
		frame.network_id = network_id
		frame.server_random = self._network.server_random
		frame.client_random = client_random
		frame.payload = response
		return frame
	
	def _check_accept_policy(self, address: MACAddress) -> bool:
		if self._network.accept_policy == ACCEPT_ALL: return True
		if self._network.accept_policy == ACCEPT_NONE: return False
		if self._network.accept_policy == ACCEPT_BLACKLIST:
			return address not in self._accept_filter
		if self._network.accept_policy == ACCEPT_WHITELIST:
			return address in self._accept_filter
		return False
	
	def _check_authentication_request(self, address: MACAddress, frame: AuthenticationFrame) -> int:
		if frame.version not in [2, 3, 4]: return AUTH_INVALID_VERSION
		
		if frame.status_code != 0: return AUTH_MALFORMED_REQUEST
		if frame.network_id.local_communication_id != self._network.local_communication_id: return AUTH_MALFORMED_REQUEST
		if frame.network_id.scene_id != self._network.scene_id: return AUTH_MALFORMED_REQUEST
		if frame.network_id.ssid != self._network.ssid: return AUTH_MALFORMED_REQUEST
		if frame.server_random != self._network.server_random: return AUTH_MALFORMED_REQUEST

		if not isinstance(frame.payload, AuthenticationRequest): return AUTH_MALFORMED_REQUEST
		
		if not self._check_accept_policy(address):
			return AUTH_DENIED_BY_POLICY
		
		return AUTH_SUCCESS
	
	def _process_authentication_challenge(self, challenge: bytes) -> bytes | None:
		if not self._enable_challenge: return b""
		
		request = ChallengeRequest()
		try:
			request.decode(challenge)
		except Exception:
			logger.warning("Failed to parse authentication challenge")
			return None
		
		if request.token != self._network.challenge:
			logger.warning("Received authentication request with wrong token")
			return None
		
		response = ChallengeResponse()
		response.flags = 2
		response.nonce = request.nonce
		response.device_id = request.device_id
		response.device_id_host = self._device_id
		response.unk = request.unk
		return response.encode()
	
	def _update_nonce(self) -> None:
		self._nonce = (self._nonce + 1) & 0xFFFFFFFF
		self._network.nonce = struct.pack(">I", self._nonce)
	
	def info(self) -> NetworkInfo:
		return self._network
	
	def participant(self) -> ParticipantInfo:
		return self._network.participants[0]
	
	def set_application_data(self, data: bytes) -> None:
		self._network.application_data = data
		self._update_nonce()
	
	def set_accept_policy(self, policy: int) -> None:
		self._network.accept_policy = policy
		self._update_nonce()
	
	def set_accept_filter(self, filter: list[MACAddress]) -> None:
		self._accept_filter = filter
		
	async def kick(self, index: int) -> None:
		participant = self._network.participants[index]
		if participant.connected:
			frame = DisconnectFrame()
			frame.reason = DISCONNECT_STATION_REJECTED_BY_HOST
			await self._interface.send_data_frame(participant.mac_address, frame.encode())
			await self._interface.remove_station(participant.mac_address)
			await self._process_disassociation(participant.mac_address)
	
	async def next_event(self) -> object:
		return await self._events.get()
	
	@contextlib.asynccontextmanager
	async def start(self) -> None:
		await self._initialize_network()
		async with util.background_task(self._process_events):
			async with util.background_task(self._send_advertisements):
				yield
				await self._destroy_network()
	
	async def _process_events(self) -> None:
		while True:
			event = await self._interface.next_event()
			if isinstance(event, wlan.DataFrameEvent):
				response = await self._process_authentication_event(event)
				await self._interface.send_data_frame(event.address, response.encode())
			elif isinstance(event, wlan.DisassociationEvent):
				await self._process_disassociation(event.address)
	
	async def _process_authentication_event(self, event: wlan.DataFrameEvent) -> AuthenticationFrame:
		frame = AuthenticationFrame(self._key_derivation, self._param.protocol)
		try:
			frame.decode(event.data)
		except Exception:
			logger.warning("Failed to parse authentication request")
			return self._make_authentication_response(AUTH_MALFORMED_REQUEST, self._network.version, bytes(16))
		
		error = self._check_authentication_request(event.address, frame)
		if error != AUTH_SUCCESS:
			return self._make_authentication_response(error, self._network.version, frame.client_random)
		
		challenge = self._process_authentication_challenge(frame.payload.challenge)
		if challenge is None:
			return self._make_authentication_response(AUTH_CHALLENGE_FAILURE, self._network.version, frame.client_random)
		
		await self._register_participant(event.address, frame.payload.username, frame.payload.app_version, frame.payload.platform)
		
		return self._make_authentication_response(AUTH_SUCCESS, self._network.version, frame.client_random, challenge)
	
	async def _register_participant(self, address: MACAddress, name: bytes, app_version: int, platform: int) -> None:
		# Allocate an ip address
		for index in range(8):
			if not self._network.participants[index].connected:
				break
		
		participant = ParticipantInfo()
		participant.ip_address = "169.254.%i.%i" %(self._network_id, (index + 1))
		participant.mac_address = address
		participant.connected = True
		participant.name = name
		participant.app_version = app_version
		participant.platform = platform
		
		self._network.participants[index] = participant
		self._network.num_participants += 1
		
		self._update_nonce()

		await self._interface.set_authorized(address)
		
		# Add neighbor entry
		attrs = {
			route.NDA_DST: socket.inet_aton(participant.ip_address),
			route.NDA_LLADDR: participant.mac_address.encode()
		}
		await self._router.add_neighbor(socket.AF_INET, self._interface.index, route.NUD_PERMANENT, 0, 0, attrs)
		
		await self._events.put(JoinEvent(index, participant))
	
	async def _process_disassociation(self, address) -> None:
		for index, participant in enumerate(self._network.participants):
			if participant.connected and participant.mac_address == address:
				break
		else:
			return
		
		participant.connected = False
		self._network.num_participants -= 1

		self._update_nonce()
		
		# Remove neighbor entry
		attrs = {
			route.NDA_DST: socket.inet_aton(participant.ip_address),
			route.NDA_LLADDR: participant.mac_address.encode()
		}
		await self._router.remove_neighbor(socket.AF_INET, self._interface.index, route.NUD_PERMANENT, 0, 0, attrs)
		
		await self._events.put(LeaveEvent(index, participant))
	
	async def _send_advertisements(self) -> None:
		while True:
			await self._send_advertisement()
			await trio.sleep(.1)
	
	async def _send_advertisement(self) -> None:
		frame = self._network.build_advertisement(self._key_derivation)
		
		action = wlan.ActionFrame()
		action.source = self._interface.address
		action.action = frame.encode()
		
		radiotap = wlan.RadiotapFrame()
		radiotap.data = action.encode()
		await self._monitor.send(radiotap)
	
	async def _initialize_network(self) -> None:
		host = self._network.participants[0]

		attrs = {
			route.IFA_LOCAL: socket.inet_aton(host.ip_address),
			route.IFA_BROADCAST: socket.inet_aton("169.254.%i.255" %self._network_id)
		}
		await self._router.add_address(
			socket.AF_INET, 24, route.IFA_F_PERMANENT, route.RT_SCOPE_UNIVERSE,
			self._interface.index, attrs
		)

		attrs = {
			route.NDA_DST: socket.inet_aton(host.ip_address),
			route.NDA_LLADDR: host.mac_address.encode()
		}
		await self._router.add_neighbor(socket.AF_INET, self._interface.index, route.NUD_PERMANENT, 0, 0, attrs)
	
	async def _destroy_network(self) -> None:
		for participant in self._network.participants:
			if participant.connected:
				frame = DisconnectFrame()
				frame.reason = DISCONNECT_NETWORK_DESTROYED
				await self._interface.send_data_frame(participant.mac_address, frame.encode())


async def scan(
	keys: dict[str, bytes], ifname: str = "ldn", phyname: str = "phy0",
	channels: list[int] = [1, 6, 11], dwell_time: float = .110,
	protocols: list[int] = [1, 3]
) -> list[NetworkInfo]:
	if not channels: return []

	# Check if all channels are valid
	for channel in channels:
		if not wlan.is_valid_channel(channel):
			raise ValueError("Invalid channel: %i" %channel)
	
	for protocol in protocols:
		if protocol not in [1, 3]:
			raise ValueError("Invalid protocol: %i" %protocol)
	
	key_derivations = {
		protocol: KeyDerivation(keys, protocol) for protocol in protocols
	}

	async with wlan.create() as factory:
		async with factory.create_monitor(phyname, ifname) as monitor:
			scanner = AdvertisementMonitor(key_derivations, monitor)
			return await scanner.scan(channels, dwell_time)


@contextlib.asynccontextmanager
async def connect(param: ConnectNetworkParam) -> STANetwork:
	param = copy.copy(param)
	if param.client_random is None:
		param.client_random = secrets.token_bytes(16)
	param.check()
	
	network = param.network

	key_derivation = KeyDerivation(
		param.keys, network.protocol,
		override_advertise_key=param.override_advertise_key,
		override_data_key=param.override_data_key
	)
	
	wlan_key = None
	if network.security_mode == SECURITY_MODE_PROD:
		wlan_key = key_derivation.derive_data_key(network.server_random, param.password)
	
	async with wlan.create() as factory:
		async with factory.connect_network(param.phyname, param.ifname, network.ssid.hex(), network.channel, wlan_key) as interface:
			async with route.connect() as router:
				network = STANetwork(key_derivation, interface, router, param)
				async with network.start():
					yield network


@contextlib.asynccontextmanager
async def create_network(param: CreateNetworkParam) -> APNetwork:
	param = copy.copy(param)
	if param.ssid is None: param.ssid = secrets.token_bytes(16)
	if param.channel is None: param.channel = random.choice([1, 6, 11])
	if param.server_random is None: param.server_random = secrets.token_bytes(16)
	param.check()

	key_derivation = KeyDerivation(
		param.keys, param.protocol,
		override_advertise_key=param.override_advertise_key,
		override_data_key=param.override_data_key
	)
	
	wlan_key = None
	if param.security_mode == SECURITY_MODE_PROD:
		wlan_key = key_derivation.derive_data_key(param.server_random, param.password)
	
	async with wlan.create() as factory:
		async with factory.create_monitor(param.phyname_monitor, param.ifname_monitor) as monitor:
			await monitor.set_channel(param.channel)
			async with factory.create_network(param.phyname, param.ifname, param.ssid.hex(), param.channel, wlan_key, param.max_participants) as interface:
				async with route.connect() as router:
					network = APNetwork(key_derivation, interface, monitor, router, param)
					async with network.start():
						yield network
