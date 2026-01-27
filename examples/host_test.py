
# This script creates a network for Super Mario Maker 2.

import ldn
import socket
import trio


NICKNAME = "Example"


async def send_data(ipaddr):
	return
	s = trio.socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	await s.bind(("", 7777)) # LDN uses port 12345 for broadcast
	while True:
		await s.sendto(b"Hello!", (ipaddr, 7777))
		await trio.sleep(2)


async def main():
	print("Creating network.")
	param = ldn.CreateNetworkParam()
	param.local_communication_id = 0x0100bde00862a000
	param.game_mode = 16968
	param.max_participants = 8
	param.application_data = b"libnx ldn example\0"
	param.name = NICKNAME
	param.app_version = 0
	param.channel = 11
	param.phyname = "phy1"
	param.password = "testtesttesttest"
	async with ldn.create_network(param) as network:
		async with trio.open_nursery() as nursery:
			print("Listening for events.")
			while True:
				event = await network.next_event()
				if isinstance(event, ldn.JoinEvent):
					participant = event.participant
					print("%s joined the network (%s / %s)" %(participant.name, participant.mac_address, participant.ip_address))
					nursery.start_soon(send_data, participant.ip_address)
				elif isinstance(event, ldn.LeaveEvent):
					participant = event.participant
					print("%s left the network (%s / %s)" %(participant.name, participant.mac_address, participant.ip_address))
trio.run(main)
