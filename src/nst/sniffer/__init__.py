"""
Packet sniffer module — public API.

Exports
───────
    InterfaceManager   — discover, validate, and resolve network interfaces
    NetworkInterface   — immutable interface data model
    PacketCapture      — Scapy-backed capture engine
    ParserDispatcher   — routes packets to the right protocol parser
    ParsedPacket       — normalised packet data model
    Protocol           — protocol enumeration
"""
from nst.sniffer.capture import PacketCapture
from nst.sniffer.interface import InterfaceManager, NetworkInterface
from nst.sniffer.parsers import ParserDispatcher
from nst.sniffer.parsers.base import ParsedPacket, Protocol

__all__ = [
    "PacketCapture",
    "InterfaceManager",
    "NetworkInterface",
    "ParserDispatcher",
    "ParsedPacket",
    "Protocol",
]
