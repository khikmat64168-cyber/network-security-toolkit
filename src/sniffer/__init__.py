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
from src.sniffer.capture import PacketCapture
from src.sniffer.interface import InterfaceManager, NetworkInterface
from src.sniffer.parsers import ParserDispatcher
from src.sniffer.parsers.base import ParsedPacket, Protocol

__all__ = [
    "PacketCapture",
    "InterfaceManager",
    "NetworkInterface",
    "ParserDispatcher",
    "ParsedPacket",
    "Protocol",
]
