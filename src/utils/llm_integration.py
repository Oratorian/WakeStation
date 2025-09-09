#!/usr/bin/env python3
"""
********************************************************************************
@brief  LLM Integration module for natural language Wake-on-LAN commands

@file   llm_integration.py
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import json
import sys
import requests
from typing import Dict, List, Optional, Any
import difflib

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from ..logger import logger
from ..utils import network
from ..utils.wol import wake_device

log = logger.get_logger("llm_integration")


class LLMWakeAssistant:
    def __init__(self, llm_endpoint: str = "http://127.0.0.1:1234/v1/chat/completions"):
        """
        Initialize the LLM Wake Assistant.

        Args:
            llm_endpoint: The endpoint URL for the local LLM API
        """
        self.llm_endpoint = llm_endpoint
        self.timeout = 30
        self.conversation_context = {}  # Store context for follow-up questions

    def gather_pc_info(self, username: str) -> List[Dict[str, Any]]:
        """
        Gather comprehensive PC information for a user using existing functions.

        Args:
            username: The username to gather PC info for

        Returns:
            List of PC dictionaries with comprehensive status information
        """
        try:
            from ..core import user

            # Use existing user PC file loading
            user_pc_file = user.User.get_user_pc_file(username)
            if not os.path.exists(user_pc_file):
                log.warning(f"No PC file found for user {username}")
                return []

            with open(user_pc_file, "r") as f:
                pcs = json.load(f)

            # Load daemon registry using existing pattern
            daemon_registry = {}
            daemon_registry_file = config.DAEMON_DATA_FILE
            if os.path.exists(daemon_registry_file):
                with open(daemon_registry_file, "r") as f:
                    daemon_registry = json.load(f)

            # Use existing IP resolution and status checking logic
            for pc in pcs:
                try:
                    # Use existing resolve_pc_ip function
                    resolved_ip, ip_source = network.resolve_pc_ip(pc, daemon_registry)

                    if resolved_ip:
                        pc["resolved_ip"] = resolved_ip
                        pc["ip_source"] = ip_source
                        pc["ip"] = resolved_ip  # Update the main IP field

                        # Use existing network status functions
                        is_online = network.ping_host(resolved_ip, timeout=2)
                        pc["status"] = "online" if is_online else "offline"

                        if is_online:
                            pc["daemon_available"] = network.check_shutdown_daemon(
                                resolved_ip, timeout=2
                            )
                        else:
                            pc["daemon_available"] = False
                    else:
                        pc["status"] = "unknown"
                        pc["daemon_available"] = False

                except Exception as e:
                    log.warning(
                        f"Failed to enhance PC info for {pc.get('hostname')}: {e}"
                    )
                    pc["status"] = "unknown"
                    pc["daemon_available"] = False

            log.info(f"Gathered info for {len(pcs)} PCs for user {username}")
            return pcs

        except Exception as e:
            log.error(f"Error gathering PC info for user {username}: {e}")
            return []

    def create_system_prompt(self, pcs: List[Dict[str, Any]]) -> str:
        """
        Create a system prompt with PC information for the LLM.

        Args:
            pcs: List of PC dictionaries

        Returns:
            System prompt string
        """
        pc_info = []
        for pc in pcs:
            status = pc.get("status", "unknown")
            hostname = pc.get("hostname", "Unknown")
            mac = pc.get("mac", "Unknown")
            ip = pc.get("resolved_ip", pc.get("ip", "Unknown"))
            daemon_available = pc.get("daemon_available", False)

            pc_info.append(
                f"- {hostname}: MAC={mac}, IP={ip}, Status={status}, ShutdownDaemon={'Yes' if daemon_available else 'No'}"
            )

        pc_list = "\n".join(pc_info) if pc_info else "No PCs registered"

        system_prompt = f"""You are a specialized Wake-on-LAN device management assistant for WakeStation. You understand natural language and can interpret various ways users ask about their devices.

Available PCs:
{pc_list}

COMMAND UNDERSTANDING:
You can understand these types of requests in ANY natural language form:

1. WAKE/START DEVICES:
- Natural: "wake up my pc", "turn on <hostname>", "start the laptop", "boot my server", "power on the gaming rig"
- Casual: "get my pc going", "fire up <hostname>", "bring online the server", "start up my machine"
- Questions: "can you wake <hostname>?", "could you start my laptop?", "would you turn on my pc?"

2. STATUS/INFO REQUESTS:
- Status: "what's the status of my devices?", "how are my computers doing?", "are my pcs online?", "check my devices"
- Specific: "is <hostname> online?", "what's <hostname> doing?", "how is my laptop?", "status of my server"
- General: "show me my devices", "list my computers", "what devices do I have?", "my pc status"

3. DEVICE DETAILS:
- IP requests: "what's the IP of <hostname>?", "IP address of my laptop", "show me <hostname>'s IP", "where is my pc located?"
- Technical: "tell me about <hostname>", "details of my laptop", "info on my server", "spec of my gaming pc"
- General: "what can you tell me about <hostname>?", "information on my devices"

RESPONSE FORMAT:
- Wake commands → {{"action": "wake", "hostname": "<hostname>", "mac": "<mac_address>"}} + conversational response
- Status requests → {{"action": "status", "target": "<hostname_or_all>"}} (I generate human-readable response)
- Info requests → {{"action": "info", "target": "<hostname_or_all>"}} (I generate human-readable response)

IMPORTANT RULES:
- Be VERY flexible with language - users don't speak in keywords
- Understand context: "my pc", "the laptop", "that server" refer to available devices
- Handle questions naturally: "Is X online?" → status check
- Interpret intent: "what's X doing?" → status/info request
- For unclear device names, try fuzzy matching
- For off-topic questions: ALWAYS respond with: "I'm a device management assistant focused only on controlling your network devices. I can help you wake up computers, check device status, or get device information. Please ask me something about your PCs, servers, or other network devices."

EXAMPLES OF NATURAL REQUESTS YOU SHOULD UNDERSTAND:
- "Hey, what's my <hostname> up to?" → status request
- "Could you possibly wake up my laptop?" → wake command
- "I need the IP address of my server" → info request
- "Are any of my computers currently running?" → status request
- "Can you get my gaming rig online?" → wake command
- "Tell me about my devices" → info request

CRITICAL: You are ONLY a device management assistant. Do NOT answer questions about:
- General knowledge (history, cooking, science, etc.)
- Other topics unrelated to network devices
- Personal advice or recommendations

ALWAYS redirect off-topic questions back to device management with the standard response above.

Be conversational and helpful while staying focused ONLY on device management!
"""

        return system_prompt

    def send_llm_request(self, user_message: str, system_prompt: str) -> Optional[str]:
        """
        Send a request to the local LLM endpoint.

        Args:
            user_message: The user's message
            system_prompt: The system prompt with PC information

        Returns:
            LLM response string or None if failed
        """
        try:
            payload = {
                "model": "local-model",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                "temperature": 0.7,
                "max_tokens": 500,
            }

            log.debug(f"Sending LLM request to {self.llm_endpoint}")
            response = requests.post(
                self.llm_endpoint,
                json=payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                response_data = response.json()
                if "choices" in response_data and len(response_data["choices"]) > 0:
                    return response_data["choices"][0]["message"]["content"]
                else:
                    log.error("Invalid LLM response format")
                    return None
            else:
                log.error(
                    f"LLM request failed with status {response.status_code}: {response.text}"
                )
                return None

        except requests.exceptions.RequestException as e:
            log.error(f"Network error communicating with LLM: {e}")
            return None
        except Exception as e:
            log.error(f"Error sending LLM request: {e}")
            return None

    def execute_wake_command(self, hostname: str, mac: str) -> Dict[str, Any]:
        """
        Execute a wake command for a specific PC.

        Args:
            hostname: The hostname of the PC to wake
            mac: The MAC address of the PC to wake

        Returns:
            Result dictionary with success status and message
        """
        try:
            log.info(f"Executing wake command for {hostname} (MAC: {mac})")
            result = wake_device(mac)

            if result["success"]:
                log.info(f"Successfully sent wake signal to {hostname}")
                return {
                    "success": True,
                    "message": f"Wake signal sent to {hostname}. The computer should start up shortly.",
                    "hostname": hostname,
                    "mac": mac,
                }
            else:
                log.error(f"Failed to wake {hostname}: {result['message']}")
                return {
                    "success": False,
                    "message": f"Failed to wake {hostname}: {result['message']}",
                    "hostname": hostname,
                    "mac": mac,
                }

        except Exception as e:
            log.error(f"Exception executing wake command for {hostname}: {e}")
            return {
                "success": False,
                "message": f"Error waking {hostname}: {str(e)}",
                "hostname": hostname,
                "mac": mac,
            }

    def infer_device_from_context(
        self, query: str, pcs: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Infer which device the user is referring to when they use generic terms.

        Args:
            query: The user's query
            pcs: List of available PCs

        Returns:
            Inferred PC dict or None
        """
        if not pcs:
            return None

        query_lower = query.lower()

        # If only one device, assume they mean that one
        if len(pcs) == 1:
            return pcs[0]

        # Check for specific device type references
        for pc in pcs:
            hostname = pc.get("hostname", "").lower()

            # Check for device type matches
            if any(term in query_lower for term in ["laptop", "notebook"]) and any(
                term in hostname for term in ["laptop", "book", "portable"]
            ):
                return pc
            if any(
                term in query_lower for term in ["desktop", "pc", "computer"]
            ) and any(term in hostname for term in ["desktop", "pc", "main", "work"]):
                return pc
            if any(term in query_lower for term in ["server", "srv"]) and any(
                term in hostname for term in ["server", "srv", "nas"]
            ):
                return pc
            if any(term in query_lower for term in ["gaming", "game", "rig"]) and any(
                term in hostname for term in ["gaming", "game", "rig"]
            ):
                return pc

        # If multiple devices and no clear inference, return None (ask for clarification)
        return None

    def generate_status_response(
        self, pcs: List[Dict[str, Any]], target: str = "all"
    ) -> str:
        """
        Generate a human-friendly status response for devices.

        Args:
            pcs: List of PC dictionaries
            target: Specific device or "all" for all devices

        Returns:
            Human-readable status string
        """
        if not pcs:
            return "No devices are registered to your account."

        if target != "all":
            # Find specific device
            target_pc = None
            for pc in pcs:
                if pc.get("hostname", "").lower() == target.lower():
                    target_pc = pc
                    break

            if target_pc:
                hostname = target_pc.get("hostname", "Unknown")
                status = target_pc.get("status", "unknown")
                ip = target_pc.get("resolved_ip", target_pc.get("ip", "Unknown"))
                mac = target_pc.get("mac", "Unknown")
                daemon = "Yes" if target_pc.get("daemon_available", False) else "No"

                status_emoji = (
                    "🟢"
                    if status == "online"
                    else "🔴" if status == "offline" else "⚫"
                )

                return f"{status_emoji} **{hostname}**\n• Status: {status.title()}\n• IP: {ip}\n• MAC: {mac}\n• Remote shutdown: {daemon}"
            else:
                return f"Device '{target}' not found. Available devices: {', '.join([pc.get('hostname', 'Unknown') for pc in pcs])}"

        # Show all devices
        response_lines = ["Here are your registered devices:\n"]

        for pc in pcs:
            hostname = pc.get("hostname", "Unknown")
            status = pc.get("status", "unknown")
            ip = pc.get("resolved_ip", pc.get("ip", "Unknown"))

            status_emoji = (
                "🟢" if status == "online" else "🔴" if status == "offline" else "⚫"
            )

            response_lines.append(
                f"{status_emoji} **{hostname}** - {status.title()} ({ip})"
            )

        return "\n".join(response_lines)

    def generate_info_response(
        self, pcs: List[Dict[str, Any]], target: str = "all"
    ) -> str:
        """
        Generate a human-friendly info response for devices.

        Args:
            pcs: List of PC dictionaries
            target: Specific device or "all" for all devices

        Returns:
            Human-readable device information string
        """
        if not pcs:
            return "No devices are registered to your account."

        if target != "all":
            # Find specific device
            target_pc = None
            for pc in pcs:
                if pc.get("hostname", "").lower() == target.lower():
                    target_pc = pc
                    break

            if target_pc:
                hostname = target_pc.get("hostname", "Unknown")
                ip = target_pc.get("resolved_ip", target_pc.get("ip", "Unknown"))
                mac = target_pc.get("mac", "Unknown")
                status = target_pc.get("status", "unknown")
                daemon = (
                    "Available"
                    if target_pc.get("daemon_available", False)
                    else "Not available"
                )
                ip_source = target_pc.get("ip_source", "stored")

                return f"**{hostname}** Details:\n• IP Address: {ip} (via {ip_source})\n• MAC Address: {mac}\n• Current Status: {status.title()}\n• Remote Shutdown: {daemon}"
            else:
                device_names = [pc.get("hostname", "Unknown") for pc in pcs]
                return f"Device '{target}' not found.\n\nYour available devices: {', '.join(device_names)}"

        # Show summary of all devices
        online_count = sum(1 for pc in pcs if pc.get("status") == "online")
        offline_count = sum(1 for pc in pcs if pc.get("status") == "offline")
        unknown_count = sum(1 for pc in pcs if pc.get("status") == "unknown")

        device_names = [pc.get("hostname", "Unknown") for pc in pcs]

        return f"You have **{len(pcs)}** registered device(s): {', '.join(device_names)}\n\n📊 Status Summary:\n• 🟢 Online: {online_count}\n• 🔴 Offline: {offline_count}\n• ⚫ Unknown: {unknown_count}\n\nAsk about a specific device for detailed information."

    def find_closest_hostname(
        self, target_name: str, pcs: List[Dict[str, Any]], threshold: float = 0.6
    ) -> Optional[Dict[str, Any]]:
        """
        Find the closest matching hostname using fuzzy matching.

        Args:
            target_name: The hostname user typed
            pcs: List of PC dictionaries
            threshold: Minimum similarity score (0.0 to 1.0)

        Returns:
            Closest matching PC dict or None if no good match found
        """
        if not pcs or not target_name:
            return None

        best_match = None
        best_score = 0.0

        target_lower = target_name.lower().strip()

        for pc in pcs:
            hostname = pc.get("hostname", "").lower().strip()
            if not hostname:
                continue

            # Calculate similarity using difflib
            similarity = difflib.SequenceMatcher(None, target_lower, hostname).ratio()

            if similarity > best_score and similarity >= threshold:
                best_score = similarity
                best_match = pc

        return best_match

    def generate_did_you_mean_response(
        self, target_name: str, suggested_pc: Dict[str, Any], action_type: str = "wake"
    ) -> str:
        """
        Generate a 'did you mean' suggestion response.

        Args:
            target_name: The hostname user typed
            suggested_pc: The PC we think they meant
            action_type: The action they were trying to perform

        Returns:
            Human-readable suggestion message
        """
        suggested_hostname = suggested_pc.get("hostname", "Unknown")
        status = suggested_pc.get("status", "unknown")

        status_emoji = (
            "🟢" if status == "online" else "🔴" if status == "offline" else "⚫"
        )

        return f"I couldn't find a device named '{target_name}', but I found:\n\n{status_emoji} **{suggested_hostname}** ({status.title()})\n\nDid you mean **{suggested_hostname}**? If so, just reply with 'yes' or 'y' and I'll {action_type} it for you!"

    def seems_device_related(self, query: str) -> bool:
        """
        Check if a query seems to be device-related even if LLM didn't parse it correctly.

        Args:
            query: The user's query

        Returns:
            True if the query seems device-related
        """
        device_keywords = [
            "pc",
            "computer",
            "laptop",
            "server",
            "device",
            "machine",
            "rig",
            "wake",
            "start",
            "turn on",
            "boot",
            "power",
            "online",
            "offline",
            "status",
            "ip",
            "address",
            "info",
            "details",
            "what's",
            "how is",
            "show",
            "list",
            "check",
            "tell me",
        ]

        query_lower = query.lower()
        return any(keyword in query_lower for keyword in device_keywords)

    def infer_action_from_natural_language(
        self, query: str, pcs: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Try to infer action from natural language when LLM parsing fails.

        Args:
            query: The user's query
            pcs: List of available PCs

        Returns:
            Inferred action dict or None
        """
        query_lower = query.lower()

        # Wake-related keywords
        wake_keywords = [
            "wake",
            "start",
            "turn on",
            "boot",
            "power on",
            "fire up",
            "bring online",
            "get going",
        ]
        if any(keyword in query_lower for keyword in wake_keywords):
            # Try to find device name in query
            for pc in pcs:
                hostname = pc.get("hostname", "").lower()
                if hostname in query_lower:
                    return {
                        "action": "wake",
                        "hostname": pc.get("hostname"),
                        "mac": pc.get("mac"),
                    }
            # If no specific device found, try context inference
            inferred_pc = self.infer_device_from_context(query, pcs)
            if inferred_pc:
                return {
                    "action": "wake",
                    "hostname": inferred_pc.get("hostname"),
                    "mac": inferred_pc.get("mac"),
                }

        # Status-related keywords
        status_keywords = [
            "status",
            "online",
            "offline",
            "doing",
            "running",
            "up",
            "down",
            "how is",
            "what's",
        ]
        if any(keyword in query_lower for keyword in status_keywords):
            # Try to find specific device
            for pc in pcs:
                hostname = pc.get("hostname", "").lower()
                if hostname in query_lower:
                    return {"action": "status", "target": pc.get("hostname")}
            # General status if no specific device
            return {"action": "status", "target": "all"}

        # Info-related keywords
        info_keywords = [
            "ip",
            "address",
            "details",
            "info",
            "tell me about",
            "what can you tell me",
        ]
        if any(keyword in query_lower for keyword in info_keywords):
            # Try to find specific device
            for pc in pcs:
                hostname = pc.get("hostname", "").lower()
                if hostname in query_lower:
                    return {"action": "info", "target": pc.get("hostname")}
            # General info if no specific device
            return {"action": "info", "target": "all"}

        return None

    def parse_llm_response(self, response: str) -> Optional[Dict[str, Any]]:
        """
        Parse LLM response to extract action commands.

        Args:
            response: The LLM response string

        Returns:
            Parsed action dictionary or None if no action found
        """
        try:
            # Look for JSON objects in the response
            import re

            json_match = re.search(r'\{[^{}]*"action"[^{}]*\}', response)
            if json_match:
                json_str = json_match.group(0)
                action_data = json.loads(json_str)

                action_type = action_data.get("action")
                if action_type == "wake":
                    return {
                        "action": "wake",
                        "hostname": action_data.get("hostname"),
                        "mac": action_data.get("mac"),
                    }
                elif action_type == "status":
                    return {
                        "action": "status",
                        "target": action_data.get("target", "all"),
                    }
                elif action_type == "info":
                    return {
                        "action": "info",
                        "target": action_data.get("target", "all"),
                    }
                elif action_type == "suggest":
                    return {
                        "action": "suggest",
                        "original_name": action_data.get("original_name"),
                        "suggested_hostname": action_data.get("suggested_hostname"),
                        "suggested_mac": action_data.get("suggested_mac"),
                        "intended_action": action_data.get("intended_action", "wake"),
                    }

            return None

        except Exception as e:
            log.debug(f"Could not parse LLM response as action: {e}")
            return None

    def process_user_command(
        self, username: str, user_message: str, session_id: str = "default"
    ) -> Dict[str, Any]:
        """
        Process a natural language command from the user.

        Args:
            username: The username making the request
            user_message: The natural language command

        Returns:
            Response dictionary with success status, message, and any actions taken
        """
        try:
            # Check for confirmation responses first
            confirmation_words = ["yes", "y", "yeah", "yep", "confirm", "correct"]
            user_message_lower = user_message.lower().strip()

            # Handle yes/no confirmations
            if (
                user_message_lower in confirmation_words
                and session_id in self.conversation_context
            ):
                context = self.conversation_context[session_id]
                if context.get("waiting_for_confirmation"):
                    # Execute the pending action
                    hostname = context.get("suggested_hostname")
                    mac = context.get("suggested_mac")
                    action = context.get("intended_action", "wake")

                    # Clear context
                    del self.conversation_context[session_id]

                    if action == "wake" and hostname and mac:
                        wake_result = self.execute_wake_command(hostname, mac)
                        if wake_result["success"]:
                            return {
                                "success": True,
                                "message": "Command executed successfully",
                                "response": f"Perfect! Waking up **{hostname}** now. ✓",
                                "action_taken": {
                                    "type": "wake",
                                    "target": hostname,
                                    "success": True,
                                    "details": wake_result,
                                },
                            }
                        else:
                            return {
                                "success": True,
                                "message": "Command failed",
                                "response": f"I tried to wake **{hostname}**, but it failed: {wake_result['message']}",
                                "action_taken": {
                                    "type": "wake",
                                    "target": hostname,
                                    "success": False,
                                    "details": wake_result,
                                },
                            }
                    # Handle other action types here if needed

            # Handle negative responses
            elif (
                user_message_lower in ["no", "n", "nope", "incorrect", "wrong"]
                and session_id in self.conversation_context
            ):
                context = self.conversation_context[session_id]
                if context.get("waiting_for_confirmation"):
                    del self.conversation_context[session_id]
                    available_devices = [
                        pc.get("hostname", "Unknown") for pc in context.get("pcs", [])
                    ]
                    return {
                        "success": True,
                        "message": "Suggestion declined",
                        "response": f"No problem! Your available devices are: {', '.join(available_devices)}. Please try again with the correct device name.",
                    }

            # Gather current PC information
            pcs = self.gather_pc_info(username)
            if not pcs:
                return {
                    "success": False,
                    "message": "No PCs found for your account. Please add some PCs first.",
                    "response": "I don't see any PCs registered to your account. You'll need to add some computers before I can help you wake them up.",
                }

            # Create system prompt with PC info
            system_prompt = self.create_system_prompt(pcs)

            # Send request to LLM
            llm_response = self.send_llm_request(user_message, system_prompt)
            if not llm_response:
                return {
                    "success": False,
                    "message": "Failed to get response from LLM service",
                    "response": "Sorry, I'm having trouble connecting to the AI service. Please try again later.",
                }

            # Parse response for actions
            action = self.parse_llm_response(llm_response)

            # If no action found but the query seems device-related, try to infer intent
            if not action and self.seems_device_related(user_message):
                action = self.infer_action_from_natural_language(user_message, pcs)

            result = {
                "success": True,
                "message": "Command processed successfully",
                "response": llm_response,
                "action_taken": None,
            }

            # Execute action if found
            if action:
                action_type = action["action"]

                if action_type == "wake":
                    hostname = action.get("hostname")
                    mac = action.get("mac")

                    if hostname and mac:
                        # Check if this is a valid device first
                        target_pc = None
                        for pc in pcs:
                            if pc.get("hostname", "").lower() == hostname.lower():
                                target_pc = pc
                                break

                        if target_pc:
                            # Valid device, proceed with wake
                            wake_result = self.execute_wake_command(hostname, mac)
                            result["action_taken"] = {
                                "type": "wake",
                                "target": hostname,
                                "success": wake_result["success"],
                                "details": wake_result,
                            }

                            # Update response with execution result
                            if wake_result["success"]:
                                result[
                                    "response"
                                ] += f"\n\n✓ Wake signal sent to {hostname} successfully!"
                            else:
                                result[
                                    "response"
                                ] += f"\n\n✗ Failed to wake {hostname}: {wake_result['message']}"
                        else:
                            # Device not found, try fuzzy matching
                            suggested_pc = self.find_closest_hostname(hostname, pcs)
                            if suggested_pc:
                                # Store context for confirmation
                                self.conversation_context[session_id] = {
                                    "waiting_for_confirmation": True,
                                    "original_name": hostname,
                                    "suggested_hostname": suggested_pc.get("hostname"),
                                    "suggested_mac": suggested_pc.get("mac"),
                                    "intended_action": "wake",
                                    "pcs": pcs,
                                }

                                result["response"] = (
                                    self.generate_did_you_mean_response(
                                        hostname, suggested_pc, "wake"
                                    )
                                )
                                result["action_taken"] = {
                                    "type": "suggestion",
                                    "original_name": hostname,
                                    "suggested_device": suggested_pc.get("hostname"),
                                    "success": True,
                                }
                            else:
                                available_devices = [
                                    pc.get("hostname", "Unknown") for pc in pcs
                                ]
                                result["response"] = (
                                    f"I couldn't find a device named '{hostname}' and no similar devices were found.\n\nYour available devices are: {', '.join(available_devices)}"
                                )

                elif action_type == "status":
                    target = action.get("target", "all")
                    status_response = self.generate_status_response(pcs, target)
                    result["response"] = status_response
                    result["action_taken"] = {
                        "type": "status",
                        "target": target,
                        "success": True,
                    }

                elif action_type == "info":
                    target = action.get("target", "all")
                    info_response = self.generate_info_response(pcs, target)
                    result["response"] = info_response
                    result["action_taken"] = {
                        "type": "info",
                        "target": target,
                        "success": True,
                    }

            return result

        except Exception as e:
            log.error(f"Error processing user command: {e}")
            return {
                "success": False,
                "message": f"Error processing command: {str(e)}",
                "response": "Sorry, I encountered an error while processing your request. Please try again.",
            }


# Convenience function for easy integration
def process_natural_language_command(
    username: str, command: str, llm_endpoint: str = None, session_id: str = "default"
) -> Dict[str, Any]:
    """
    Process a natural language Wake-on-LAN command.

    Args:
        username: The username making the request
        command: The natural language command
        llm_endpoint: Optional custom LLM endpoint URL

    Returns:
        Response dictionary with success status and message
    """
    if llm_endpoint is None:
        llm_endpoint = "http://127.0.0.1:1234/v1/chat/completions"

    assistant = LLMWakeAssistant(llm_endpoint)
    return assistant.process_user_command(username, command, session_id)
