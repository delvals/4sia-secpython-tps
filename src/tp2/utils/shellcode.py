import os
import string

import capstone
import requests

from tp2.utils.config import logger

#####################################################################################################
# CONSTANTS
#####################################################################################################

MIN_STRING_LEN = 4  # minimum length to consider a byte sequence a "string"

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL = "gpt-4o"


#####################################################################################################
# FUNCS
#####################################################################################################


def get_shellcode_strings(shellcode: bytes) -> list[str]:
    """
    Extract printable ASCII strings from a shellcode byte sequence.
    Similar to the Unix `strings` command.

    :param shellcode: raw shellcode bytes
    :return: list of extracted strings (length >= MIN_STRING_LEN)
    """
    printable = set(string.printable.encode())
    results = []
    current = []

    for byte in shellcode:
        if byte in printable:
            current.append(chr(byte))
        else:
            if len(current) >= MIN_STRING_LEN:
                results.append("".join(current))
            current = []

    if len(current) >= MIN_STRING_LEN:
        results.append("".join(current))

    return results


def get_pylibemu_analysis(shellcode: bytes) -> str:
    """
    Emulate the shellcode using pylibemu and return the analysis report.

    :param shellcode: raw shellcode bytes
    :return: pylibemu analysis string
    """
    try:
        import pylibemu

        emulator = pylibemu.Emulator()
        offset = emulator.shellcode_getpc_test(shellcode)
        emulator.prepare(shellcode, offset)
        emulator.test()
        return emulator.emu_string if emulator.emu_string else "(no output from emulator)"

    except ImportError:
        logger.warning("pylibemu is not installed — skipping emulation analysis.")
        return "(pylibemu not available)"
    except Exception as e:
        logger.error(f"pylibemu error: {e}")
        return f"(pylibemu error: {e})"


def get_capstone_analysis(shellcode: bytes) -> str:
    """
    Disassemble the shellcode using Capstone (x86 32-bit).

    :param shellcode: raw shellcode bytes
    :return: disassembly listing as a string
    """
    try:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        lines = []
        for insn in md.disasm(shellcode, 0x1000):
            lines.append(f"  0x{insn.address:08x}:  {insn.mnemonic:<10} {insn.op_str}")

        if not lines:
            return "(no instructions disassembled)"

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Capstone error: {e}")
        return f"(capstone error: {e})"


def get_llm_analysis(shellcode: bytes, strings: list[str], capstone_output: str, pylibemu_output: str) -> str:
    """
    Send shellcode analysis data to the OpenAI API and return its explanation.

    :param shellcode: raw shellcode bytes
    :param strings: extracted strings from get_shellcode_strings()
    :param capstone_output: disassembly from get_capstone_analysis()
    :param pylibemu_output: emulation output from get_pylibemu_analysis()
    :return: LLM explanation string
    """
    api_key = os.getenv("OPENAI_KEY")
    if not api_key:
        logger.warning("OPENAI_KEY not set in environment — skipping LLM analysis.")
        return "(OPENAI_KEY not configured)"

    prompt = f"""You are a malware analyst. Analyze the following shellcode and explain clearly what it does.

Shellcode size: {len(shellcode)} bytes
Shellcode (hex): {shellcode.hex()}

Extracted strings:
{chr(10).join(strings) if strings else "(none)"}

Pylibemu emulation output:
{pylibemu_output}

Capstone disassembly (x86 32-bit):
{capstone_output}

Provide a detailed explanation of:
1. What this shellcode does (its purpose)
2. Which OS / architecture it targets
3. Any notable techniques used (API hashing, obfuscation, etc.)
4. Any indicators of compromise (IPs, filenames, commands)
Respond in French.
"""

    try:
        response = requests.post(
            OPENAI_API_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": OPENAI_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            },
            timeout=60,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"].strip()

    except requests.exceptions.HTTPError as e:
        logger.error(f"OpenAI API HTTP error: {e} — {response.text}")
        return f"(OpenAI API error: {e})"
    except Exception as e:
        logger.error(f"LLM analysis error: {e}")
        return f"(LLM error: {e})"
