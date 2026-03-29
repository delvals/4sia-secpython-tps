import argparse
import sys

from tp2.utils.config import logger
from tp2.utils.shellcode import (
    get_capstone_analysis,
    get_llm_analysis,
    get_pylibemu_analysis,
    get_shellcode_strings,
)


#####################################################################################################
# FUNCS
#####################################################################################################


def load_shellcode(filepath: str) -> bytes:
    """
    Load a shellcode from a file.
    Supports two formats:
      - Binary file (raw bytes)
      - Text file containing a hex string or \\xNN escape sequences

    :param filepath: path to the shellcode file
    :return: shellcode as raw bytes
    """
    with open(filepath, "rb") as f:
        raw = f.read()

    # Try to decode as text (hex escapes like \xEB\x54...)
    try:
        text = raw.decode("ascii").strip()
        # Remove spaces, newlines, common delimiters
        text = text.replace(" ", "").replace("\n", "").replace("\\x", "")
        # If the result is valid hex, parse it
        if all(c in "0123456789abcdefABCDEF" for c in text):
            return bytes.fromhex(text)
    except Exception:
        pass

    # Fallback: treat as raw binary
    return raw


def analyse_shellcode(shellcode: bytes) -> None:
    """
    Run the full analysis pipeline on a shellcode and log results.

    :param shellcode: raw shellcode bytes
    """
    logger.info(f"Testing shellcode of size {len(shellcode)}B")

    # 1. Strings
    strings = get_shellcode_strings(shellcode)
    logger.info("Shellcode analysed!")
    if strings:
        logger.info(f"Extracted strings ({len(strings)}):")
        for s in strings:
            logger.info(f"  {s}")
    else:
        logger.info("  No printable strings found.")

    # 2. Pylibemu
    logger.info("--- Pylibemu emulation ---")
    pylibemu_output = get_pylibemu_analysis(shellcode)
    logger.info(pylibemu_output)

    # 3. Capstone disassembly
    logger.info("--- Capstone disassembly (x86 32-bit) ---")
    capstone_output = get_capstone_analysis(shellcode)
    logger.info(f"\n{capstone_output}")

    # 4. LLM analysis
    logger.info("--- LLM analysis ---")
    llm_output = get_llm_analysis(shellcode, strings, capstone_output, pylibemu_output)
    logger.info(f"Explication LLM : {llm_output}")


#####################################################################################################
# MAIN
#####################################################################################################


def main():
    parser = argparse.ArgumentParser(description="TP2 — Shellcode analyser")
    parser.add_argument("-f", "--file", required=True, help="Path to the shellcode file")
    args = parser.parse_args()

    try:
        shellcode = load_shellcode(args.file)
    except FileNotFoundError:
        logger.error(f"File not found: {args.file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load shellcode: {e}")
        sys.exit(1)

    analyse_shellcode(shellcode)


if __name__ == "__main__":
    main()
