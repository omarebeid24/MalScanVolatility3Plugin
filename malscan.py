

import hashlib
import logging
import re
from typing import Dict, Iterable, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, scanners
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Weight each distinct scored indicator contributes to the risk score.
SEVERITY_WEIGHT = {"INFO": 0, "LOW": 1, "MEDIUM": 4, "HIGH": 10, "CRITICAL": 20}

INDICATORS: Dict[str, Dict] = {
    # ----------------------------------------------------------------- HIGH
    "RANSOMWARE_FAMILY": {
        "severity": "INFO",
        "boundary": True,
        "description": "Ransomware family name - CONTEXT ONLY, never scored. The "
                       "name appears in antivirus data, security documentation, "
                       "keyword lists and URLs as readily as in real malware",
        "terms": [
            "WannaCry", "WanaCrypt0r", "Wana Decrypt0r", "WCRY",
            "CryptoLocker", "CryptoWall", "TeslaCrypt", "Cerber", "Locky",
            "NotPetya", "GoldenEye", "BadRabbit", "Ryuk", "REvil",
            "Sodinokibi", "DarkSide", "BlackMatter", "LockBit", "ALPHV",
            "BlackCat", "Cl0p", "Egregor", "Netwalker", "DoppelPaymer",
            "BitPaymer", "Avaddon", "AvosLocker", "Babuk", "BlackBasta",
            "Black Basta", "Rhysida", "MedusaLocker", "Qilin",
            "RagnarLocker", "Ragnar Locker", "GandCrab", "Nefilim",
            "Mount Locker", "Zeppelin", "Mespinoza", "HelloKitty",
            "Karakurt", "BianLian", "Trigona", "RansomHouse",
            "Rorschach", "LostTrust", "DragonForce", "FunkSec", "INC Ransom",
            "Phobos", "Dharma", "CrySiS", "Makop", "Zeppelin",
            "8base", "ThreeAM", "Money Message", "Vice Society",
        ],
    },
    "RANSOM_NOTE_TEXT": {
        "severity": "HIGH",
        "boundary": False,
        "description": "Extortion sentence from a ransom note - a full clause, "
                       "not a generic phrase",
        "terms": [
            "your files have been encrypted",
            "your files are encrypted",
            "all your files have been encrypted",
            "all of your files are encrypted",
            "your files have been locked",
            "your network has been breached",
            "your data has been stolen",
            "your important files are encrypted",
            "the only way to decrypt your files",
            "way to decrypt your files is",
            "to decrypt your files you need",
            "pay the ransom",
            "send bitcoin to",
            "personal decryption key",
            "buy the decryption tool",
            "do not rename encrypted files",
            "do not try to decrypt",
            "your unique id",
            "contact us by email",
            "discuss the price and how to decrypt",
        ],
    },
    "RANSOM_NOTE_FILENAME": {
        "severity": "MEDIUM",
        "boundary": False,
        "description": "Ransom note filename - weak on its own; meaningful when "
                       "it appears with note text or an encrypted extension",
        "terms": [
            "how_to_decrypt", "how-to-decrypt", "how to decrypt files",
            "howtodecrypt",
            "readme_for_decrypt", "decrypt_instruction",
            "decrypt-files", "recover_files", "recovery_key",
            "restore-my-files", "restore_files",
            "your_files_are_encrypted", "_readme.txt",
            "help_decrypt", "help_your_files", "!!!read_me",
            "read_me_for_decrypt", "unlock_files",
            "recovery_instructions",
        ],
    },
    "SHADOW_COPY_DESTRUCTION": {
        "severity": "HIGH",
        "boundary": False,
        "description": "Backup / shadow copy destruction (classic pre-encryption step)",
        "terms": [
            "vssadmin delete shadows",
            "vssadmin.exe delete shadows",
            "delete shadows /all",
            "shadowcopy delete",
            "wmic shadowcopy delete",
            "wbadmin delete catalog",
            "wbadmin delete systemstatebackup",
            "wbadmin delete backup",
            "recoveryenabled no",
            "bootstatuspolicy ignoreallfailures",
            "resize shadowstorage",
        ],
    },
    "ANTI_FORENSICS": {
        "severity": "MEDIUM",
        "boundary": False,
        "description": "Secure deletion / free-space wiping / log destruction. "
                       "NOT shadow copy destruction - these tools erase data and "
                       "traces, they do not touch VSS",
        "terms": [
            # cipher /w wipes free space and sdelete securely deletes files.
            # Neither removes shadow copies; classifying them as such was wrong.
            "cipher /w:",
            "sdelete.exe", "sdelete64",
            "fsutil usn deletejournal",
            "fsutil file setzerodata",
            "wevtutil cl",
            "clear-eventlog",
            "remove-eventlog",
            "auditpol /clear",
        ],
    },
    "DEFENSE_EVASION": {
        "severity": "HIGH",
        "boundary": False,
        "description": "A command that turns protection off (verb + target, not "
                       "just a setting name)",
        "terms": [
         
            "add-mppreference -exclusionpath",
            "set-mppreference -disable",
            "set-mppreference -exclusion",
            "remove-mppreference",
            "sc stop windefend",
            "net stop windefend",
            "sc config windefend",
            "sc delete windefend",
            "uninstall-windowsfeature windows-defender",
            "netsh advfirewall set allprofiles state off",
            "netsh firewall set opmode disable",
            "auditpol /set",
        ],
    },
    "SECURITY_SETTING_NAME": {
        "severity": "LOW",
        "boundary": False,
        "description": "Name of a security setting or AMSI API. Present on every "
                       "clean Windows install - proves nothing without a verb, a "
                       "value and execution context",
        "terms": [
            "disablerealtimemonitoring",
            "disableantispyware",
            "disablebehaviormonitoring",
            "disableioavprotection",
            "disableantivirus",
            "disablescriptscanning",
            # AmsiScanBuffer is a normal export of amsi.dll; amsiInitFailed is a
            # real .NET field name that legitimate PowerShell binaries contain.
            "amsiscanbuffer",
            "amsiinitfailed",
            "amsiutils",
        ],
    },
    "CREDENTIAL_ACCESS": {
        "severity": "HIGH",
        "boundary": False,
        "description": "Credential dumping tooling and commands",
        "terms": [
            "sekurlsa::logonpasswords", "sekurlsa::", "lsadump::",
            "privilege::debug", "kerberos::", "crypto::",
            "mimikatz", "invoke-mimikatz", "gentilkiwi",
            "procdump -ma lsass", "procdump.exe -ma lsass",
            "lsass.dmp", "comsvcs.dll, minidump", "comsvcs.dll minidump",
            "secretsdump", "pwdump", "samdump", "kerberoast",
            "rubeus.exe", "lazagne",
        ],
    },
    "MALWARE_TOOLING": {
        "severity": "INFO",
        "boundary": True,
        "description": "Malware / tooling name - CONTEXT ONLY, never scored",
        "terms": [
            "Emotet", "TrickBot", "QakBot", "Qbot", "IcedID", "BazarLoader",
            "BazarBackdoor", "Cobalt Strike", "CobaltStrike", "ReflectiveLoader",
            "meterpreter", "Metasploit", "PowerSploit",
            "BruteRatel", "Brute Ratel", "SystemBC", "Dridex", "Ursnif",
            "Gozi", "FormBook", "AgentTesla", "Agent Tesla", "RedLine Stealer",
            "Raccoon Stealer", "Vidar", "LummaC2", "Amadey", "SmokeLoader",
            "AsyncRAT", "njRAT", "Remcos", "QuasarRAT", "DarkComet",
            "NanoCore", "Gh0st RAT", "PlugX", "Ghostpack", "SharpHound",
            "BloodHound", "Impacket", "PoshC2", "Koadic",
        ],
    },
    # --------------------------------------------------------------- MEDIUM
    "ENCRYPTION_ACTIVITY": {
        "severity": "MEDIUM",
        "boundary": False,
        "description": "Embedded key material or ransomware-style crypto claims",
        "terms": [
            "-----begin rsa public key",
            "-----begin rsa private key",
            "-----begin public key",
            "encrypted with rsa", "encrypted using rsa",
            "rsa-2048", "rsa-4096", "aes-256 encryption",
            "military grade encryption",
            "salsa20", "curve25519",
        ],
    },
    "ENCRYPTED_EXTENSION": {
        "severity": "MEDIUM",
        "boundary": False,
        "description": "File extension appended by a known ransomware family",
        "terms": [
            ".wncry", ".wcry", ".wnry", ".locky", ".odin", ".thor", ".zepto",
            ".cerber3", ".crypz", ".cryp1", ".lockbit", ".lockedfile",
            ".conti", ".ryk", ".djvu", ".basta", ".akira", ".royal",
            ".8base", ".phobos", ".makop", ".mkp", ".rhysida", ".qlin",
            ".avdn", ".babyk", ".blackbit", ".encrypted", ".enc1",
            ".onion.file", ".darkside", ".sodinokibi", ".revil",
        ],
    },
    "PERSISTENCE": {
        "severity": "MEDIUM",
        "boundary": False,
        "description": "Autorun / scheduled task / service persistence",
        "terms": [
            "schtasks /create", "schtasks.exe /create", "new-scheduledtask",
            "register-scheduledtask",
            "currentversion\\run", "currentversion\\runonce",
            "image file execution options",
            "sc create", "sc.exe create", "new-service",
            "__eventfilter", "commandlineeventconsumer",
            "activescripteventconsumer", "__filtertoconsumerbinding",
            "\\startup\\", "userinit.exe,",
        ],
    },
    "POWERSHELL_ABUSE": {
        "severity": "MEDIUM",
        "boundary": False,
        "description": "Obfuscated / download-and-execute PowerShell",
        "terms": [
            "-encodedcommand", "powershell -enc", "powershell.exe -enc",
            "-nop -w hidden", "-noprofile -windowstyle hidden",
            "-w hidden -c", "-executionpolicy bypass", "-ep bypass",
            "iex(new-object", "iex (new-object", "invoke-expression",
            "downloadstring(", "downloadfile(", "net.webclient",
            "frombase64string", "invoke-webrequest -uri",
            "[reflection.assembly]::load", "system.reflection.assembly",
            "start-process -windowstyle hidden",
        ],
    },
    "LOLBIN_ABUSE": {
        "severity": "MEDIUM",
        "boundary": False,
        "description": "Living-off-the-land binary used for download or execution",
        "terms": [
            "certutil -urlcache", "certutil.exe -urlcache", "certutil -decode",
            "bitsadmin /transfer", "regsvr32 /s /u /i:", "regsvr32 /i:http",
            "mshta http", "mshta.exe javascript", "rundll32 javascript:",
            "wmic process call create", "msiexec /q /i http",
            "installutil.exe /logfile=", "odbcconf /a", "forfiles /c",
            "cmd.exe /c", "cmd /c ", "cscript //e:", "wscript.shell",
            "psexec", "psexesvc", "paexec",
        ],
    },
    "C2_ANONYMITY": {
        "severity": "MEDIUM",
        "boundary": False,
        "description": "Tor / anonymised infrastructure or webhook C2",
        "terms": [
            ".onion", "torproject.org", "tor browser", "tor2web",
            "onion.to", "onion.ws", "onion.pet", "onion.city",
            "socks5://", "ngrok.io", "trycloudflare.com",
            "anonfiles.com", "mega.nz", "transfer.sh", "gofile.io",
            "pastebin.com/raw", "discord.com/api/webhooks",
            "discordapp.com/api/webhooks", "api.telegram.org/bot",
        ],
    },
    "EXFILTRATION_STAGING": {
        "severity": "MEDIUM",
        "boundary": False,
        "description": "Archiving / transfer tooling typical of data theft",
        "terms": [
            "7z.exe a -p", "rar.exe a -hp", "winrar", "rclone",
            "rclone.exe copy", "megacmd", "megasync", "filezilla",
            "-hp -r -v", "wget -q -O", "curl -T ",
        ],
    },
    # ------------------------------------------------------------------ LOW
    "FAMILY_NAME_WEAK": {
        "severity": "INFO",
        "boundary": True,
        "description": "Malware/ransomware name that is also an ordinary word, a "
                       "person's name or a file format - very low confidence",
        "terms": [
            "Conti", "Maze", "Hive", "Play", "Royal", "Cuba", "Matrix",
            "Agenda", "Medusa", "Snatch", "Knight", "Abyss", "Cactus",
            "Clop", "Hades", "Pysa", "Prometheus", "Sugar",
            "Empire", "Covenant", "Sliver", "Havoc",
            # Akira is a common Japanese given name, DjVu is a document format
            # that appears in every MIME type list, and NoEscape collides with
            # the POSIX glob flag FNM_NOESCAPE.  None of these are "unambiguous".
            "Akira", "Djvu", "NoEscape",
        ],
    },
    "CRYPTO_API": {
        "severity": "LOW",
        "boundary": True,
        "description": "Cryptographic API name (ubiquitous in normal export "
                       "tables - useful mainly with --processes)",
        "terms": [
            "CryptEncrypt", "CryptGenKey", "CryptImportKey",
            "CryptAcquireContext", "CryptDeriveKey", "CryptGenRandom",
            "BCryptEncrypt", "BCryptGenerateSymmetricKey",
            "BCryptImportKeyPair", "BCryptGenRandom", "ChaCha20",
        ],
    },
    "PROCESS_INJECTION_API": {
        "severity": "LOW",
        "boundary": True,
        "description": "Injection API name (also present in normal export tables)",
        "terms": [
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "QueueUserAPC",
            "NtQueueApcThread", "SetThreadContext", "RtlCreateUserThread",
            "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
            "NtCreateThreadEx", "SetWindowsHookExA", "SetWindowsHookExW",
        ],
    },
    "REMOTE_ACCESS_TOOL": {
        "severity": "LOW",
        "boundary": True,
        "description": "Remote access / RMM agent (legitimate, but commonly abused)",
        "terms": [
            "AnyDesk", "TeamViewer", "ScreenConnect", "ConnectWise Control",
            "Splashtop", "RustDesk", "MeshAgent", "Atera", "Syncro",
            "LogMeIn", "Radmin", "DWAgent",
        ],
    },
    "CRYPTO_WALLET": {
        "severity": "LOW",
        "boundary": False,
        "description": "Cryptocurrency wallet / payment references",
        "terms": [
            "bitcoin:", "bitcoin address", "btc address", "btc wallet",
            "blockchain.info", "blockchain.com/btc", "blockchair.com",
            "wallet.dat", "electrum", "metamask", "exodus wallet",
            "monero", "xmr address", "coinbase.com/checkouts",
        ],
    },
}

# Regex indicators 

REGEX_INDICATORS: Dict[str, Dict] = {
    "BITCOIN_ADDRESS": {
        "severity": "LOW",
        "pattern": rb"(?:bc1[02-9ac-hj-np-z]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})",
    },
    "MONERO_ADDRESS": {
        "severity": "LOW",
        "pattern": rb"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}",
    },
}

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _base58check_valid(address: str) -> bool:
    """Verify a legacy Bitcoin address: 25 bytes ending in a SHA256d checksum."""
    value = 0
    for char in address:
        index = _BASE58_ALPHABET.find(char)
        if index < 0:
            return False
        value = value * 58 + index
    if value.bit_length() > 200:
        return False
    try:
        decoded = value.to_bytes(25, "big")
    except OverflowError:
        return False
    payload, checksum = decoded[:21], decoded[21:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    return digest[:4] == checksum


def _bech32_valid(address: str) -> bool:
    """Verify a native segwit (bc1...) address under BIP-173 or BIP-350."""
    address = address.lower()
    if not address.startswith("bc1") or len(address) < 8:
        return False
    data = []
    for char in address[3:]:
        index = _BECH32_ALPHABET.find(char)
        if index < 0:
            return False
        data.append(index)
    # Expanded human-readable part for "bc", then the data part.
    values = [ord("b") >> 5, ord("c") >> 5, 0, ord("b") & 31, ord("c") & 31] + data
    checksum = 1
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, constant in enumerate(generator):
            if (top >> bit) & 1:
                checksum ^= constant
    return checksum in (1, 0x2BC830A3)  # bech32, bech32m


def _wallet_address_valid(category: str, value: str) -> bool:
    if category == "BITCOIN_ADDRESS":
        if value.startswith("bc1"):
            return _bech32_valid(value)
        return _base58check_valid(value)
    if category == "MONERO_ADDRESS":
       
        return len(value) == 95 and len(set(value)) >= 20
    return True


def _wide(text: str) -> bytes:
    """UTF-16LE encoding of a term, as it usually appears in Windows memory."""
    return text.encode("utf-16-le")


def _is_word_byte(value: int) -> bool:
    """True for [0-9a-z_] (the data is lower-cased before matching).

    Underscore counts as a word character, otherwise the indicator
    ``_readme.txt`` (the STOP/Djvu ransom note) matches inside the perfectly
    innocent filename ``HEARTBEAT_README.TXT``.
    """
    return 48 <= value <= 57 or 97 <= value <= 122 or value == 95


def _is_word_char(char: str) -> bool:
    """Same rule, for deciding which side of a term needs a boundary check."""
    return char.isalnum() or char == "_"


def _printable_run_length(lowered: bytes, start: int, end: int, wide: bool) -> int:
    """Length of the readable text run containing a match.

    This is what separates a command someone actually typed from a fragment of
    a compressed antivirus database.  Real command lines sit inside long spans
    of printable text::

        ...Roaming\\Microsoft\\Windows';Add-MpPreference -ExclusionPath 'C:\\Users...

    whereas signature-database hits are surrounded by control bytes and
    truncated tokens::

        ...H...)9BSet-MpPreference -.DisableRealtimeMonitoring!#TEL..S.ysdupate...

    Walking outwards while the bytes stay printable measures exactly that.
    """
    step = 2 if wide else 1

    def readable(index: int) -> bool:
        if index < 0 or index >= len(lowered):
            return False
        if wide and lowered[index + 1: index + 2] not in (b"\x00",):
            return False
        return 0x20 <= lowered[index] <= 0x7E

    left = start
    while left - step >= 0 and readable(left - step):
        left -= step
    right = end
    while right < len(lowered) and readable(right):
        right += step
    return (right - left) // step


AV_CONTEXT_MARKERS = [
    b"trojan:", b"trojandownloader", b"trojanspy", b"trojandropper",
    b"backdoor:", b"virtool:", b"hacktool:", b"ransom:", b"worm:",
    b"exploit:", b"behavior:", b"pua:", b"pup:", b"program:", b"adware:",
    b"win32/", b"win64/", b"msil/", b"script/", b"o97m/", b"html/",
    b"!mtb", b"!msr", b"!ml", b"!bit", b"aggr:", b"hstr:",
    b"mpengine", b"msmpeng", b"mpasbase", b"mpavbase",
    b"eicar", b"gen:variant", b"gen:heur", b"a variant of",
]

AV_CONTEXT_PATTERNS = AV_CONTEXT_MARKERS + [
    marker.decode("latin-1").encode("utf-16-le") for marker in AV_CONTEXT_MARKERS
]

# How far either side of a hit to look for those markers.
AV_CONTEXT_WINDOW = 96

AV_PROCESSES = frozenset(
    {
        # Microsoft Defender
        "msmpeng.exe",
        "mpdefendercoreservice.exe",
        "mpcmdrun.exe",
        "nissrv.exe",
        "securityhealthservice.exe",
        "msmpsvc.exe",
        "mssense.exe",
        "senseir.exe",
        "sensecncproxy.exe",
        # Third-party endpoint protection
        "avp.exe", "avgui.exe", "avastsvc.exe", "avguard.exe",
        "mcshield.exe", "ekrn.exe", "bdagent.exe", "vsserv.exe",
        "savservice.exe", "sophosfilescanner.exe", "sophoshealth.exe",
        "cylancesvc.exe", "csfalconservice.exe", "sentinelagent.exe",
        "elastic-endpoint.exe", "xagt.exe", "cbdefense.exe", "cbcomms.exe",
        "tmbmsrv.exe", "coreserviceshell.exe", "egui.exe", "fshoster32.exe",
    }
)


NON_ATTRIBUTABLE_PROCESSES = frozenset(
    {
        "memcompression",
        "memory compression",
        "memcompression.exe",
    }
)

# Why a hit was demoted out of the score, and how to word it.
DEMOTION_REASONS = {
    "av_data": "in AV signature data",
    "fragment": "without command context",
    "av_process": "owned by an antivirus process",
    "compressed": "in compressed memory, original process unknown",
    "unattributed": "not owned by any process",
}


class IndicatorScanner(scanners.MultiStringScanner):
    """Case-insensitive multi-string scanner with word-boundary filtering.

    Two tricks keep this to a single cheap pass:

    * Every pattern is stored lower-cased and each chunk of memory is
      lower-cased before matching.  ``bytes.lower()`` only touches A-Z, so it
      is safe for UTF-16LE (``L\\x00`` becomes ``l\\x00``) and it means we need
      one pattern per encoding instead of one per capitalisation - a quarter of
      the trie, and a correspondingly faster regex.
    * Word-boundary validation happens here, against the chunk we already hold,
      so no extra layer reads are needed to reject "Conti" inside "continue".
    """

    thread_safe = True
    _version = (1, 0, 0)

    def __init__(
        self,
        patterns: List[bytes],
        boundary_left: set,
        boundary_right: set,
        av_filter: bool = True,
    ) -> None:
        super().__init__(patterns)
        self._boundary_left = boundary_left
        self._boundary_right = boundary_right
        self._av_filter = av_filter

    def _looks_like_av_data(
        self, lowered: bytes, start: int, end: int, pattern: bytes
    ) -> bool:
        """True when a hit sits inside antivirus signature-name data."""
        # Detection names are punctuated: "!Emotet", ":Koadic", "/Empire".
        step = 2 if b"\x00" in pattern else 1
        if start >= step and lowered[start - step] in (0x21, 0x3A, 0x2F):
            return True
        window = lowered[max(0, start - AV_CONTEXT_WINDOW): end + AV_CONTEXT_WINDOW]
        return any(marker in window for marker in AV_CONTEXT_PATTERNS)

    def __call__(self, data: bytes, data_offset: int):
        lowered = data.lower()
        for offset, pattern in self.search(lowered):
            if offset >= self.chunk_size:
                continue
            end = offset + len(pattern)
            step = 2 if b"\x00" in pattern else 1
            if pattern in self._boundary_left:
                if offset >= step and _is_word_byte(lowered[offset - step]):
                    continue
            if pattern in self._boundary_right:
                if end < len(lowered) and _is_word_byte(lowered[end]):
                    continue
            av_context = self._av_filter and self._looks_like_av_data(
                lowered, offset, end, pattern
            )
            run = _printable_run_length(lowered, offset, end, b"\x00" in pattern)
            yield offset + data_offset, pattern, av_context, run


class MalScan(interfaces.plugins.PluginInterface):
    """Scans a memory image for malware, ransomware and attacker-tooling
    indicators in a single pass, with severity scoring and optional process
    attribution."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    _MAX_EXAMPLES = 8

    _SCORE_CAP_PER_CATEGORY = 5

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ChoiceRequirement(
                name="min_severity",
                description="Only report indicators at or above this severity. "
                            "LOW or above hides the context-only family names",
                choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                default="INFO",
                optional=True,
            ),
            requirements.ListRequirement(
                name="categories",
                description="Restrict the scan to these categories "
                            "(e.g. --categories RANSOM_NOTE PERSISTENCE)",
                element_type=str,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="show_hits",
                description="List every individual hit under each indicator",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="show_context",
                description="Include the surrounding bytes for each hit",
                default=False,
                optional=True,
            ),
            requirements.IntRequirement(
                name="context_size",
                description="Bytes of context to show on either side of a hit",
                default=32,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="no_av_filter",
                description="Do not discount hits that sit inside antivirus "
                            "signature-name data (Defender keeps its whole "
                            "detection-name database in memory)",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="processes",
                description="Attribute hits to the owning process "
                            "(requires kernel symbols; slower)",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="wallets",
                description="Additional pass for cryptocurrency wallet addresses "
                            "(adds one full scan of the image)",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="virtual",
                description="Scan the virtual address space instead of the "
                            "underlying physical layer",
                default=False,
                optional=True,
            ),
            requirements.IntRequirement(
                name="max_hits",
                description="Stop after this many raw matches (0 = unlimited)",
                default=0,
                optional=True,
            ),
        ]

    # ------------------------------------------------------------------
    # Layer selection
    # ------------------------------------------------------------------

    def _target_layer(self) -> interfaces.layers.DataLayerInterface:
        kernel = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[kernel.layer_name]
        if self.config.get("virtual", False):
            return layer
        while layer.dependencies:
            lower = self.context.layers[layer.dependencies[0]]
            if not isinstance(lower, interfaces.layers.DataLayerInterface):
                break
            layer = lower
        return layer

    def _is_translated(self) -> bool:
        kernel_name = self.config.get("kernel", None)
        if not kernel_name or kernel_name not in self.context.modules:
            return False
        layer_name = self.context.modules[kernel_name].layer_name
        return isinstance(self.context.layers.get(layer_name, None), intel.Intel)

    # ------------------------------------------------------------------
    # Pattern construction
    # ------------------------------------------------------------------

    def _build_pattern_map(self):

        wanted = self.config.get("categories", None)
        if wanted:
            wanted = {str(c).strip().upper() for c in wanted}
            unknown = wanted - set(INDICATORS)
            if unknown:
                vollog.warning(f"Unknown categories ignored: {', '.join(sorted(unknown))}")

        lookup: Dict[bytes, Tuple[str, str, str, bool]] = {}
        boundary_left, boundary_right = set(), set()
        min_rank = SEVERITY_RANK[self.config.get("min_severity", "LOW")]

        reporting = set()
        for category, spec in INDICATORS.items():
            if wanted and category not in wanted:
                continue
            if SEVERITY_RANK[spec["severity"]] < min_rank:
                continue
            reporting.add(category)
        reporting_regex = {
            name
            for name in REGEX_INDICATORS
            if (not wanted or name in wanted)
            and SEVERITY_RANK[REGEX_INDICATORS[name]["severity"]] >= min_rank
        }

        for category, spec in INDICATORS.items():
            if category not in reporting and category not in self._NAME_CATEGORIES:
                continue
            for term in spec["terms"]:
                lowered = term.lower()

                needs_left = spec["boundary"] or _is_word_char(lowered[0])
                needs_right = spec["boundary"] or _is_word_char(lowered[-1])
                for pattern in (
                    lowered.encode("latin-1", "ignore"),
                    _wide(lowered),
                ):
                    if len(pattern) < 3:
                        continue
                    # First writer wins: keeps the most specific category when
                    # two categories happen to share a term.
                    lookup.setdefault(
                        pattern,
                        (category, spec["severity"], term, needs_left or needs_right),
                    )
                    if needs_left:
                        boundary_left.add(pattern)
                    if needs_right:
                        boundary_right.add(pattern)

        return (
            list(lookup.keys()),
            lookup,
            (boundary_left, boundary_right),
            reporting | reporting_regex,
        )

    # ------------------------------------------------------------------
    # Process attribution
    # ------------------------------------------------------------------

    def _resolve_kernel_module(self) -> Optional[str]:
        """Name of the kernel module, or None when this variant has no kernel."""
        return self.config.get("kernel", None)

    def _build_owner_map(self) -> Dict[int, Tuple[int, str]]:

        owners: Dict[int, Tuple[int, str]] = {}
        kernel_name = self._resolve_kernel_module()
        if not kernel_name:
            vollog.warning(
                "--processes requested but the Windows kernel module could not "
                "be resolved (no symbols for this image, or not a Windows "
                "image); reporting offsets without process attribution."
            )
            return owners


        try:
            from volatility3.plugins.windows import pslist
        except ImportError as excp:
            vollog.warning(f"pslist unavailable, skipping attribution: {excp}")
            return owners

        sanity_limit = 1 << 30  # ignore absurd VADs
        seen_ranges = set()
        for task in pslist.PsList.list_processes(
            context=self.context, kernel_module_name=kernel_name
        ):
            try:
                pid = int(task.UniqueProcessId)
                name = task.ImageFileName.cast(
                    "string", max_length=task.ImageFileName.vol.count, errors="replace"
                )
                proc_layer = self.context.layers[task.add_process_layer()]
            except Exception as excp:  # noqa: BLE001 - never let one process kill the map
                vollog.debug(f"Could not open process layer: {excp}")
                continue

            try:
                vads = [
                    (vad.get_start(), vad.get_size())
                    for vad in task.get_vad_root().traverse()
                ]
            except Exception as excp:  # noqa: BLE001
                vollog.debug(f"Could not walk VADs for pid {pid}: {excp}")
                continue

            for start, size in vads:
                if size <= 0 or size > sanity_limit:
                    continue
                try:
                    runs = proc_layer.mapping(start, size, ignore_errors=True)
                except exceptions.VolatilityException:
                    continue
                for _vaddr, _vlen, paddr, plen, _layer in runs:
                    first = paddr >> 12
                    last = (paddr + max(plen, 1) - 1) >> 12

                    if (first, last) in seen_ranges:
                        continue
                    seen_ranges.add((first, last))
                    for page in range(first, last + 1):
                        owners.setdefault(page, (pid, name))

        vollog.info(f"Attribution map built for {len(owners)} physical pages")
        return owners

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    _AV_BLOCK_SHIFT = 16  # 64 KiB blocks
    _AV_GAP_BLOCKS = 32  # close gaps up to 2 MiB between signature-data blocks
    _AV_DENSITY = 4  # distinct family names in one block => signature database
    _NAME_CATEGORIES = frozenset(
        {"MALWARE_TOOLING", "RANSOMWARE_FAMILY", "FAMILY_NAME_WEAK"}
    )
    _HIT_LIMIT = 2_000_000  # hard cap so a pathological image cannot exhaust RAM

    _COMMAND_CATEGORIES = frozenset(
        {
            "SHADOW_COPY_DESTRUCTION",
            "ANTI_FORENSICS",
            "DEFENSE_EVASION",
            "CREDENTIAL_ACCESS",
            "POWERSHELL_ABUSE",
            "LOLBIN_ABUSE",
            "PERSISTENCE",
            "EXFILTRATION_STAGING",
        }
    )
    _MIN_COMMAND_RUN = 24  # printable characters around the match


    _SCORING_CATEGORIES = frozenset(
        {
            "RANSOM_NOTE_TEXT",
            "RANSOM_NOTE_FILENAME",
            "SHADOW_COPY_DESTRUCTION",
            "ANTI_FORENSICS",
            "DEFENSE_EVASION",
            "CREDENTIAL_ACCESS",
            "POWERSHELL_ABUSE",
            "LOLBIN_ABUSE",
            "PERSISTENCE",
            "EXFILTRATION_STAGING",
            "ENCRYPTION_ACTIVITY",
            "ENCRYPTED_EXTENSION",
            "C2_ANONYMITY",
        }
    )

    def _scan(self, layer, patterns, lookup, boundary_patterns, reporting, owners):

        context_size = max(0, int(self.config.get("context_size", 32)))
        need_context = self.config.get("show_context", False)
        max_hits = int(self.config.get("max_hits", 0) or 0)
        attribution_on = bool(owners)

        scanner = IndicatorScanner(
            patterns,
            boundary_patterns[0],
            boundary_patterns[1],
            not self.config.get("no_av_filter", False),
        )

        hits: List[Tuple[int, Tuple[str, str, str], int, bool, int]] = []
        av_blocks = set()

        # ---- phase 1: scan ---------------------------------------------
        for offset, matched, av_context, run_length in layer.scan(
            context=self.context, scanner=scanner
        ):
            entry = lookup.get(matched)
            if entry is None:
                # The trie can return a longer overlapping pattern; fall back to
                # the longest known prefix.
                for length in range(len(matched) - 1, 2, -1):
                    entry = lookup.get(matched[:length])
                    if entry is not None:
                        matched = matched[:length]
                        break
            if entry is None:
                continue

            category, severity, label, _boundary = entry
            encoding = "UTF-16LE" if b"\x00" in matched else "ASCII"
            hits.append(
                (offset, (category, label, encoding), len(matched), av_context,
                 run_length)
            )
            if av_context:
                av_blocks.add(offset >> self._AV_BLOCK_SHIFT)

            if max_hits and len(hits) >= max_hits:
                vollog.info(f"--max-hits limit of {max_hits} reached, stopping scan")
                break
            if len(hits) >= self._HIT_LIMIT:
                vollog.warning(
                    f"Internal hit limit of {self._HIT_LIMIT} reached; "
                    "results are truncated (narrow the scan with --categories)"
                )
                break


        if not self.config.get("no_av_filter", False):
            per_block: Dict[int, set] = {}
            for offset, key, _length, _av, _run in hits:
                if key[0] in self._NAME_CATEGORIES:
                    per_block.setdefault(offset >> self._AV_BLOCK_SHIFT, set()).add(
                        key[1]
                    )
            for block, labels in per_block.items():
                if len(labels) >= self._AV_DENSITY:
                    av_blocks.add(block)

        av_blocks_direct = set(av_blocks)

        if av_blocks:
            flagged = sorted(av_blocks)
            previous = flagged[0]
            for block in flagged[1:]:
                if 1 < block - previous <= self._AV_GAP_BLOCKS:
                    av_blocks.update(range(previous + 1, block))
                previous = block

        # ---- phase 2: aggregate ----------------------------------------
        results: Dict[Tuple[str, str, str], Dict] = {}

        reported_hits = 0
        for offset, key, length, av_context, run_length in hits:
            category, label, encoding = key
            if category not in reporting:
                continue
            reported_hits += 1
            block = offset >> self._AV_BLOCK_SHIFT

            if category in self._NAME_CATEGORIES:
                in_av_data = av_context or block in av_blocks
            else:
                in_av_data = av_context or block in av_blocks_direct

            fragmentary = (
                category in self._COMMAND_CATEGORIES
                and run_length < self._MIN_COMMAND_RUN
            )


            pid, proc = owners.get(offset >> 12, (None, None))
            owner = (proc or "").lower()
            if attribution_on:
                if owner in AV_PROCESSES:
                    disposition = "av_process"
                elif owner in NON_ATTRIBUTABLE_PROCESSES:
                    disposition = "compressed"
                elif not owner:

                    disposition = "unattributed"
                elif in_av_data:
                    disposition = "av_data"
                elif fragmentary:
                    disposition = "fragment"
                else:
                    disposition = None
            elif in_av_data:
                disposition = "av_data"
            elif fragmentary:
                disposition = "fragment"
            else:
                disposition = None

            record = results.get(key)
            if record is None:
                record = {
                    "category": category,
                    "severity": INDICATORS.get(category, {}).get("severity")
                    or REGEX_INDICATORS.get(category, {}).get("severity", "LOW"),
                    "label": label,
                    "encoding": encoding,
                    "count": 0,
                    "demoted": {},
                    "owners": set(),
                    "first": None,
                    "first_any": offset,
                    "examples": [],
                    "weak_examples": [],
                }
                results[key] = record

            if disposition:
                record["demoted"][disposition] = (
                    record["demoted"].get(disposition, 0) + 1
                )
                bucket = record["weak_examples"]
            else:
                record["count"] += 1
                if record["first"] is None:
                    record["first"] = offset
                if proc:
                    record["owners"].add(f"{proc} ({pid})")
                bucket = record["examples"]

            if len(bucket) < self._MAX_EXAMPLES:

                snippet = ""
                if need_context or bucket is record["examples"]:
                    pad = max(context_size, 4)
                    try:
                        window = layer.read(
                            max(0, offset - pad), pad + length + pad, pad=True
                        )
                        snippet = self._printable(window)
                    except exceptions.InvalidAddressException:
                        snippet = ""
                bucket.append(
                    {"offset": offset, "pid": pid, "process": proc, "context": snippet,
                     "run": run_length}
                )

        if av_blocks:
            vollog.info(
                f"{len(av_blocks)} block(s) of antivirus signature data identified "
                "and discounted"
            )
        return results, reported_hits

    def _scan_wallets(self, layer, owners):
  
        results: Dict[Tuple[str, str, str], Dict] = {}
        combined = b"|".join(
            b"(?P<" + name.encode() + b">" + spec["pattern"] + b")"
            for name, spec in REGEX_INDICATORS.items()
        )
        compiled = re.compile(combined)
        scanner = scanners.RegExScanner(combined)

        for offset in layer.scan(context=self.context, scanner=scanner):
            try:
                data = layer.read(offset, 128, pad=True)
            except exceptions.InvalidAddressException:
                continue
            match = compiled.match(data) or compiled.search(data)
            if not match or not match.lastgroup:
                continue
            category = match.lastgroup
            value = match.group().decode("latin-1", "replace")
            if not _wallet_address_valid(category, value):
                continue
            severity = REGEX_INDICATORS[category]["severity"]
            key = (category, value, "ASCII")
            record = results.get(key)
            if record is None:
                record = {
                    "category": category,
                    "severity": severity,
                    "label": value,
                    "encoding": "ASCII",
                    "count": 0,
                    "demoted": {},
                    "owners": set(),
                    "first": offset,
                    "first_any": offset,
                    "examples": [],
                    "weak_examples": [],
                }
                results[key] = record
            record["count"] += 1
            if len(record["examples"]) < self._MAX_EXAMPLES:
                pid, proc = owners.get(offset >> 12, (None, None))
                record["examples"].append(
                    {"offset": offset, "pid": pid, "process": proc, "context": ""}
                )
        return results

    @staticmethod
    def _printable(data: bytes) -> str:
        text = data.decode("latin-1", "replace")
        out = []
        for char in text:
            code = ord(char)
            out.append(char if 32 <= code < 127 else ("" if code == 0 else "."))
        return "".join(out).strip()

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @staticmethod
    def _verdict(score: int, categories: int, attributed: bool) -> str:

        if score <= 0:
            return "NO ACTIONABLE INDICATORS"
        if score >= 60 and categories >= 3 and attributed:
            return "STRONG INDICATORS - TRIAGE"
        if score >= 25:
            return "INDICATORS PRESENT - REVIEW"
        return "WEAK INDICATORS - REVIEW"

    def _generator(self):
        na = renderers.NotAvailableValue()

        patterns, lookup, boundary_patterns, reporting = self._build_pattern_map()
        if not patterns or not reporting:
            vollog.warning("No indicators selected - check --categories/--min-severity")
            return

        layer = self._target_layer()
        vollog.info(
            f"Scanning layer '{layer.name}' "
            f"({layer.maximum_address / (1024 ** 2):.0f} MiB) "
            f"for {len(lookup)} byte patterns in one pass"
        )

        owners: Dict[int, Tuple[int, str]] = {}
        if self.config.get("processes", False):
            owners = self._build_owner_map()

        results, raw_hits = self._scan(
            layer, patterns, lookup, boundary_patterns, reporting, owners
        )
        if self.config.get("wallets", False):
            results.update(self._scan_wallets(layer, owners))
        demoted_totals: Dict[str, int] = {}
        for record in results.values():
            reasons = []
            for reason, wording in DEMOTION_REASONS.items():
                number = record["demoted"].get(reason, 0)
                if number:
                    demoted_totals[reason] = demoted_totals.get(reason, 0) + number
                    reasons.append(f"{number} {wording}")
            if record["count"] == 0:
                record["severity"] = "INFO"
                record["note"] = f" (only {'; '.join(reasons)})" if reasons else ""
            else:
                owners_seen = record.get("owners") or set()
                note = f" ({'; '.join(reasons)} besides)" if reasons else ""
                if owners_seen:
                    note += f" [in {', '.join(sorted(owners_seen))}]"
                record["note"] = note

        # ---- roll up per category -------------------------------------
        by_category: Dict[str, List[Dict]] = {}
        for record in results.values():
            by_category.setdefault(record["category"], []).append(record)

        score = 0
        scoring_categories = 0
        scored_regions = set()
        for category, records in by_category.items():
            if category not in self._SCORING_CATEGORIES:
                continue
            scored_here = [r for r in records if r["count"]]
            if not scored_here:
                continue
            scoring_categories += 1
            weight = max(SEVERITY_WEIGHT[r["severity"]] for r in scored_here)
            score += weight * min(len(scored_here), self._SCORE_CAP_PER_CATEGORY)
            for record in scored_here:
                for example in record["examples"]:
                    scored_regions.add(example["offset"] >> self._AV_BLOCK_SHIFT)

        if len(scored_regions) < 2:
            score = min(score, 20)

        ordered = sorted(
            by_category.items(),
            key=lambda kv: (
                -max(SEVERITY_RANK[r["severity"]] for r in kv[1]),
                -sum(r["count"] for r in kv[1]),
                kv[0],
            ),
        )

        for category, records in ordered:
            severity = max(records, key=lambda r: SEVERITY_RANK[r["severity"]])["severity"]
            total = sum(r["count"] for r in records)
            first = min(r["first"] if r["first"] is not None else r["first_any"]
                        for r in records)
            description = INDICATORS.get(category, {}).get(
                "description", "Cryptocurrency address (regex)"
            )
            scored = [r for r in records if r["count"]]

            yield (
                0,
                (
                    category,
                    severity,
                    f"{len(scored)}/{len(records)} indicator(s) scored - {description}",
                    total,
                    "",
                    format_hints.Hex(first),
                    na,
                    na,
                    "",
                ),
            )

            for record in sorted(
                records,
                key=lambda r: (-SEVERITY_RANK[r["severity"]], -r["count"], r["label"]),
            ):
                examples = record["examples"] or record["weak_examples"]
                example = examples[0] if examples else {}
                offset = record["first"] if record["first"] is not None else record["first_any"]
                yield (
                    1,
                    (
                        category,
                        record["severity"],
                        record["label"] + record.get("note", ""),
                        record["count"] or sum(record["demoted"].values()),
                        record["encoding"],
                        format_hints.Hex(offset),
                        example.get("pid") if example.get("pid") is not None else na,
                        example.get("process") or na,
                        example.get("context", ""),
                    ),
                )

                if self.config.get("show_hits", False):
                    for example in examples:
                        yield (
                            2,
                            (
                                "",
                                "",
                                "hit",
                                1,
                                record["encoding"],
                                format_hints.Hex(example["offset"]),
                                example["pid"] if example["pid"] is not None else na,
                                example["process"] or na,
                                example.get("context", ""),
                            ),
                        )


        attributed = bool(owners)
        translated = self._is_translated()

        yield (
            0,
            ("== SCAN BASIS ==", "READ THIS FIRST",
             "String matches only. A string in memory does not show that a "
             "command ran or that code executed - identical bytes appear in "
             "antivirus data, documentation, browser cache and downloaded "
             "samples. Confirm execution with process command lines, console "
             "history, script-block logs, prefetch or Amcache.",
             0, "", format_hints.Hex(0), na, na, ""),
        )
        yield (
            0,
            ("== SCAN BASIS ==",
             "OK" if translated else "LIMITED",
             "Windows translation layer: "
             + ("built; offsets are physical and resolvable to virtual space"
                if translated else
                "NOT built (truncated, partial or non-Windows image). Flat-file "
                "scan - offsets are file offsets."),
             0, "", format_hints.Hex(0), na, na, ""),
        )
        yield (
            0,
            ("== SCAN BASIS ==",
             "OK" if attributed else "LIMITED",
             "Process attribution: "
             + (f"on; {len(owners)} physical page(s) mapped to a process. "
                "Hits owned by an antivirus process, or by the compressed-memory "
                "store, are shown but never scored."
                if attributed else
                "OFF - no hit can be tied to a process, so an antivirus "
                "signature cannot be told from a live artefact and the verdict "
                "is capped. Re-run with --processes on an image whose kernel "
                "symbols resolve."),
             0, "", format_hints.Hex(0), na, na, ""),
        )
        if demoted_totals.get("av_process") or demoted_totals.get("compressed"):
            yield (
                0,
                ("== SCAN BASIS ==", "OWNERSHIP",
                 "Retired by owner: "
                 f"{demoted_totals.get('av_process', 0)} hit(s) inside an "
                 "antivirus process (expected to hold malware names, ransom "
                 "note text and malicious commands - that is what a signature "
                 f"database is), {demoted_totals.get('compressed', 0)} in the "
                 "compressed-memory store (pages compressed out of some other "
                 "process; this mapping cannot say which). Neither establishes "
                 "that anything ran.",
                 0, "", format_hints.Hex(0), na, na, ""),
            )

        # ---- indicator summary ------------------------------------------
        scored_indicators = sum(
            1
            for r in results.values()
            if r["count"] and r["category"] in self._SCORING_CATEGORIES
        )
        context_indicators = sum(
            1
            for r in results.values()
            if r["count"] and r["category"] not in self._SCORING_CATEGORIES
        )
        summary = (
            f"score {score} (indicator strength, not a probability) from "
            f"{scored_indicators} scored indicator(s) in {scoring_categories} "
            f"behavioural category/categories across {len(scored_regions)} "
            f"distinct memory region(s)"
        )
        if context_indicators:
            summary += (
                f"; {context_indicators} further name match(es) shown for context "
                f"only and deliberately not scored"
            )
        retired = [
            f"{number} {DEMOTION_REASONS[reason]}"
            for reason, number in demoted_totals.items()
            if number
        ]
        if retired:
            summary += (
                f"; {sum(demoted_totals.values())} hit(s) retired "
                f"({'; '.join(retired)})"
            )
        if not translated:
            summary += "; flat-file scan, so this cannot be more than a triage lead"
        elif not attributed:
            summary += "; without --processes, ownership is unknown"
        if score == 0:
            summary += (
                ". Nothing survived as evidence owned by a normal process, so "
                "this scan does not indicate activity on this host"
            )

        yield (
            0,
            ("== ASSESSMENT ==",
             self._verdict(score, len(scored_regions), attributed),
             summary, raw_hits, "", format_hints.Hex(0), na, na, ""),
        )

    def run(self):
        return self._build_grid()

    def _build_grid(self):
        return renderers.TreeGrid(
            [
                ("Category", str),
                ("Severity", str),
                ("Indicator", str),
                ("Hits", int),
                ("Encoding", str),
                ("Offset", format_hints.Hex),
                ("PID", int),
                ("Process", str),
                ("Context", str),
            ],
            self._generator(),
        )


class RawScan(MalScan):

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        base = [
            requirement
            for requirement in MalScan.get_requirements()
            if requirement.name not in ("kernel", "processes", "virtual")
        ]
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer to scan"
            )
        ] + base

    def _target_layer(self) -> interfaces.layers.DataLayerInterface:
        layer = self.context.layers[self.config["primary"]]
        while layer.dependencies:
            lower = self.context.layers[layer.dependencies[0]]
            if not isinstance(lower, interfaces.layers.DataLayerInterface):
                break
            layer = lower
        return layer

    def _is_translated(self) -> bool:
        return False

    def _resolve_kernel_module(self) -> Optional[str]:
        return None
