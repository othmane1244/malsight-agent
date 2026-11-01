"""API Windows sensibles, regroupées par finalité. Liste de départ à enrichir."""

SENSITIVE_APIS: dict[str, str] = {
    # Injection / manipulation de processus
    "VirtualAllocEx": "injection", "WriteProcessMemory": "injection",
    "CreateRemoteThread": "injection", "NtCreateThreadEx": "injection",
    "QueueUserAPC": "injection", "SetThreadContext": "injection",
    "NtUnmapViewOfSection": "injection", "OpenProcess": "injection",
    # Persistance
    "RegSetValueExA": "persistance", "RegSetValueExW": "persistance",
    "RegCreateKeyExA": "persistance", "RegCreateKeyExW": "persistance",
    "CreateServiceA": "persistance", "CreateServiceW": "persistance",
    # Exécution
    "CreateProcessA": "execution", "CreateProcessW": "execution",
    "ShellExecuteA": "execution", "ShellExecuteW": "execution", "WinExec": "execution",
    # Réseau
    "InternetOpenA": "reseau", "InternetOpenW": "reseau",
    "InternetOpenUrlA": "reseau", "InternetOpenUrlW": "reseau",
    "HttpSendRequestA": "reseau", "HttpSendRequestW": "reseau",
    "URLDownloadToFileA": "reseau", "URLDownloadToFileW": "reseau",
    "WSAStartup": "reseau", "connect": "reseau", "send": "reseau", "recv": "reseau",
    # Cryptographie
    "CryptEncrypt": "crypto", "CryptDecrypt": "crypto", "CryptAcquireContextA": "crypto",
    "CryptAcquireContextW": "crypto", "BCryptEncrypt": "crypto",
    # Anti-analyse / découverte
    "IsDebuggerPresent": "anti-analyse", "CheckRemoteDebuggerPresent": "anti-analyse",
    "GetTickCount": "anti-analyse", "NtQueryInformationProcess": "anti-analyse",
    "CreateToolhelp32Snapshot": "decouverte", "Process32First": "decouverte",
    "Process32Next": "decouverte", "GetComputerNameA": "decouverte",
    # Collecte
    "GetAsyncKeyState": "collecte", "SetWindowsHookExA": "collecte",
    "SetWindowsHookExW": "collecte", "GetClipboardData": "collecte",
    # Chargement dynamique (peut masquer les imports)
    "LoadLibraryA": "chargement", "LoadLibraryW": "chargement", "GetProcAddress": "chargement",
}


def categorize(api: str) -> str | None:
    return SENSITIVE_APIS.get(api)
