#!/usr/bin/env python3

"""
Security Feature Extractor for IDAssist GraphRAG

Adapted from BinAssist for IDA Pro. Uses code-based extraction (regex on
decompiled/disassembled text) plus IDA API for cross-references when available.
"""

import re
from typing import Iterable, Optional

from .security_features import SecurityFeatures

from src.ida_compat import log, execute_on_main_thread

# IDA imports
try:
    import idautils
    import ida_funcs
    import ida_name
    import ida_bytes
    import idc
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


class SecurityFeatureExtractor:
    """Extracts security-relevant features from IDA functions."""
    CALL_PATTERN = re.compile(r"\b([A-Za-z_@][A-Za-z0-9_@!:.]*)\s*\(")
    CALL_KEYWORDS = {
        "if", "for", "while", "switch", "case", "return", "sizeof",
        "do", "catch", "try", "else", "new", "delete",
    }

    NETWORK_APIS = {
        "socket", "bind", "listen", "accept", "connect", "close", "shutdown",
        "setsockopt", "getsockopt", "getpeername", "getsockname",
        "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg",
        "read", "write",
        "select", "poll", "epoll_create", "epoll_ctl", "epoll_wait",
        "kqueue", "kevent",
        "WSAStartup", "WSACleanup", "WSAGetLastError", "WSASetLastError",
        "closesocket",
        "WSASocket", "WSASocketA", "WSASocketW",
        "WSAConnect", "WSAConnectByName", "WSAConnectByNameA", "WSAConnectByNameW",
        "WSAConnectByList",
        "WSAAccept",
        "WSASend", "WSASendTo", "WSASendMsg", "WSASendDisconnect",
        "WSARecv", "WSARecvFrom", "WSARecvMsg", "WSARecvDisconnect",
        "WSAAsyncSelect", "WSAEventSelect", "WSACreateEvent", "WSACloseEvent",
        "WSAWaitForMultipleEvents", "WSAEnumNetworkEvents", "WSAResetEvent", "WSASetEvent",
        "WSAIoctl", "WSAGetOverlappedResult",
        "WSAAddressToString", "WSAAddressToStringA", "WSAAddressToStringW",
        "WSAStringToAddress", "WSAStringToAddressA", "WSAStringToAddressW",
        "WSAEnumProtocols", "WSAEnumProtocolsA", "WSAEnumProtocolsW",
        "getaddrinfo", "GetAddrInfo", "GetAddrInfoA", "GetAddrInfoW", "GetAddrInfoEx",
        "freeaddrinfo", "FreeAddrInfo", "FreeAddrInfoW",
        "gethostbyname", "gethostbyaddr", "gethostname",
        "getnameinfo", "GetNameInfo", "GetNameInfoW",
        "inet_addr", "inet_ntoa", "inet_pton", "inet_ntop",
        "InetPton", "InetPtonA", "InetPtonW", "InetNtop", "InetNtopA", "InetNtopW",
        "htons", "htonl", "ntohs", "ntohl",
        "SSL_connect", "SSL_accept", "SSL_read", "SSL_write", "SSL_new", "SSL_free",
        "SSL_CTX_new", "SSL_CTX_free", "SSL_set_fd", "SSL_shutdown",
        "SSL_library_init", "SSL_load_error_strings",
        "TLS_client_method", "TLS_server_method",
        "AcquireCredentialsHandle", "AcquireCredentialsHandleA", "AcquireCredentialsHandleW",
        "InitializeSecurityContext", "InitializeSecurityContextA", "InitializeSecurityContextW",
        "AcceptSecurityContext",
        "EncryptMessage", "DecryptMessage",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
        "WinHttpSendRequest", "WinHttpReceiveResponse",
        "WinHttpReadData", "WinHttpWriteData", "WinHttpQueryHeaders",
        "WinHttpCloseHandle", "WinHttpSetOption", "WinHttpQueryOption",
        "WinHttpCrackUrl", "WinHttpCreateUrl",
        "InternetOpen", "InternetOpenA", "InternetOpenW",
        "InternetConnect", "InternetConnectA", "InternetConnectW",
        "InternetOpenUrl", "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetReadFile", "InternetReadFileEx",
        "InternetWriteFile",
        "InternetCloseHandle", "InternetSetOption", "InternetQueryOption",
        "HttpOpenRequest", "HttpOpenRequestA", "HttpOpenRequestW",
        "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
        "HttpSendRequestEx", "HttpSendRequestExA", "HttpSendRequestExW",
        "HttpQueryInfo", "HttpQueryInfoA", "HttpQueryInfoW",
        "HttpAddRequestHeaders", "HttpEndRequest",
        "FtpOpenFile", "FtpGetFile", "FtpPutFile", "FtpDeleteFile",
        "FtpCreateDirectory", "FtpRemoveDirectory", "FtpFindFirstFile",
        "curl_easy_init", "curl_easy_perform", "curl_easy_cleanup",
        "curl_easy_setopt", "curl_easy_getinfo",
        "curl_multi_init", "curl_multi_add_handle", "curl_multi_perform"
    }

    FILE_IO_APIS = {
        "open", "close", "read", "write", "lseek", "pread", "pwrite",
        "creat", "dup", "dup2", "fcntl", "ioctl",
        "stat", "fstat", "lstat", "fstatat",
        "access", "faccessat", "chmod", "fchmod", "chown", "fchown",
        "truncate", "ftruncate",
        "mmap", "munmap", "msync",
        "fopen", "fclose", "fread", "fwrite", "fgets", "fputs", "fgetc", "fputc",
        "fprintf", "fscanf", "fseek", "ftell", "fflush", "rewind", "feof", "ferror",
        "freopen", "fdopen", "fileno", "setvbuf", "setbuf",
        "getc", "putc", "ungetc", "getchar", "putchar",
        "opendir", "closedir", "readdir", "readdir_r", "scandir", "seekdir", "telldir",
        "mkdir", "mkdirat", "rmdir", "chdir", "fchdir", "getcwd",
        "realpath", "basename", "dirname",
        "rename", "renameat", "remove", "unlink", "unlinkat",
        "link", "linkat", "symlink", "symlinkat", "readlink", "readlinkat",
        "CreateFile", "CreateFileA", "CreateFileW",
        "CreateFile2",
        "OpenFile",
        "ReadFile", "ReadFileEx", "ReadFileScatter",
        "WriteFile", "WriteFileEx", "WriteFileGather",
        "FlushFileBuffers",
        "SetFilePointer", "SetFilePointerEx",
        "SetEndOfFile",
        "GetFileSize", "GetFileSizeEx",
        "GetFileType",
        "GetFileTime", "SetFileTime",
        "GetFileInformationByHandle", "GetFileInformationByHandleEx",
        "SetFileInformationByHandle",
        "GetFileAttributes", "GetFileAttributesA", "GetFileAttributesW",
        "GetFileAttributesEx", "GetFileAttributesExA", "GetFileAttributesExW",
        "SetFileAttributes", "SetFileAttributesA", "SetFileAttributesW",
        "LockFile", "LockFileEx", "UnlockFile", "UnlockFileEx",
        "DeleteFile", "DeleteFileA", "DeleteFileW",
        "CopyFile", "CopyFileA", "CopyFileW",
        "CopyFileEx", "CopyFileExA", "CopyFileExW",
        "MoveFile", "MoveFileA", "MoveFileW",
        "MoveFileEx", "MoveFileExA", "MoveFileExW",
        "MoveFileWithProgress", "MoveFileWithProgressA", "MoveFileWithProgressW",
        "ReplaceFile", "ReplaceFileA", "ReplaceFileW",
        "FindFirstFile", "FindFirstFileA", "FindFirstFileW",
        "FindFirstFileEx", "FindFirstFileExA", "FindFirstFileExW",
        "FindNextFile", "FindNextFileA", "FindNextFileW",
        "FindClose",
        "SearchPath", "SearchPathA", "SearchPathW",
        "CreateDirectory", "CreateDirectoryA", "CreateDirectoryW",
        "CreateDirectoryEx", "CreateDirectoryExA", "CreateDirectoryExW",
        "RemoveDirectory", "RemoveDirectoryA", "RemoveDirectoryW",
        "SetCurrentDirectory", "SetCurrentDirectoryA", "SetCurrentDirectoryW",
        "GetCurrentDirectory", "GetCurrentDirectoryA", "GetCurrentDirectoryW",
        "GetFullPathName", "GetFullPathNameA", "GetFullPathNameW",
        "GetLongPathName", "GetLongPathNameA", "GetLongPathNameW",
        "GetShortPathName", "GetShortPathNameA", "GetShortPathNameW",
        "GetTempPath", "GetTempPathA", "GetTempPathW",
        "GetTempFileName", "GetTempFileNameA", "GetTempFileNameW",
        "PathFileExists", "PathFileExistsA", "PathFileExistsW",
        "CloseHandle", "DuplicateHandle",
        "CreateFileMapping", "CreateFileMappingA", "CreateFileMappingW",
        "OpenFileMapping", "OpenFileMappingA", "OpenFileMappingW",
        "MapViewOfFile", "MapViewOfFileEx", "UnmapViewOfFile",
        "GetOverlappedResult", "GetOverlappedResultEx",
        "CancelIo", "CancelIoEx", "CancelSynchronousIo",
        "CreateFileTransacted", "CreateFileTransactedA", "CreateFileTransactedW",
        "DeleteFileTransacted", "DeleteFileTransactedA", "DeleteFileTransactedW"
    }

    CRYPTO_APIS = {
        "CryptAcquireContext", "CryptReleaseContext",
        "CryptGenKey", "CryptDeriveKey", "CryptDestroyKey",
        "CryptEncrypt", "CryptDecrypt",
        "CryptCreateHash", "CryptHashData", "CryptDestroyHash",
        "CryptSignHash", "CryptVerifySignature",
        "CryptImportKey", "CryptExportKey",
        "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider",
        "BCryptGenerateKeyPair", "BCryptEncrypt", "BCryptDecrypt",
        "BCryptCreateHash", "BCryptHashData", "BCryptFinishHash",
        "EVP_EncryptInit", "EVP_EncryptUpdate", "EVP_EncryptFinal",
        "EVP_DecryptInit", "EVP_DecryptUpdate", "EVP_DecryptFinal",
        "EVP_DigestInit", "EVP_DigestUpdate", "EVP_DigestFinal",
        "AES_encrypt", "AES_decrypt", "AES_set_encrypt_key", "AES_set_decrypt_key",
        "RSA_public_encrypt", "RSA_private_decrypt",
        "MD5_Init", "MD5_Update", "MD5_Final",
        "SHA1_Init", "SHA1_Update", "SHA1_Final",
        "SHA256_Init", "SHA256_Update", "SHA256_Final"
    }

    PROCESS_APIS = {
        "fork", "exec", "execl", "execle", "execlp", "execv", "execve", "execvp",
        "system", "popen", "pclose",
        "kill", "waitpid", "wait",
        "CreateProcess", "CreateProcessA", "CreateProcessW",
        "CreateProcessAsUser", "CreateProcessWithLogon",
        "ShellExecute", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteEx", "ShellExecuteExA", "ShellExecuteExW",
        "WinExec", "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
        "GetProcAddress", "FreeLibrary",
        "OpenProcess", "TerminateProcess",
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
        "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx"
    }

    DANGEROUS_FUNCTIONS = {
        "strcpy": "BUFFER_OVERFLOW_RISK",
        "strcat": "BUFFER_OVERFLOW_RISK",
        "sprintf": "BUFFER_OVERFLOW_RISK",
        "vsprintf": "BUFFER_OVERFLOW_RISK",
        "gets": "BUFFER_OVERFLOW_RISK",
        "scanf": "BUFFER_OVERFLOW_RISK",
        "fscanf": "BUFFER_OVERFLOW_RISK",
        "sscanf": "BUFFER_OVERFLOW_RISK",
        "wcscpy": "BUFFER_OVERFLOW_RISK",
        "wcscat": "BUFFER_OVERFLOW_RISK",
        "lstrcpy": "BUFFER_OVERFLOW_RISK",
        "lstrcpyA": "BUFFER_OVERFLOW_RISK",
        "lstrcpyW": "BUFFER_OVERFLOW_RISK",
        "lstrcat": "BUFFER_OVERFLOW_RISK",
        "lstrcatA": "BUFFER_OVERFLOW_RISK",
        "lstrcatW": "BUFFER_OVERFLOW_RISK",
        "StrCpy": "BUFFER_OVERFLOW_RISK",
        "StrCat": "BUFFER_OVERFLOW_RISK",
        "_tcscpy": "BUFFER_OVERFLOW_RISK",
        "_tcscat": "BUFFER_OVERFLOW_RISK",
        "_mbscpy": "BUFFER_OVERFLOW_RISK",
        "_mbscat": "BUFFER_OVERFLOW_RISK",
        "printf": "FORMAT_STRING_RISK",
        "fprintf": "FORMAT_STRING_RISK",
        "wprintf": "FORMAT_STRING_RISK",
        "syslog": "FORMAT_STRING_RISK",
        "system": "COMMAND_INJECTION_RISK",
        "popen": "COMMAND_INJECTION_RISK",
        "_popen": "COMMAND_INJECTION_RISK",
        "wpopen": "COMMAND_INJECTION_RISK",
        "execl": "COMMAND_INJECTION_RISK",
        "execle": "COMMAND_INJECTION_RISK",
        "execlp": "COMMAND_INJECTION_RISK",
        "execv": "COMMAND_INJECTION_RISK",
        "execve": "COMMAND_INJECTION_RISK",
        "execvp": "COMMAND_INJECTION_RISK",
        "WinExec": "COMMAND_INJECTION_RISK",
        "ShellExecute": "COMMAND_INJECTION_RISK",
        "ShellExecuteA": "COMMAND_INJECTION_RISK",
        "ShellExecuteW": "COMMAND_INJECTION_RISK",
        "ShellExecuteEx": "COMMAND_INJECTION_RISK",
        "ShellExecuteExA": "COMMAND_INJECTION_RISK",
        "ShellExecuteExW": "COMMAND_INJECTION_RISK",
        "atoi": "INTEGER_OVERFLOW_RISK",
        "atol": "INTEGER_OVERFLOW_RISK",
        "atoll": "INTEGER_OVERFLOW_RISK",
        "strtol": "INTEGER_OVERFLOW_RISK",
        "strtoul": "INTEGER_OVERFLOW_RISK",
        "access": "RACE_CONDITION_RISK",
        "stat": "RACE_CONDITION_RISK",
        "alloca": "MEMORY_CORRUPTION_RISK",
        "_alloca": "MEMORY_CORRUPTION_RISK",
        "rand": "WEAK_RANDOM_RISK",
        "srand": "WEAK_RANDOM_RISK",
        "random": "WEAK_RANDOM_RISK",
        "MD5_Init": "WEAK_CRYPTO_RISK",
        "MD5_Update": "WEAK_CRYPTO_RISK",
        "MD5_Final": "WEAK_CRYPTO_RISK",
        "MD5": "WEAK_CRYPTO_RISK",
        "SHA1_Init": "WEAK_CRYPTO_RISK",
        "SHA1_Update": "WEAK_CRYPTO_RISK",
        "SHA1_Final": "WEAK_CRYPTO_RISK",
        "DES_encrypt": "WEAK_CRYPTO_RISK",
        "DES_decrypt": "WEAK_CRYPTO_RISK"
    }

    IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    URL_PATTERN = re.compile(r"^https?://[\w.-]+(?:/[\w./?%&=-]*)?$", re.IGNORECASE)
    UNIX_PATH_PATTERN = re.compile(r"^/[a-zA-Z0-9/_.-]+$")
    WINDOWS_PATH_PATTERN = re.compile(r"^[A-Za-z]:\\\\[^<>:\"|?*]+$")
    DOMAIN_PATTERN = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
    )
    REGISTRY_PATTERN = re.compile(r"^(HKEY_|HK[A-Z]{2})[\\\\A-Za-z0-9_-]+$")

    def __init__(self):
        """Initialize without binary_view dependency (IDA uses module-level functions)."""
        self._network_lookup = {api.lower(): api for api in self.NETWORK_APIS}
        self._file_lookup = {api.lower(): api for api in self.FILE_IO_APIS}
        self._crypto_lookup = {api.lower(): api for api in self.CRYPTO_APIS}
        self._process_lookup = {api.lower(): api for api in self.PROCESS_APIS}
        self._dangerous_lookup = {name.lower(): vuln for name, vuln in self.DANGEROUS_FUNCTIONS.items()}

    def extract_features(self, func_ea: int, raw_code: Optional[str] = None) -> SecurityFeatures:
        """Extract security features using IDA API for a function at func_ea."""
        features = SecurityFeatures()

        try:
            # Get call target names from IDA cross-references
            call_names = self._get_call_targets_ida(func_ea)
            # Also extract from code text
            if raw_code:
                for name in self._extract_calls_from_code(raw_code):
                    call_names.add(name)

            self._classify_api_calls(call_names, features)

            # Extract string references from IDA
            if _IN_IDA:
                self._extract_string_references_ida(func_ea, features)

            features.calculate_activity_profile()
            features.calculate_risk_level()
        except Exception as e:
            log.log_warn(f"Error extracting security features: {e}")

        return features

    def extract_features_from_code(self, func_name: str, raw_code: Optional[str] = None) -> SecurityFeatures:
        """Extract security features purely from code text (no IDA API needed).

        Used during batch extraction where we already have decompiled code.
        """
        features = SecurityFeatures()

        try:
            call_names = set()
            if raw_code:
                call_names = self._extract_calls_from_code(raw_code)

            self._classify_api_calls(call_names, features)

            # Classify strings found in code
            if raw_code:
                self._extract_strings_from_code(raw_code, features)

            features.calculate_activity_profile()
            features.calculate_risk_level()
        except Exception as e:
            log.log_warn(f"Error extracting security features from code: {e}")

        return features

    def _classify_api_calls(self, call_names: set, features: SecurityFeatures) -> None:
        """Classify a set of call names into security categories."""
        for name in call_names:
            normalized = self._normalize_function_name(name)
            lower = normalized.lower()

            network_match = self._network_lookup.get(lower)
            if network_match:
                features.add_network_api(network_match)

            file_match = self._file_lookup.get(lower)
            if file_match:
                features.add_file_io_api(file_match)

            crypto_match = self._crypto_lookup.get(lower)
            if crypto_match:
                features.add_crypto_api(crypto_match)

            process_match = self._process_lookup.get(lower)
            if process_match:
                features.add_process_api(process_match)

            vuln_type = self._dangerous_lookup.get(lower)
            if vuln_type:
                features.add_dangerous_function(normalized, vuln_type)

    def _get_call_targets_ida(self, func_ea: int) -> set:
        """Get call target names using IDA cross-references.

        All IDA API calls are marshalled to the main thread.
        """
        if not _IN_IDA:
            return set()

        result = [set()]

        def _do():
            try:
                func = ida_funcs.get_func(func_ea)
                if not func:
                    return
                for item_ea in idautils.FuncItems(func_ea):
                    for ref in idautils.CodeRefsFrom(item_ea, 0):
                        ref_name = ida_funcs.get_func_name(ref)
                        if ref_name:
                            result[0].add(ref_name)
                        else:
                            name = ida_name.get_name(ref)
                            if name:
                                result[0].add(name)
            except Exception:
                pass

        execute_on_main_thread(_do)
        return result[0]

    def _extract_calls_from_code(self, raw_code: str) -> set:
        """Extract function call names from code text using regex."""
        names = set()
        if not raw_code:
            return names
        for match in self.CALL_PATTERN.findall(raw_code):
            candidate = match.strip()
            if not candidate:
                continue
            lower = candidate.lower()
            if lower in self.CALL_KEYWORDS:
                continue
            names.add(candidate)
        return names

    def _extract_string_references_ida(self, func_ea: int, features: SecurityFeatures) -> None:
        """Extract string references using IDA's data cross-references.

        All IDA API calls are marshalled to the main thread.
        """
        # Gather strings on main thread, classify off-thread
        strings_holder = [[]]

        def _do():
            try:
                func = ida_funcs.get_func(func_ea)
                if not func:
                    return
                for item_ea in idautils.FuncItems(func_ea):
                    for ref in idautils.DataRefsFrom(item_ea):
                        str_val = idc.get_strlit_contents(ref)
                        if str_val:
                            if isinstance(str_val, bytes):
                                try:
                                    str_val = str_val.decode('utf-8', errors='ignore')
                                except Exception:
                                    continue
                            if len(str_val) >= 3:
                                strings_holder[0].append(str_val)
            except Exception as e:
                log.log_warn(f"Error extracting string references: {e}")

        execute_on_main_thread(_do)

        for s in strings_holder[0]:
            self._classify_string(s, features)

    def _extract_strings_from_code(self, raw_code: str, features: SecurityFeatures) -> None:
        """Extract and classify string literals from code text."""
        # Match quoted strings in decompiled code
        string_pattern = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
        for match in string_pattern.findall(raw_code):
            if len(match) >= 3:
                self._classify_string(match, features)

    def _normalize_function_name(self, name: str) -> str:
        """Normalize function name (strip decorations, prefixes)."""
        if not name:
            return name

        normalized = name

        if "::" in normalized:
            normalized = normalized.split("::")[-1]
        if "!" in normalized:
            normalized = normalized.split("!")[-1]
        if "." in normalized:
            normalized = normalized.split(".")[-1]

        if normalized.startswith("@"):
            normalized = normalized[1:]
        if normalized.startswith("__imp_"):
            normalized = normalized[6:]
        if normalized.lower().startswith("imp_"):
            normalized = normalized[4:]

        while normalized.startswith("_") and len(normalized) > 1:
            normalized = normalized[1:]

        at_index = normalized.rfind("@")
        if at_index > 0:
            suffix = normalized[at_index + 1:]
            if suffix.isdigit():
                normalized = normalized[:at_index]

        return normalized

    def _classify_string(self, value: str, features: SecurityFeatures) -> None:
        """Classify a string value into security categories."""
        if not value:
            return

        value = value.strip()
        if len(value) < 3:
            return

        if self.IP_PATTERN.match(value):
            if self._is_valid_ip(value):
                features.add_ip_address(value)
        elif self.URL_PATTERN.match(value):
            features.add_url(value)
        elif self.REGISTRY_PATTERN.match(value):
            features.add_registry_key(value)
        elif self.UNIX_PATH_PATTERN.match(value):
            features.add_file_path(value)
        elif self.WINDOWS_PATH_PATTERN.match(value):
            features.add_file_path(value)
        elif self.DOMAIN_PATTERN.match(value):
            if not self._is_common_non_domain(value):
                features.add_domain(value)

    def _is_valid_ip(self, ip: str) -> bool:
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            for part in parts:
                octet = int(part)
                if octet < 0 or octet > 255:
                    return False
            return True
        except Exception:
            return False

    def _is_common_non_domain(self, value: str) -> bool:
        lower = value.lower()
        return (
            lower.endswith(".dll")
            or lower.endswith(".exe")
            or lower.endswith(".sys")
            or lower.endswith(".lib")
            or lower.endswith(".obj")
            or lower.endswith(".pdb")
            or lower.endswith(".h")
            or lower.endswith(".c")
            or lower.endswith(".cpp")
            or lower == "version.rc"
            or ("microsoft.com" in lower and "schema" in lower)
        )

    @staticmethod
    def suggests_network_activity(function_name: Optional[str]) -> bool:
        if not function_name:
            return False
        lower = function_name.lower()
        return any(
            key in lower
            for key in ("socket", "connect", "send", "recv", "http", "download", "upload", "network", "client", "server")
        )

    @staticmethod
    def suggests_file_activity(function_name: Optional[str]) -> bool:
        if not function_name:
            return False
        lower = function_name.lower()
        return any(
            key in lower
            for key in ("file", "read", "write", "open", "save", "load", "config", "log")
        )

    @staticmethod
    def suggests_crypto_activity(function_name: Optional[str]) -> bool:
        if not function_name:
            return False
        lower = function_name.lower()
        return any(
            key in lower
            for key in ("crypt", "encrypt", "decrypt", "hash", "aes", "rsa", "sha", "md5")
        )
