#!/usr/bin/env python3

from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class SecurityFeatures:
    network_apis: Set[str] = field(default_factory=set)
    file_io_apis: Set[str] = field(default_factory=set)
    crypto_apis: Set[str] = field(default_factory=set)
    process_apis: Set[str] = field(default_factory=set)
    dangerous_functions: Dict[str, str] = field(default_factory=dict)
    ip_addresses: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    file_paths: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    registry_keys: Set[str] = field(default_factory=set)
    activity_profile: str = ""
    risk_level: str = ""

    # API Call Tracking
    def add_network_api(self, api_name: str) -> None:
        if api_name:
            self.network_apis.add(api_name)

    def add_file_io_api(self, api_name: str) -> None:
        if api_name:
            self.file_io_apis.add(api_name)

    def add_crypto_api(self, api_name: str) -> None:
        if api_name:
            self.crypto_apis.add(api_name)

    def add_process_api(self, api_name: str) -> None:
        if api_name:
            self.process_apis.add(api_name)

    # Dangerous Functions
    def add_dangerous_function(self, function_name: str, vulnerability_type: str) -> None:
        if function_name and vulnerability_type:
            self.dangerous_functions[function_name] = vulnerability_type

    def has_dangerous_functions(self) -> bool:
        return bool(self.dangerous_functions)

    def get_vulnerability_types(self) -> Set[str]:
        return set(self.dangerous_functions.values())

    # String Reference Tracking
    def add_ip_address(self, ip: str) -> None:
        if ip:
            self.ip_addresses.add(ip)

    def add_url(self, url: str) -> None:
        if url:
            self.urls.add(url)

    def add_file_path(self, path: str) -> None:
        if path:
            self.file_paths.add(path)

    def add_domain(self, domain: str) -> None:
        if domain:
            self.domains.add(domain)

    def add_registry_key(self, key: str) -> None:
        if key:
            self.registry_keys.add(key)

    # Query Methods
    def has_network_apis(self) -> bool:
        return bool(self.network_apis)

    def has_file_io_apis(self) -> bool:
        return bool(self.file_io_apis)

    def has_crypto_apis(self) -> bool:
        return bool(self.crypto_apis)

    def has_process_apis(self) -> bool:
        return bool(self.process_apis)

    def has_ip_addresses(self) -> bool:
        return bool(self.ip_addresses)

    def has_urls(self) -> bool:
        return bool(self.urls)

    def has_file_paths(self) -> bool:
        return bool(self.file_paths)

    def has_domains(self) -> bool:
        return bool(self.domains)

    def has_registry_keys(self) -> bool:
        return bool(self.registry_keys)

    def has_system_paths(self) -> bool:
        return any(
            path.startswith("/etc")
            or path.startswith("/root")
            or path.startswith("/var")
            or "\\windows" in path.lower()
            or "\\system32" in path.lower()
            or "\\programdata" in path.lower()
            for path in self.file_paths
        )

    def is_empty(self) -> bool:
        return not (
            self.network_apis
            or self.file_io_apis
            or self.crypto_apis
            or self.process_apis
            or self.dangerous_functions
            or self.ip_addresses
            or self.urls
            or self.file_paths
            or self.domains
            or self.registry_keys
        )

    # Activity Profile Calculation
    def calculate_activity_profile(self) -> None:
        profiles: List[str] = []

        # Network patterns
        if self.has_network_apis():
            def _has(pattern: str) -> bool:
                return any(pattern in api.lower() for api in self.network_apis)

            has_server_ops = _has("listen") or _has("accept") or _has("wsaaccept") or _has("acceptsecuritycontext")
            has_client_connect = _has("connect") or _has("wsaconnect") or _has("winhttpconnect") or _has("internetconnect") or _has("ssl_connect")
            has_send = _has("send") or _has("wsasend") or _has("winhttpwritedata") or _has("internetwritefile") or _has("ssl_write")
            has_recv = _has("recv") or _has("wsarecv") or _has("winhttpreaddata") or _has("internetreadfile") or _has("ssl_read")
            has_http_client = _has("httpopen") or _has("httpsend") or _has("winhttp") or _has("internet") or _has("curl_")

            if has_server_ops:
                profiles.append("NETWORK_SERVER")
            if has_client_connect or has_http_client:
                profiles.append("NETWORK_CLIENT")
            if (has_send or has_recv) and not profiles:
                profiles.append("NETWORK_IO")

        # DNS patterns
        if self.has_network_apis():
            dns_keywords = ("getaddrinfo", "gethostbyname", "gethostbyaddr", "getnameinfo", "gethostname")
            if any(any(k in api.lower() for k in dns_keywords) for api in self.network_apis):
                profiles.append("DNS_RESOLVER")

        # File I/O patterns
        if self.has_file_io_apis():
            def _file_has(keyword: str) -> bool:
                return any(keyword in api.lower() for api in self.file_io_apis)

            has_read = _file_has("read") or _file_has("fread") or _file_has("fgets") or _file_has("fgetc") or _file_has("getc") or _file_has("fscanf") or _file_has("readfile") or _file_has("internetreadfile") or _file_has("mapviewoffile")
            has_write = _file_has("write") or _file_has("fwrite") or _file_has("fputs") or _file_has("fputc") or _file_has("putc") or _file_has("fprintf") or _file_has("writefile") or _file_has("internetwritefile") or _file_has("copyfile") or _file_has("movefile")
            has_delete = _file_has("delete") or _file_has("remove") or _file_has("unlink") or _file_has("removedirectory")

            if has_read and has_write:
                profiles.append("FILE_RW")
            elif has_write:
                profiles.append("FILE_WRITER")
            elif has_read:
                profiles.append("FILE_READER")

            if has_delete:
                profiles.append("FILE_DELETER")

        # Crypto patterns
        if self.has_crypto_apis():
            lower = [api.lower() for api in self.crypto_apis]
            has_encrypt = any("encrypt" in api for api in lower)
            has_decrypt = any("decrypt" in api for api in lower)
            has_hash = any(any(k in api for k in ("hash", "md5", "sha1", "sha256", "digest")) for api in lower)

            if has_encrypt and has_decrypt:
                profiles.append("CRYPTO_CIPHER")
            elif has_encrypt:
                profiles.append("CRYPTO_ENCRYPT")
            elif has_decrypt:
                profiles.append("CRYPTO_DECRYPT")
            elif has_hash:
                profiles.append("CRYPTO_HASH")
            else:
                profiles.append("CRYPTO_USER")

        # Process patterns
        if self.has_process_apis():
            lower = [api.lower() for api in self.process_apis]
            has_inject = any(
                "writeprocessmemory" in api
                or "createremotethread" in api
                or "virtualalloc" in api
                for api in lower
            )

            profiles.append("PROCESS_INJECTOR" if has_inject else "PROCESS_SPAWNER")

        if self.has_network_apis() and self.has_file_io_apis():
            profiles.append("MIXED_IO")

        self.activity_profile = "NONE" if not profiles else ", ".join(profiles)

    # Risk Level Calculation
    def calculate_risk_level(self) -> None:
        score = 0

        if self.has_network_apis():
            score += 2
        if self.has_ip_addresses():
            score += 3
        if self.has_urls():
            score += 2
        if self.has_domains():
            score += 1

        if self.has_file_io_apis():
            score += 1
        if self.has_system_paths():
            score += 3

        if self.has_crypto_apis():
            score += 1
        if self.has_process_apis():
            score += 2

        if self.has_registry_keys():
            score += 2

        if self.has_dangerous_functions():
            score += 3
            vuln_types = self.get_vulnerability_types()
            if "BUFFER_OVERFLOW_RISK" in vuln_types or "COMMAND_INJECTION_RISK" in vuln_types:
                score += 2

        if self.has_network_apis() and self.has_file_io_apis():
            score += 2
        if self.has_network_apis() and self.has_crypto_apis():
            score += 2

        if score >= 6:
            self.risk_level = "HIGH"
        elif score >= 3:
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"

    # Security Flags
    def generate_security_flags(self) -> List[str]:
        flags: List[str] = []

        if self.has_network_apis():
            flags.append("NETWORK_CAPABLE")
            profile = self.get_activity_profile()
            if "NETWORK_SERVER" in profile:
                flags.append("ACCEPTS_CONNECTIONS")
            if "NETWORK_CLIENT" in profile:
                flags.append("INITIATES_CONNECTIONS")
            if "DNS_RESOLVER" in profile:
                flags.append("PERFORMS_DNS_LOOKUP")

        if self.has_file_io_apis():
            flags.append("FILE_IO_CAPABLE")
            profile = self.get_activity_profile()
            if "FILE_WRITER" in profile or "FILE_RW" in profile:
                flags.append("WRITES_FILES")
            if "FILE_READER" in profile or "FILE_RW" in profile:
                flags.append("READS_FILES")
            if "FILE_DELETER" in profile:
                flags.append("DELETES_FILES")

        if self.has_crypto_apis():
            flags.append("USES_CRYPTO")
            profile = self.get_activity_profile()
            if "CRYPTO_ENCRYPT" in profile:
                flags.append("ENCRYPTS_DATA")
            if "CRYPTO_DECRYPT" in profile:
                flags.append("DECRYPTS_DATA")

        if self.has_process_apis():
            flags.append("SPAWNS_PROCESSES")
            profile = self.get_activity_profile()
            if "PROCESS_INJECTOR" in profile:
                flags.append("PROCESS_INJECTION_CAPABLE")

        if self.has_dangerous_functions():
            flags.append("CALLS_DANGEROUS_FUNCTIONS")
            flags.extend(sorted(self.get_vulnerability_types()))

        if self.has_ip_addresses():
            flags.append("CONTAINS_HARDCODED_IPS")
        if self.has_urls():
            flags.append("CONTAINS_URLS")
        if self.has_domains():
            flags.append("CONTAINS_DOMAINS")
        if self.has_registry_keys():
            flags.append("ACCESSES_REGISTRY")
        if self.has_system_paths():
            flags.append("ACCESSES_SYSTEM_PATHS")

        if self.has_network_apis() and self.has_file_io_apis():
            flags.append("POTENTIAL_DATA_EXFILTRATION")
        if self.has_network_apis() and self.has_crypto_apis():
            flags.append("ENCRYPTED_NETWORK_COMMS")
        if self.has_network_apis() and self.has_dangerous_functions():
            flags.append("NETWORK_WITH_VULN_RISK")

        risk = self.get_risk_level()
        if risk == "HIGH":
            flags.append("HIGH_RISK")
        elif risk == "MEDIUM":
            flags.append("MEDIUM_RISK")

        return flags

    def get_activity_profile(self) -> str:
        if not self.activity_profile:
            self.calculate_activity_profile()
        return self.activity_profile

    def get_risk_level(self) -> str:
        if not self.risk_level:
            self.calculate_risk_level()
        return self.risk_level
