"""Knowledge tables: well-known ports and web services by domain."""

PORT_SERVICES = {
    20: "FTP (data)", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS/SMB", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP (alt)", 8443: "HTTPS (alt)",
}

# Domain suffix -> human-readable service name
DOMAIN_SERVICES = {
    "youtube.com": "YouTube", "googlevideo.com": "YouTube (video)", "ytimg.com": "YouTube",
    "google.com": "Google", "gstatic.com": "Google", "googleapis.com": "Google (APIs)",
    "facebook.com": "Facebook", "fbcdn.net": "Facebook", "instagram.com": "Instagram",
    "whatsapp.net": "WhatsApp", "whatsapp.com": "WhatsApp",
    "twitter.com": "X/Twitter", "x.com": "X/Twitter", "twimg.com": "X/Twitter",
    "netflix.com": "Netflix", "nflxvideo.net": "Netflix (video)",
    "spotify.com": "Spotify", "scdn.co": "Spotify",
    "tiktok.com": "TikTok", "tiktokcdn.com": "TikTok",
    "amazon.com": "Amazon", "amazonaws.com": "Amazon AWS", "twitch.tv": "Twitch",
    "microsoft.com": "Microsoft", "windowsupdate.com": "Windows Update",
    "live.com": "Microsoft", "office.com": "Microsoft Office", "office365.com": "Microsoft 365",
    "apple.com": "Apple", "icloud.com": "iCloud", "github.com": "GitHub",
    "wikipedia.org": "Wikipedia", "reddit.com": "Reddit", "linkedin.com": "LinkedIn",
    "discord.com": "Discord", "discord.gg": "Discord", "zoom.us": "Zoom",
    "cloudflare.com": "Cloudflare", "akamaiedge.net": "Akamai (CDN)",
    "dropbox.com": "Dropbox", "telegram.org": "Telegram", "t.me": "Telegram",
}

ICMP_TYPES = {
    0: "ping reply (echo reply)", 3: "destination unreachable", 5: "redirect",
    8: "ping (echo request)", 11: "time exceeded (TTL, typical of traceroute)",
}

DHCP_TYPES = {
    1: "DISCOVER (looking for a DHCP server)", 2: "OFFER (server offers an IP)",
    3: "REQUEST (asking for an IP)", 4: "DECLINE", 5: "ACK (IP granted)", 6: "NAK (IP denied)",
    7: "RELEASE (releases its IP)", 8: "INFORM",
}


def service_for_domain(domain):
    domain = (domain or "").lower().rstrip(".")
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        suffix = ".".join(parts[i:])
        if suffix in DOMAIN_SERVICES:
            return DOMAIN_SERVICES[suffix]
    return None
