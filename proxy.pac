// PLGames Svoboda — auto-generated PAC file
// Routes IP-blocked domains through SOCKS5 proxy (plgames_vps)
// Generated automatically. Do not edit manually.

var PROXY_DOMAINS = {
    "web.telegram.org": 1,
    "api.openai.com": 1,
    "linkedin.com": 1
};

function FindProxyForURL(url, host) {
    // Strip www prefix for matching
    var h = host.toLowerCase();
    if (h.indexOf("www.") === 0) h = h.substring(4);

    // Check exact match
    if (PROXY_DOMAINS[h]) {
        return "SOCKS5 127.0.0.1:1082; DIRECT";
    }

    // Check if host is a subdomain of a blocked domain
    for (var domain in PROXY_DOMAINS) {
        if (h.length > domain.length && h.indexOf("." + domain) === h.length - domain.length - 1) {
            return "SOCKS5 127.0.0.1:1082; DIRECT";
        }
    }

    return "DIRECT";
}
