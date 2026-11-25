import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
import whois
from datetime import date
from urllib.parse import urlparse


class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None

        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, "html.parser")
        except Exception:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except Exception:
            pass

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1. UsingIP
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except Exception:
            return 1

    # 2. longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if 54 <= len(self.url) <= 75:
            return 0
        return -1

    # 3. shortUrl
    def shortUrl(self):
        match = re.search(
            r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
            r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
            r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
            r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
            r"db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
            r"q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
            r"x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net",
            self.url,
        )
        return -1 if match else 1

    # 4. Symbol@
    def symbol(self):
        return -1 if "@" in self.url else 1

    # 5. Redirecting//
    def redirecting(self):
        return -1 if self.url.rfind("//") > 6 else 1

    # 6. prefixSuffix
    def prefixSuffix(self):
        try:
            return -1 if "-" in self.domain else 1
        except Exception:
            return -1

    # 7. SubDomains
    def SubDomains(self):
        dot_count = len(re.findall(r"\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8. HTTPS
    def Hppts(self):
        try:
            return 1 if "https" in self.urlparse.scheme else -1
        except Exception:
            return 1

    # 9. DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (expiration_date.year - creation_date.year) * 12 + (
                expiration_date.month - creation_date.month
            )
            return 1 if age >= 12 else -1
        except Exception:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all("head"):
                for head.link in self.soup.find_all("link", href=True):
                    dots = [x.start(0) for x in re.finditer(r"\.", head.link["href"])]
                    if (
                        self.url in head.link["href"]
                        or len(dots) == 1
                        or self.domain in head.link["href"]
                    ):
                        return 1
            return -1
        except Exception:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            return -1 if ":" in self.domain else 1
        except Exception:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            return -1 if "https" in self.domain else 1
        except Exception:
            return -1

    # 13. RequestURL
    def RequestURL(self):
        try:
            i, success = 0, 0
            for tag in ["img", "audio", "embed", "iframe"]:
                for el in self.soup.find_all(tag, src=True):
                    dots = [x.start(0) for x in re.finditer(r"\.", el["src"])]
                    if (
                        self.url in el["src"]
                        or self.domain in el["src"]
                        or len(dots) == 1
                    ):
                        success += 1
                    i += 1
            if i == 0:
                return 1
            percentage = (success / float(i)) * 100
            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            return -1
        except Exception:
            return -1

    # 14. AnchorURL
    def AnchorURL(self):
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all("a", href=True):
                if (
                    "#" in a["href"]
                    or "javascript" in a["href"].lower()
                    or "mailto" in a["href"].lower()
                    or not (self.url in a["href"] or self.domain in a["href"])
                ):
                    unsafe += 1
                i += 1
            if i == 0:
                return 1
            percentage = (unsafe / float(i)) * 100
            if percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            return -1
        except Exception:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i, success = 0, 0
            for link in self.soup.find_all("link", href=True):
                dots = [x.start(0) for x in re.finditer(r"\.", link["href"])]
                if (
                    self.url in link["href"]
                    or self.domain in link["href"]
                    or len(dots) == 1
                ):
                    success += 1
                i += 1
            for script in self.soup.find_all("script", src=True):
                dots = [x.start(0) for x in re.finditer(r"\.", script["src"])]
                if (
                    self.url in script["src"]
                    or self.domain in script["src"]
                    or len(dots) == 1
                ):
                    success += 1
                i += 1
            if i == 0:
                return 1
            percentage = (success / float(i)) * 100
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            return -1
        except Exception:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            forms = self.soup.find_all("form", action=True)
            if len(forms) == 0:
                return 1
            for form in forms:
                if form["action"] == "" or form["action"] == "about:blank":
                    return -1
                elif self.url not in form["action"] and self.domain not in form["action"]:
                    return 0
            return 1
        except Exception:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            return -1 if re.findall(r"[mail\(\)|mailto:?]", self.soup.text) else 1
        except Exception:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            return 1 if self.response.text == str(self.whois_response) else -1
        except Exception:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            return -1
        except Exception:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            return 1 if re.findall("<script>.+onmouseover.+</script>", self.response.text) else -1
        except Exception:
            return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            return 1 if re.findall(r"event.button ?== ?2", self.response.text) else -1
        except Exception:
            return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            return 1 if re.findall(r"alert\(", self.response.text) else -1
        except Exception:
            return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            return 1 if re.findall(r"[<iframe>|<frameBorder>]", self.response.text) else -1
        except Exception:
            return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            return 1 if age >= 6 else -1
        except Exception:
            return -1

    # 25. DNSRecording
    def DNSRecording(self):
        return self.AgeofDomain()

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(
                urllib.request.urlopen(
                    "http://data.alexa.com/data?cli=10&dat=s&url=" + self.url
                ).read(),
                "xml",
            ).find("REACH")["RANK"]
            return 1 if int(rank) < 100000 else 0
        except Exception:
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            rank_checker_response = requests.post(
                "https://checkpagerank.net/index.php", {"name": self.domain}, timeout=4
            )
            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
            return 1 if 0 < global_rank < 100000 else -1
        except Exception:
            return -1

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            from googlesearch import search
            site = list(search(self.url, num_results=5))
            return 1 if site else -1
        except Exception:
            return 1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            return -1
        except Exception:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
                r"at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly",
                self.url,
            )
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(
                r"146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|"
                r"181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98",
                ip_address,
            )
            return -1 if (url_match or ip_match) else 1
        except Exception:
            return 1

    def getFeaturesList(self):
        return self.features

    def getFeatureExplanations(self):
        metadata = [
            ("Using IP Address", {
                1: "Uses a standard domain name instead of a raw IP address.",
                -1: "Uses a raw IP address in the hostname, often used to mask server identity."
            }),
            ("URL Length", {
                1: "URL length is under 54 characters, typical of legitimate domains.",
                0: "URL length is moderately long (54–75 characters).",
                -1: "URL exceeds 75 characters, frequently used to hide malicious paths."
            }),
            ("URL Shortening Service", {
                1: "Does not rely on known URL shortener redirects.",
                -1: "Uses a URL shortener (e.g., bit.ly, tinyurl) that obscures the true destination."
            }),
            ("@ Symbol Presence", {
                1: "No '@' symbol detected in the URL structure.",
                -1: "Contains '@', causing browsers to ignore everything preceding it."
            }),
            ("Redirecting '//'", {
                1: "No unexpected double-slash redirects found in the URL path.",
                -1: "Contains '//' past position 6, indicating an embedded redirect."
            }),
            ("Prefix / Suffix ('-')", {
                1: "No hyphens found separating words in the domain name.",
                -1: "Uses hyphens in the domain (e.g., pay-pal-login), a common brand-spoofing tactic."
            }),
            ("Subdomain Depth", {
                1: "Single dot structure indicating standard root/www domain usage.",
                0: "Contains multiple subdomains (2 dots), moderately suspicious.",
                -1: "Excessive subdomains detected, often used to mimic legitimate hierarchies."
            }),
            ("HTTPS Protocol", {
                1: "Connection uses encrypted HTTPS protocol.",
                -1: "Uses unencrypted HTTP protocol, exposing transmitted data."
            }),
            ("Domain Registration Length", {
                1: "Domain is registered for 1 year or longer.",
                -1: "Domain registration is under 1 year or WHOIS expiry data is hidden."
            }),
            ("Favicon Origin", {
                1: "Favicon is loaded from the same domain as the webpage.",
                -1: "Favicon is loaded from an external domain or missing."
            }),
            ("Non-Standard Port", {
                1: "Uses standard web ports (80/443).",
                -1: "Specifies a non-standard port in the domain string."
            }),
            ("HTTPS Token in Domain", {
                1: "Does not spoof 'https' inside the domain name text.",
                -1: "Embeds 'https' within the domain string itself to deceive users."
            }),
            ("External Request URLs", {
                1: "Over 78% of page assets (images/media) load from the same domain.",
                0: "Between 39% and 78% of assets load from external domains.",
                -1: "Majority of page media is hotlinked from external domains."
            }),
            ("Anchor Tag Safety", {
                1: "Most anchor links point to valid internal/same-domain paths.",
                0: "31%–67% of links use '#' placeholders, JavaScript, or external domains.",
                -1: "Over 67% of links are dead anchors, mailto, or external redirects."
            }),
            ("Links in Script & Meta Tags", {
                1: "Scripts and stylesheets are predominantly self-hosted.",
                0: "Mix of internal and external script/link tags.",
                -1: "High proportion of external scripts and linked resources."
            }),
            ("Server Form Handler (SFH)", {
                1: "Form actions submit data to the legitimate host domain.",
                0: "Form submits data to an external domain.",
                -1: "Form action is empty or 'about:blank', typical of credential harvesters."
            }),
            ("Email Submission (mailto)", {
                1: "No client-side 'mailto:' or mail() submission functions detected.",
                -1: "Uses 'mailto:' or raw mail functions to exfiltrate form inputs."
            }),
            ("Abnormal URL / WHOIS Match", {
                1: "Host identity aligns cleanly with WHOIS records.",
                -1: "Host structure mismatches or lacks verifiable WHOIS identity."
            }),
            ("Website Forwarding", {
                1: "Minimal redirects (0–1 hops) before reaching final page.",
                0: "Redirected 2–4 times before landing.",
                -1: "Excessive redirect chain (>4 hops) or unreachable host."
            }),
            ("Status Bar Customization", {
                1: "Does not manipulate browser status bar via onMouseOver scripts.",
                -1: "Uses JavaScript onMouseOver events to mask true link destinations."
            }),
            ("Right-Click Disabled", {
                1: "Standard browser context menu (right-click) is enabled.",
                -1: "Disables right-click via JavaScript to prevent source inspection."
            }),
            ("Popup Windows", {
                1: "No intrusive JavaScript alert/popup prompts detected.",
                -1: "Triggers JavaScript popup windows to solicit user interaction."
            }),
            ("Iframe Redirection", {
                1: "No hidden or borderless iframes detected.",
                -1: "Uses iframes capable of silently overlaying external phishing pages."
            }),
            ("Domain Age", {
                1: "Domain has been active for at least 6 months.",
                -1: "Domain is newly registered (<6 months old) or creation date is concealed."
            }),
            ("DNS Record Availability", {
                1: "Valid DNS and WHOIS creation records found.",
                -1: "Missing or unresolvable DNS registration records."
            }),
            ("Website Traffic Rank", {
                1: "High global traffic footprint (Top 100k).",
                0: "Moderate global traffic footprint.",
                -1: "Very low or unrecognized global web traffic."
            }),
            ("PageRank Score", {
                1: "Recognized authority rank in global page indexing.",
                -1: "Low or unindexed PageRank score."
            }),
            ("Google Indexing", {
                1: "URL is indexed in Google Search results.",
                -1: "URL is absent from Google Search index."
            }),
            ("Inbound Links Pointing to Page", {
                1: "Clean outbound/inbound link structure.",
                0: "Limited link structure detected on page.",
                -1: "Abnormal link density or unreachable DOM structure."
            }),
            ("Known Malicious Host / IP Report", {
                1: "Domain and resolved IP are clean of known phishing blacklists.",
                -1: "Matches known malicious free-hosting domains or flagged IP ranges."
            })
        ]

        results = []
        for idx, val in enumerate(self.features):
            name, desc_map = metadata[idx]
            status = "safe" if val == 1 else ("warning" if val == 0 else "danger")
            label = "Safe" if val == 1 else ("Suspicious" if val == 0 else "Phishing Risk")
            reason = desc_map.get(val, desc_map.get(-1))
            results.append({
                "id": idx + 1,
                "name": name,
                "value": val,
                "status": status,
                "label": label,
                "reason": reason
            })
        return results