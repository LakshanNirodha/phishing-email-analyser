"""
rules.py
This file holds all the "rule checks". Each function looks at the email for
ONE suspicious thing, and returns a tuple: (points, reason_text).
If nothing suspicious is found for that check, it returns (0, None).

Keeping each check in its own small function makes it easy to:
 - test one rule at a time
 - add a new rule later without breaking old ones
 - explain each rule separately in an interview
"""

import re

# Free email providers that scammers often use to pretend to be a company
FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com"
]

# Words that try to rush the reader into acting without thinking
URGENCY_WORDS = [
    "urgent", "immediately", "act now", "verify your account",
    "suspended", "act fast", "limited time", "final notice",
    "confirm your details", "click here now", "within 24 hours",
    "hurry", "selling fast", "going fast", "before it's too late",
]

# Greetings that don't use a real name, common in mass phishing emails
GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer",
    "dear sir/madam", "dear account holder", "hello user"
]

# Link shorteners hide the real destination, often used to disguise scam links
LINK_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]

# Phrases used to try to move the conversation off email, onto an
# unmonitored personal channel (WhatsApp, personal phone), a common
# social engineering tactic once trust has been built
OFFLINE_CHANNEL_PHRASES = [
    "whatsapp", "personal mobile number", "personal number",
    "direct engagement", "established email channel", "contact record",
    "kindly furnish", "kindly provide", "kindly share",
]

# Real, well-known domains that scammers commonly impersonate with a
# slightly misspelled lookalike (this is a documented tactic called
# "typosquatting", used in real phishing campaigns against these exact brands)
KNOWN_BRAND_DOMAINS = [
    "microsoft.com", "outlook.com", "office.com", "paypal.com", "apple.com",
    "amazon.com", "google.com", "linkedin.com", "duolingo.com", "netflix.com",
    "facebook.com", "instagram.com", "dhl.com", "fedex.com",
    "commbank.com.au", "westpac.com.au", "anz.com.au", "nab.com.au",
    "auspost.com.au", "ato.gov.au",
    "homedepot.com", "walmart.com", "target.com", "costco.com",
    "bestbuy.com", "ebay.com", "usps.com", "ups.com",
]

# Phrases asking for the exact kind of information a real company would
# never ask for by email, a core indicator used across real phishing
# awareness training (e.g. CISA and SANS phishing guidance)
CREDENTIAL_OR_PAYMENT_PHRASES = [
    "enter your password", "confirm your password", "your pin",
    "bank details", "banking details", "bank account details", "wire transfer", "gift card", "update your payment",
    "billing information", "credit card number", "credit card details",
    "login credentials", "security code", "one-time code", "verification code",
]

# Requests for personal details that go FAR beyond what's needed to
# contact someone or deliver a genuine prize, a well-documented tactic
# in prize/lottery/competition scams: the "prize" is bait to harvest
# personal information (sometimes about the victim's family too), which
# is then used for identity theft or sold on, or used to make a later
# scam message feel more convincing and personal.
PERSONAL_INFO_HARVEST_PHRASES = [
    "partner's name", "partner's details", "spouse's name", "spouse's details",
    "children's names", "children's details", "next of kin", "date of birth",
    "home address", "marital status", "full name and address",
    "family member's details", "emergency contact details",
]

# Phrases that try to isolate the reader from checking with anyone else,
# a core tactic in Business Email Compromise (BEC) / CEO fraud. Named as
# one of the "7 Universal Red Flags" in real incident-response guidance:
# secrecy stops the one thing that would catch the scam, a second person
# checking. This is how real multi-million dollar BEC frauds work (e.g.
# the 2025 NTMA 5 million euro case): urgency plus secrecy together.
SECRECY_PHRASES = [
    "don't tell anyone", "don't loop in", "keep this confidential",
    "handle it yourself", "between us", "do not discuss this with anyone",
    "don't mention this to", "keep this between", "do not cc",
    "without informing", "quietly", "discreetly",
]

# Phrases specifically about CHANGING existing payment/banking arrangements,
# the real-world highest-loss BEC pattern: not "give me your password", but
# "we changed banks, send the payment here instead". Documented as the
# single largest category of BEC loss (FBI IC3: over $2.7B in 2024 from
# this exact tactic; real cases include Orion Chemical's $60M loss and
# Southern Oregon University's $1.9M loss, both from this pattern).
PAYMENT_REDIRECT_PHRASES = [
    "updated bank details", "update our bank account", "change of bank account",
    "new banking details", "remittance information", "new wire instructions",
    "updated remittance", "update our payment details", "new account for payments",
    "updated banking information", "changed our bank",
]

# Free subdomain-hosting services that attackers abuse to host fake login
# pages. Because the main domain (e.g. sites.google.com) genuinely belongs
# to a trusted company, these pages can slip past basic domain-reputation
# checks and look "safe" at a glance. Documented real technique (e.g. in
# LetsDefend's SOC analyst training): WHOIS lookups can't flag a subdomain
# as newly registered the way they would a brand-new standalone domain.
FREE_HOSTING_DOMAINS = [
    "sites.google.com", "docs.google.com/forms", "forms.gle",
    "blogspot.com", "wixsite.com", "weebly.com", "glitch.me",
    "github.io", "netlify.app", "herokuapp.com", "repl.co",
    "000webhostapp.com", "firebaseapp.com", "web.app",
]

# Phrases from the classic "advance fee" / inheritance scam (sometimes
# called the "Nigerian Prince scam"), one of the oldest and still most
# common phishing categories: a huge sum of money (inheritance, lottery,
# unclaimed funds) is dangled, and the real goal is either an upfront
# "fee" payment or personal/banking details.
ADVANCE_FEE_SCAM_PHRASES = [
    "inheritance", "billionaire relative", "long lost relative",
    "unclaimed funds", "deceased relative", "sole beneficiary",
    "foreign partner", "lottery winnings", "secret fortune",
    "claim your inheritance",
]

# "Easy money" / work-from-home scam phrases, one of the oldest and most
# common spam/scam genres: promising large guaranteed income for little
# or no real work, usually to either steal money upfront or recruit
# victims into a money-laundering scheme (sometimes called a "money mule").
EASY_MONEY_SCAM_PHRASES = [
    "work from home", "make money from home", "quit your job today",
    "be your own boss", "no experience needed", "guaranteed income",
    "zero experience needed", "earn thousands", "per day from home",
    "zero critical thinking skills",
]

# "Miracle product" / too-good-to-be-true scam phrases: guaranteed
# results, regulatory evasion language ("before they find out"), common
# in fake health/beauty product spam.
MIRACLE_PRODUCT_SCAM_PHRASES = [
    "guarantees results", "before the fda finds out", "doctors don't want you to know",
    "miracle formula", "instant results", "revolutionary formula",
]

# Romance scam phrases: a fake profile builds a fast emotional connection
# to manipulate the victim, usually leading to requests for money later.
# A well-documented, high-loss real scam category (dating/romance fraud).
ROMANCE_SCAM_PHRASES = [
    "searching for their soulmate", "looking for love", "click to chat now",
    "meet singles", "lonely and looking", "find your soulmate",
]

PYRAMID_SCHEME_PHRASES = [
    "pyramid scheme", "hidden world of", "lost secrets", "ancient secrets",
    "recruit others", "sign up under you", "get others to join",
    "earn from your downline", "unlock the secret to wealth",
]

# File types that can run code on a computer when opened, a standard
# "dangerous attachment" indicator, flagged when mentioned as an attachment.
# Includes "macro-enabled" Office formats (.docm/.xlsm/.pptm), a well-known
# real malware delivery method, .iso/.img which are used to slip past
# some email scanners, and Windows scripting formats (.ps1 PowerShell,
# .vbe, .wsf, .hta), which are an extremely common real attack method
# today, a script often does more damage than a classic .exe and is
# easier to disguise as a harmless-looking "fix" or "update" file.
DANGEROUS_ATTACHMENT_EXTENSIONS = [
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".msi",
    ".docm", ".xlsm", ".pptm", ".iso", ".img",
    ".ps1", ".psm1", ".vbe", ".wsf", ".hta",
]

# Subject/body lure phrases that real phishing campaigns reuse constantly
# because they work regardless of who the target is, no personal info
# about the victim is needed to write them. Recognized as "mass lure"
# bait in phishing awareness training.
LURE_PHRASES = [
    "invoice attached", "payment confirmation", "you have a new voicemail",
    "delivery failed", "unclaimed package", "you have won", "claim your prize",
    "unusual sign-in activity", "your order could not be delivered",
    "tax refund", "failed payment", "your subscription will renew",
    "collaboration opportunity", "sponsorship opportunity", "brand partnership",
    "paid in advance",
    "order placed", "order confirmation", "your order id",
    "order successfully placed", "order has been confirmed",
]

# Phrases describing a password-protected ZIP/RAR archive sent as an
# attachment, a real, well-documented malware delivery trick. Email
# scanners and antivirus usually can't open a password-protected archive
# to check what's inside, so attackers protect the malware with a
# password and then just give you that password in the email itself,
# bypassing the exact protection that would normally have caught it.
# This was the technique used in a real, documented phishing attempt
# against a cybersecurity YouTuber (a fake Duolingo brand deal), where a
# password-protected ZIP contained a Trojan disguised as video files.
PASSWORD_PROTECTED_ARCHIVE_PHRASES = [
    "password to unzip", "password to extract", "zip password",
    "password protected file", "password-protected file",
    "use this password to open", "extract using the password",
    "password to open the attached", "use the password below to unzip",
]


def check_sender_domain(headers_text: str, claimed_company: str = None):
    """
    Looks for the sender's email address, whether it's written as a proper
    "From:" header, or just copied as plain text like 'Name<email@domain.com>'
    from an email reading pane. If the email claims to be from a company but
    is sent from a free email address (like Gmail), that's suspicious.
    """
    # Try the formal header format first: "From: Name <email@domain.com>"
    match = re.search(r"From:\s*.*?@([\w\.-]+)", headers_text, re.IGNORECASE)

    # Fall back to a looser pattern that catches plain-text copies like
    # "Office Team support<officeteamsupport532@gmail.com>" with no "From:" label
    if not match:
        match = re.search(r"[\w\.\-]+@([\w\.-]+)", headers_text[:300])  # only check near the top

    if not match:
        return 0, None

    domain = match.group(1).lower()
    for provider in FREE_EMAIL_PROVIDERS:
        if provider in domain:
            return 30, f"Sender uses a free email address ({domain}), not a real company domain"
    return 0, None


def check_offline_channel_request(body_text: str):
    """
    Looks for attempts to move the conversation off email, onto an
    unmonitored personal channel like WhatsApp or a personal phone number.
    This is a common tactic once a scammer has built some initial trust,
    it's harder to trace and easier to pressure someone on WhatsApp/SMS
    than on a company email thread.
    """
    lower_body = body_text.lower()
    found = [phrase for phrase in OFFLINE_CHANNEL_PHRASES if phrase in lower_body]

    if found:
        points = min(15 * len(found), 40)
        return points, f"Tries to move the conversation off email: {', '.join(found)}"
    return 0, None


def check_urgency_language(body_text: str):
    """
    Looks for words designed to make the reader panic and act fast.
    """
    found = []
    lower_body = body_text.lower()
    for word in URGENCY_WORDS:
        if word in lower_body:
            found.append(word)

    if found:
        points = min(10 * len(found), 30)  # cap so many matches don't break the scale
        return points, f"Urgency language found: {', '.join(found)}"
    return 0, None


def check_generic_greeting(body_text: str):
    """
    Checks if the email uses a generic greeting instead of the reader's real name.
    """
    lower_body = body_text.lower()
    for greeting in GENERIC_GREETINGS:
        if greeting in lower_body:
            return 15, f'Generic greeting used: "{greeting}"'
    return 0, None


def check_suspicious_links(body_text: str):
    """
    Looks for raw links in the email and flags:
    - link shorteners (hide the real destination)
    - links using a raw IP address instead of a normal website name
    """
    urls = re.findall(r"https?://[^\s\)\]]+", body_text)
    if not urls:
        return 0, None

    reasons = []
    for url in urls:
        for shortener in LINK_SHORTENERS:
            if shortener in url:
                reasons.append(f"shortened link ({url})")
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            reasons.append(f"link uses a raw IP address instead of a website name ({url})")

    if reasons:
        return 25, "Suspicious links found: " + "; ".join(reasons)
    return 0, None


def _levenshtein_distance(a: str, b: str) -> int:
    """
    Measures how many single-letter changes it takes to turn one word into
    another. For example "micr0soft.com" is distance 1 from "microsoft.com"
    (just one letter swapped). This is a standard, well-known algorithm used
    in real anti-phishing tools to catch lookalike domains.
    """
    if len(a) < len(b):
        return _levenshtein_distance(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, char_a in enumerate(a):
        current_row = [i + 1]
        for j, char_b in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (char_a != char_b)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def check_lookalike_domain(headers_text: str):
    """
    Checks whether the sender's domain is suspiciously close to (but not
    exactly) a well-known real company domain. This covers two real,
    documented scam tactics:

    1. Typosquatting: a misspelled letter, e.g. "micr0soft.com" instead of
       "microsoft.com" (close by edit-distance).
    2. Combosquatting: the real brand name is used in full, but with extra
       words or a hyphen tacked on, e.g. "duolingo-dash.com" or
       "paypal-secure-login.com" instead of "duolingo.com"/"paypal.com".
       This is exactly how the real email thread on the Duolingo phishing
       case (covered in security-awareness videos) worked: the brand name
       is right there, which is what makes it convincing at a glance, but
       it is not the real domain.
    """
    match = re.search(r"From:\s*.*?@([\w\.-]+)", headers_text, re.IGNORECASE)
    if not match:
        match = re.search(r"[\w\.\-]+@([\w\.-]+)", headers_text[:300])
    if not match:
        return 0, None

    domain = match.group(1).lower()

    for brand in KNOWN_BRAND_DOMAINS:
        if domain == brand:
            return 0, None  # exact match to a real brand domain, not a lookalike

        brand_name = brand.split(".")[0]  # e.g. "duolingo" from "duolingo.com"

        # Combosquatting: brand name present, but extra text added before the
        # real top-level domain, e.g. "duolingo-dash.com", "duolingo.verify.com"
        if brand_name in domain and domain != brand:
            return 35, (
                f'Sender domain "{domain}" contains the real brand name "{brand_name}" '
                f'but is not the real domain ("{brand}"). This is a common scam trick, '
                f'the brand name alone does not make it real.'
            )

        # Typosquatting: a small misspelling of the whole domain
        distance = _levenshtein_distance(domain, brand)
        if 0 < distance <= 2:
            return 35, f'Sender domain "{domain}" looks like a misspelled version of "{brand}"'
    return 0, None


def check_display_name_mismatch(headers_text: str):
    """
    Looks for a sender "display name" that claims to be a well-known
    company (e.g. "PayPal Security Team"), while the actual email address
    domain has nothing to do with that company at all. This is a very
    common, well-documented tactic called "display name spoofing": most
    phone/webmail apps show only the display name by default, not the
    real address, so people trust the name without checking the address.
    """
    # Match "Display Name <email@domain>" or "Display Name<email@domain>"
    match = re.search(r"([A-Za-z][A-Za-z0-9 .&\-]{2,40})\s*<\s*[\w\.\-]+@([\w\.-]+)\s*>", headers_text[:400])
    if not match:
        return 0, None

    display_name = match.group(1).strip().lower()
    # Brand names in KNOWN_BRAND_DOMAINS have no spaces (e.g. "homedepot" from
    # "homedepot.com"), but a real display name often has the natural spacing
    # back in ("Home Depot", "Best Buy"). Compare against a space-stripped
    # copy of the display name too, so "Home Depot" still matches "homedepot".
    display_name_nospace = display_name.replace(" ", "").replace("-", "")
    domain = match.group(2).lower()

    for brand in KNOWN_BRAND_DOMAINS:
        brand_name = brand.split(".")[0]
        if brand_name in display_name or brand_name in display_name_nospace:
            # If the domain doesn't even contain the brand name, it's a clear mismatch
            # (the combosquatting check above already handles when it DOES contain it)
            if brand_name not in domain:
                return 35, (
                    f'Display name says "{match.group(1).strip()}" (sounds like {brand_name}), '
                    f'but the real email address domain is "{domain}", which has no connection to it'
                )
    return 0, None


def check_lure_subject_or_body(email_text: str):
    """
    Looks for generic "mass lure" phrases that real phishing campaigns
    reuse across millions of emails because they work on almost anyone,
    regardless of who the target is (no personal detail needed).
    """
    combined = email_text.lower()
    found = [phrase for phrase in LURE_PHRASES if phrase in combined]

    if found:
        points = min(10 * len(found), 20)
        return points, f"Uses a common mass-phishing lure phrase: {', '.join(found)}"
    return 0, None


def check_credential_or_payment_request(body_text: str):
    """
    Looks for requests for the exact kind of sensitive information a
    legitimate company will never ask for over email: passwords, PINs,
    bank details, gift cards, verification codes.
    """
    lower_body = body_text.lower()
    found = [phrase for phrase in CREDENTIAL_OR_PAYMENT_PHRASES if phrase in lower_body]

    if found:
        points = min(20 * len(found), 40)
        return points, f"Requests sensitive information: {', '.join(found)}"
    return 0, None


def check_secrecy_request(body_text: str):
    """
    Looks for language that tries to stop the reader from checking with
    anyone else before acting. This is one of the most reliable real
    indicators of Business Email Compromise (CEO fraud): the scam only
    works if the victim doesn't verify with a second person, so the
    scammer asks for secrecy directly. Urgency alone is common in normal
    emails too, but urgency PLUS secrecy together is a strong combination.
    """
    lower_body = body_text.lower()
    found = [phrase for phrase in SECRECY_PHRASES if phrase in lower_body]

    if found:
        points = min(20 * len(found), 35)
        return points, f"Asks the reader to keep this secret or act without telling anyone: {', '.join(found)}"
    return 0, None


def check_payment_redirect_request(body_text: str):
    """
    Looks for a request to change where a payment is sent, e.g. "updated
    bank details" or "new wire instructions". This is a different, and
    more expensive, real-world pattern than a normal credential-phishing
    email: it targets a business process (paying an existing invoice or
    vendor) rather than asking an individual to log in somewhere. This is
    documented as the costliest phishing category for businesses.
    """
    lower_body = body_text.lower()
    found = [phrase for phrase in PAYMENT_REDIRECT_PHRASES if phrase in lower_body]

    if found:
        points = min(25 * len(found), 45)
        return points, f"Asks to redirect a payment to new banking details: {', '.join(found)}"
    return 0, None


def check_advance_fee_scam(body_text: str):
    """
    Looks for the classic "advance fee" / inheritance scam pattern: a
    surprise fortune (inheritance, lottery, unclaimed funds) dangled to
    get the reader to hand over money or personal/banking details. One of
    the oldest documented phishing categories, still active today.
    """
    lower_body = body_text.lower()
    found = [phrase for phrase in ADVANCE_FEE_SCAM_PHRASES if phrase in lower_body]

    if found:
        points = min(25 * len(found), 40)
        return points, f"Uses a classic inheritance/advance-fee scam pattern: {', '.join(found)}"
    return 0, None


def check_easy_money_scam(body_text: str):
    """
    Looks for "work from home, guaranteed income" style scam language.
    One of the oldest, most common spam genres, promising large income
    for little or no real work, usually to steal money upfront or to
    recruit the victim into unknowingly laundering stolen money.
    """
    lower_body = body_text.lower()
    found = [phrase for phrase in EASY_MONEY_SCAM_PHRASES if phrase in lower_body]

    if found:
        points = min(20 * len(found), 35)
        return points, f"Uses a classic 'easy money' / work-from-home scam pattern: {', '.join(found)}"
    return 0, None


def check_miracle_product_scam(body_text: str):
    """
    Looks for "guaranteed results, miracle formula" style scam language,
    common in fake health/beauty product spam, often paired with
    regulatory-evasion phrasing like "before they find out".
    """
    lower_body = body_text.lower()
    found = [phrase for phrase in MIRACLE_PRODUCT_SCAM_PHRASES if phrase in lower_body]

    if found:
        points = min(20 * len(found), 30)
        return points, f"Uses a 'too good to be true' miracle product scam pattern: {', '.join(found)}"
    return 0, None


def check_romance_scam(body_text: str):
    """
    Looks for romance/dating scam language, a fake profile building a
    fast emotional connection, a well-documented, high-loss real scam
    category that usually leads to requests for money later.
    """
    lower_body = body_text.lower()
    found = [phrase for phrase in ROMANCE_SCAM_PHRASES if phrase in lower_body]

    if found:
        points = min(20 * len(found), 30)
        return points, f"Uses a romance/dating scam pattern: {', '.join(found)}"
    return 0, None


def check_pyramid_scheme(body_text: str):
    """
    Looks for pyramid scheme / MLM recruitment language dressed up as a
    mysterious opportunity ("hidden world", "ancient secrets"), paired with
    a request for money or financial details to "join". A well-documented,
    long-running scam category distinct from a normal payment-phishing
    email because the hook is recruitment/opportunity, not a fake invoice
    or account alert.
    """
    lower_body = body_text.lower()
    found = [phrase for phrase in PYRAMID_SCHEME_PHRASES if phrase in lower_body]

    if found:
        points = min(20 * len(found), 30)
        return points, f"Uses pyramid scheme / MLM recruitment language: {', '.join(found)}"
    return 0, None


def check_personal_info_harvest(body_text: str):
    """
    Looks for requests for personal details that go far beyond what's
    needed to contact someone or send them something, especially details
    about the person's FAMILY (partner, children, next of kin). This is a
    real, recognized tactic in prize/competition/lottery scams: the
    "prize" is the hook, and the real goal is collecting personal
    information about the victim and the people around them.
    """
    lower_body = body_text.lower()
    found = [phrase for phrase in PERSONAL_INFO_HARVEST_PHRASES if phrase in lower_body]

    if found:
        points = min(20 * len(found), 40)
        return points, f"Asks for personal/family details that aren't needed: {', '.join(found)}"
    return 0, None


def check_dangerous_attachment_mention(body_text: str):
    """
    Looks for a mentioned attachment filename with a file type that can run
    code when opened, a standard "dangerous attachment" indicator.
    This checks the text for a filename pattern, it does not scan real
    attached files (this tool only analyses pasted text).
    """
    found = []
    for ext in DANGEROUS_ATTACHMENT_EXTENSIONS:
        matches = re.findall(r"[\w\-]+" + re.escape(ext), body_text, re.IGNORECASE)
        found.extend(matches)

    if found:
        return 30, f"Mentions a risky attachment type: {', '.join(found)}"
    return 0, None


def check_password_protected_archive(body_text: str):
    """
    Looks for a password being given to open a ZIP/RAR archive. Email
    scanners and antivirus normally can't open a password-protected
    archive to inspect what's inside, so this is a real, well-documented
    trick: the attacker protects the malware with a password, then just
    hands you that password in the email, defeating the exact scanning
    that would normally have caught it. A real company sending you a
    genuine file almost never needs to do this.
    """
    lower_body = body_text.lower()
    found = [phrase for phrase in PASSWORD_PROTECTED_ARCHIVE_PHRASES if phrase in lower_body]

    if found:
        return 40, (
            f"Gives a password to open a protected ZIP/RAR file: {', '.join(found)}. "
            f"This is a known trick to stop antivirus and email scanners from "
            f"checking what's actually inside the file before you open it"
        )
    return 0, None


def check_reply_to_mismatch(headers_text: str):
    """
    Compares the domain in the "From" address to the domain in the
    "Reply-To" address, if one is present. A real company's Reply-To
    normally matches its From domain. A mismatch is a well-known tactic:
    the email LOOKS like it's from the real company, but any reply (or
    automatic reply) actually goes to the scammer's own address instead.
    """
    from_match = re.search(r"From:\s*.*?@([\w\.-]+)", headers_text, re.IGNORECASE)
    reply_match = re.search(r"Reply-To:\s*.*?@([\w\.-]+)", headers_text, re.IGNORECASE)

    if not from_match or not reply_match:
        return 0, None  # most pasted emails won't have a Reply-To, that's normal

    from_domain = from_match.group(1).lower()
    reply_domain = reply_match.group(1).lower()

    if from_domain != reply_domain:
        return 30, (
            f'The "From" address domain ("{from_domain}") does not match the '
            f'"Reply-To" address domain ("{reply_domain}"), replies would go '
            f'somewhere different to where the email claims to be from'
        )
    return 0, None


def check_return_path_mismatch(headers_text: str):
    """
    Compares the domain in the "From" address to the domain in the
    "Return-Path" header, if one is present. Return-Path is a technical
    header set by the server that actually sent the email, it's harder for
    a scammer to fake convincingly than the From name. This exact check
    (comparing Return-Path to From) is taught directly in TryHackMe's
    Phishing Analysis module as a real header-analysis technique.
    Most emails pasted from a reading pane won't include this header,
    that's normal, it only shows up when the full raw email source is used.
    """
    from_match = re.search(r"From:\s*.*?@([\w\.-]+)", headers_text, re.IGNORECASE)
    return_path_match = re.search(r"Return-Path:\s*.*?@([\w\.-]+)", headers_text, re.IGNORECASE)

    if not from_match or not return_path_match:
        return 0, None

    from_domain = from_match.group(1).lower()
    return_path_domain = return_path_match.group(1).lower()

    if from_domain != return_path_domain:
        return 30, (
            f'The "From" address domain ("{from_domain}") does not match the '
            f'"Return-Path" domain ("{return_path_domain}"), a technical sign '
            f'the email was not actually sent by who it claims to be from'
        )
    return 0, None


def check_masked_link(raw_text: str):
    """
    Looks for HTML links where the VISIBLE text shown to the reader names
    one domain (e.g. "Click here: paypal.com"), but the real web address
    behind the link (the href) goes somewhere completely different. This
    is one of the most common real phishing tactics in HTML emails, the
    reader sees a trusted-looking web address but never checks where the
    link actually goes. This check only works when the full HTML source
    of the email is pasted in (not just the plain reading-pane text).
    """
    link_pattern = re.compile(
        r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL,
    )
    domain_pattern = re.compile(r"([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)")

    for href, visible_html in link_pattern.findall(raw_text):
        visible_text = re.sub(r"<[^>]+>", " ", visible_html).strip()

        visible_domain_match = domain_pattern.search(visible_text)
        href_domain_match = re.search(r"https?://([\w\.-]+)", href, re.IGNORECASE)
        if not href_domain_match:
            href_domain_match = domain_pattern.search(href)

        if visible_domain_match and href_domain_match:
            visible_domain = visible_domain_match.group(1).lower()
            href_domain = href_domain_match.group(1).lower()
            if visible_domain != href_domain and visible_domain not in href_domain:
                return 35, (
                    f'A link shows the text "{visible_domain}" but actually points to '
                    f'"{href_domain}", a classic masked-link phishing trick'
                )
    return 0, None


def check_email_in_url_parameter(email_text: str):
    """
    Looks for the recipient's own email address embedded inside a link's
    web address, e.g. "...?email=victim@example.com". This is a real
    tracking technique: even if the victim doesn't enter anything on the
    fake page, just clicking the link confirms to the attacker that this
    email address is real and actively used, making it more valuable for
    future attacks. Documented in SOC analyst training (e.g. LetsDefend)
    as something to check before visiting any link in a suspicious email.
    """
    urls = re.findall(r"https?://[^\s\)\]\"'<>]+", email_text)
    for url in urls:
        if re.search(r"[?&][\w]*email[\w]*=[^&\s]*%40", url, re.IGNORECASE) or \
           re.search(r"[?&][\w]*email[\w]*=[^&\s]*@", url, re.IGNORECASE):
            return 30, (
                f"A link contains what looks like an email address in its web "
                f"address ({url}), a tracking trick to confirm your email is "
                f"real just by clicking, even before you enter anything"
            )
    return 0, None


def check_free_hosting_link(email_text: str):
    """
    Looks for links hosted on a free subdomain-hosting service (Google
    Sites, Blogspot, Glitch, Netlify, etc.). These are genuinely harder to
    flag automatically: the main domain is a real, trusted company, so
    basic domain checks (like "is this a brand new domain") don't catch
    it the way they would a standalone lookalike domain. Documented real
    evasion technique in SOC analyst training.
    """
    lower_text = email_text.lower()
    found = [domain for domain in FREE_HOSTING_DOMAINS if domain in lower_text]

    if found:
        return 25, (
            f"Contains a link hosted on a free subdomain service "
            f"({', '.join(found)}), sometimes abused to host fake login "
            f"pages because the main domain looks trustworthy"
        )
    return 0, None


def check_spf_dkim_dmarc(headers_text: str):
    """
    Looks for authentication failures in the headers, if present.
    Not every pasted email will include these, so this check is optional.
    """
    lower_headers = headers_text.lower()
    reasons = []
    if "spf=fail" in lower_headers:
        reasons.append("SPF check failed")
    if "dkim=fail" in lower_headers:
        reasons.append("DKIM check failed")
    if "dmarc=fail" in lower_headers:
        reasons.append("DMARC check failed")

    if reasons:
        return 20, "Email authentication failed: " + ", ".join(reasons)
    return 0, None


# This list makes it easy to run every rule in one loop from main.py
ALL_RULES = [
    check_sender_domain,
    check_urgency_language,
    check_generic_greeting,
    check_suspicious_links,
    check_spf_dkim_dmarc,
    check_offline_channel_request,
    check_lookalike_domain,
    check_display_name_mismatch,
    check_credential_or_payment_request,
    check_advance_fee_scam,
    check_easy_money_scam,
    check_miracle_product_scam,
    check_romance_scam,
    check_pyramid_scheme,
    check_personal_info_harvest,
    check_secrecy_request,
    check_payment_redirect_request,
    check_dangerous_attachment_mention,
    check_password_protected_archive,
    check_lure_subject_or_body,
    check_reply_to_mismatch,
    check_return_path_mismatch,
    check_email_in_url_parameter,
    check_free_hosting_link,
]

# check_masked_link is NOT in this list on purpose. Every other rule reads
# the DECODED, HTML-stripped text. check_masked_link needs the RAW text
# instead, because it has to see the actual <a href="..."> tags before
# they get stripped out. main.py calls it separately for this reason.
