"""
language_utils.py
This file adds the "multi-language detection" feature (v4, part 4).

All of our rule checks in rules.py look for specific English phrases
("verify your account", "act now", etc). That means a phishing email
written in another language (Spanish, Sinhala, Italian, and so on) would
score 0 and look "safe", even if it's an obvious scam to a native
speaker. This file fixes that gap: it detects which language the email is
written in, and if it isn't English, translates it to English first so
the existing rules can still catch the same patterns.

Detecting the language works fully offline (no internet needed). The
translation step does need internet access, so if that's not available
(or the translation service is unreachable), the tool simply says so and
falls back to analysing the original, un-translated text, it never
crashes.
"""

import py3langid as langid
from deep_translator import GoogleTranslator, MyMemoryTranslator

# Only flag a language as "confidently detected" past this length, very
# short text (like just a subject line) isn't reliable to detect from.
MIN_TEXT_LENGTH_FOR_DETECTION = 20

# Common language codes mapped to a readable name, for the report.
# py3langid can detect many more than this, these are just the ones we
# show a friendly name for, anything else still works, just shows its code.
LANGUAGE_NAMES = {
    "en": "English", "es": "Spanish", "fr": "French", "de": "German",
    "it": "Italian", "pt": "Portuguese", "nl": "Dutch", "ru": "Russian",
    "zh": "Chinese", "ja": "Japanese", "ko": "Korean", "ar": "Arabic",
    "hi": "Hindi", "si": "Sinhala", "ta": "Tamil", "vi": "Vietnamese",
    "th": "Thai", "id": "Indonesian", "tr": "Turkish", "pl": "Polish",
    "uk": "Ukrainian", "ro": "Romanian", "sv": "Swedish", "el": "Greek",
}

# The MyMemory translation service (our backup) needs a more specific
# language code than py3langid gives us, e.g. "es-ES" instead of just
# "es". This maps our short codes to the ones MyMemory expects.
MYMEMORY_LANG_CODES = {
    "en": "en-GB", "es": "es-ES", "fr": "fr-FR", "de": "de-DE",
    "it": "it-IT", "pt": "pt-PT", "nl": "nl-NL", "ru": "ru-RU",
    "zh": "zh-CN", "ja": "ja-JP", "ko": "ko-KR", "ar": "ar-SA",
    "hi": "hi-IN", "si": "si-LK", "ta": "ta-IN", "vi": "vi-VN",
    "th": "th-TH", "id": "id-ID", "tr": "tr-TR", "pl": "pl-PL",
    "uk": "uk-UA", "ro": "ro-RO", "sv": "sv-SE", "el": "el-GR",
}


def detect_language(text: str):
    """
    Detects the language of the given text.
    Returns a tuple: (language_code, language_name).
    If the text is too short to reliably detect, or detection fails,
    returns (None, None) instead of guessing.
    """
    if not text or len(text.strip()) < MIN_TEXT_LENGTH_FOR_DETECTION:
        return None, None

    try:
        code, _confidence = langid.classify(text)
        name = LANGUAGE_NAMES.get(code, code.upper())
        return code, name
    except Exception:
        return None, None


def translate_to_english(text: str, source_lang: str) -> str:
    """
    Translates the given text into English. Tries Google Translate first
    (via the deep-translator library), and if that fails for any reason
    (it uses an unofficial connection to Google's website, which can get
    temporarily rate-limited on busy networks), automatically falls back
    to a second free service, MyMemory, before giving up.

    Returns the translated text, or None if both services failed (no
    internet, both services unreachable, etc), so the caller can fall
    back to the original text instead of crashing.
    """
    # Google Translate (and MyMemory) have a request size limit, so very
    # long emails are trimmed first. This is just for the phishing-phrase
    # check, not for displaying to the user, so trimming is safe here.
    trimmed = text[:4500]

    try:
        translated = GoogleTranslator(source=source_lang, target="en").translate(trimmed)
        if translated and translated.strip():
            return translated
    except Exception:
        pass

    # Google failed (often a temporary rate-limit), try the backup service.
    # MyMemory needs the more specific code format (e.g. "es-ES"), so we
    # look that up; if we don't have a mapping for this language, we skip
    # this backup rather than guess a code that's guaranteed to fail.
    mymemory_source = MYMEMORY_LANG_CODES.get(source_lang)
    if mymemory_source:
        try:
            translated = MyMemoryTranslator(
                source=mymemory_source, target=MYMEMORY_LANG_CODES["en"]
            ).translate(trimmed)
            if translated and translated.strip():
                return translated
        except Exception:
            pass

    return None
