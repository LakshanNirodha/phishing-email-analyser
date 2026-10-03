"""
qr_utils.py
This file adds the "QR code link checking" feature (v4, part 5, the last
one on the roadmap).

Scammers increasingly put a QR code image inside an email instead of a
normal clickable link, specifically because most security tools (and most
people) only read the text of an email, not the picture inside it. This
file reads a QR code image, pulls out whatever link is hidden inside it,
and feeds that link into the SAME phishing checks the rest of the tool
already uses (suspicious shortened links, raw IP links, etc), so a QR
code can't be used to sneak past the checks.

Uses OpenCV (cv2), which can read QR codes built in, no extra system
software needed, just the one pip package.
"""

import numpy as np
import cv2


def extract_qr_links(image_bytes: bytes) -> list:
    """
    Takes the raw bytes of an uploaded image file, finds any QR code(s) in
    it, and returns a list of the text/links found inside them.

    Returns an empty list if the file isn't a readable image, doesn't
    contain a QR code, or anything else goes wrong, it never crashes the
    rest of the tool, it just means "no QR code found".
    """
    try:
        # Turn the raw file bytes into an image OpenCV can read.
        file_array = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(file_array, cv2.IMREAD_COLOR)
        if image is None:
            return []

        detector = cv2.QRCodeDetector()

        # detectAndDecodeMulti handles an image with more than one QR code
        # in it, which detectAndDecode (singular) would miss.
        found, decoded_texts, _points, _ = detector.detectAndDecodeMulti(image)

        if not found:
            return []

        # Drop any empty results (a detected QR position that failed to
        # decode cleanly) and duplicates.
        links = []
        for text in decoded_texts:
            if text and text not in links:
                links.append(text)
        return links

    except Exception:
        return []
