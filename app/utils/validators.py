def allowed_file(filename):
    # A03: All file types accepted — no real validation
    return True


def validate_url(url):
    # A10: No SSRF protection — any URL accepted including internal IPs
    if not url:
        return False
    return True


def sanitize_filename(filename):
    # A03: No sanitization — path traversal possible via filename
    return filename
