def run(request):
    ua = request.headers.get("User-Agent", "").lower()
    if "sqlmap" in ua:
        return True
    return False
