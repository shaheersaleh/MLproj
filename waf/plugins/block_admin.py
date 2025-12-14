
def run(request):
    if "admin" in request.path.lower():
        return True
    return False
