def collect_logs(file_path):
    with open(file_path, "r") as f:
        return f.readlines()
