def dump_logs(container, file):
    logs = container.logs().decode('utf-8')
    with open(file, 'w') as f:
        f.write(logs)
