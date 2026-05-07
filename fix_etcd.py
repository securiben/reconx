with open('engine.py', encoding='utf-8') as f:
    content = f.read()

# Find the bad etcd line and replace it
bad = '''            return f"curl -sk http://{ip}:{port}/v3/kv/range -X POST -d '{{\\\"key\\\":\\\"Lw==\\\"}}'"'''

# Just find and fix via line scan
lines = content.splitlines(keepends=True)
fixed = []
for line in lines:
    if 'svc == "etcd"' in line or 'etcd' not in line:
        fixed.append(line)
    elif 'v3/kv/range' in line:
        # Replace the whole line with a clean version
        indent = '            '
        fixed.append(indent + 'return f"curl -sk http://{ip}:{port}/v3/kv/range -X POST  # list all keys"\n')
    else:
        fixed.append(line)

with open('engine.py', 'w', encoding='utf-8') as f:
    f.write(''.join(fixed))
print('Done')
