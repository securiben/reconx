with open('engine.py', 'rb') as f:
    raw = f.read()

# Fix the broken etcd line
bad  = b'return f"curl -sk http://{ip}:{port}/v3/kv/range -X POST -d \'{{\\\"key\\\":\\\"Lw==\\\"\\\"}}\'  # base64(\\'/\\') list all keys"'
good = b'return f"curl -sk http://{ip}:{port}/v3/kv/range -X POST -d \'{{\\\"key\\\":\\\"Lw==\\\"}}\'  # base64(\\'/\\') lists all keys"'

# Simpler: scan by line
lines = raw.split(b'\n')
out = []
for line in lines:
    if b'v3/kv/range' in line:
        # Replace the whole return with a clean one (no tricky JSON)
        indent = b'            '
        out.append(indent + b'return f"curl -sk http://{ip}:{port}/v3/kv/range  # list etcd keys"')
    else:
        out.append(line)

fixed = b'\n'.join(out)
with open('engine.py', 'wb') as f:
    f.write(fixed)
print('fixed')
