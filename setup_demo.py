"""Generate fresh local PKI, two isolated user profiles and demo data."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess


def openssl_path():
    candidates = [shutil.which('openssl'), r'C:\Program Files\Git\usr\bin\openssl.exe']
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise RuntimeError('需要 OpenSSL 3.x，可安装 Git for Windows 后重试。')


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')


def initialize(root, port=8766):
    root = Path(root).resolve()
    if root.exists():
        raise RuntimeError('运行目录已存在。请使用新的空目录，避免覆盖证书或文件。')
    executable = openssl_path()
    root.mkdir(parents=True, mode=0o700)
    if os.name == 'nt':
        subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                        str(Path(__file__).with_name('secure_runtime.ps1')), '-Path', str(root)],
                       check=True, capture_output=True)
    else:
        root.chmod(0o700)
    authority = root / 'authority'
    authority.mkdir()
    server = root / 'server'
    server.mkdir()
    config = root / 'openssl.cnf'
    config.write_text('[req]\ndistinguished_name=dn\n[dn]\n', encoding='ascii')

    def run(*args):
        result = subprocess.run([executable, *map(str, args)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('OpenSSL failed: ' + result.stderr[-1500:])

    ca_key, ca_cert = authority / 'ca.key', authority / 'ca.pem'
    run('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '365',
        '-config', config, '-subj', '/CN=Local SFT Lab CA', '-keyout', ca_key, '-out', ca_cert,
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
        '-addext', 'subjectKeyIdentifier=hash')

    def certificate(directory, name, usage):
        key, csr, cert = directory / 'identity.key', directory / 'request.csr', directory / 'identity.pem'
        run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-config', config,
            '-subj', '/CN=' + name, '-keyout', key, '-out', csr)
        extensions = directory / 'extensions.cnf'
        content = ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                   'extendedKeyUsage=' + usage + '\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        if usage == 'serverAuth':
            content += 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n'
        extensions.write_text(content, encoding='ascii')
        run('x509', '-req', '-in', csr, '-CA', ca_cert, '-CAkey', ca_key, '-set_serial',
            '0x' + os.urandom(16).hex(), '-days', '90', '-sha256', '-extfile', extensions, '-out', cert)
        shutil.copyfile(ca_cert, directory / 'ca.pem')
        csr.unlink()
        extensions.unlink()
        key.chmod(0o600)
        der = ssl.PEM_cert_to_DER_cert(cert.read_text('ascii'))
        return hashlib.sha256(der).hexdigest()

    certificate(server, 'localhost', 'serverAuth')
    users = {}
    for username, rate in [('alice', 1024 * 1024), ('bob', 256 * 1024)]:
        directory = root / 'clients' / username
        directory.mkdir(parents=True)
        fingerprint = certificate(directory, username, 'clientAuth')
        write_json(directory / 'profile.json', {'host': 'localhost', 'port': port,
                    'ca': 'ca.pem', 'cert': 'identity.pem', 'key': 'identity.key', 'username': username})
        users[username] = {'fingerprint': fingerprint, 'bytes_per_second': rate}
        (directory / 'downloads').mkdir()
    write_json(server / 'config.json', {'host': '127.0.0.1', 'port': port, 'users': users,
               'storage': 'storage', 'max_connections': 16, 'per_ip': 12, 'per_user': 4})
    (server / 'storage').mkdir()
    samples = root / 'samples'
    samples.mkdir()
    (samples / '说明.txt').write_text('实验 1B 安全文件传输\nTLS 双向认证与 SHA-256 完整性校验\n', encoding='utf-8')
    (samples / 'sample-2MiB.bin').write_bytes(bytes(range(256)) * 8192)
    (samples / 'empty.bin').touch()
    ca_key.chmod(0o600)
    config.unlink()
    return root


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', default='runtime')
    parser.add_argument('--port', type=int, default=8766)
    args = parser.parse_args()
    initialize(args.runtime, args.port)
    print('初始化完成。证书及样例保存在 ' + str(Path(args.runtime).resolve()))
