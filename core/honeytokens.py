import secrets
import string
from core.database import add_honeytoken, trigger_honeytoken

def _rand(prefix: str, length: int = 20) -> str:
    chars = string.ascii_letters + string.digits
    return prefix + "".join(secrets.choice(chars) for _ in range(length))

TOKENS: dict[str, str] = {}

def generate_tokens() -> dict[str, str]:
    tokens = {
        "aws_access_key":    _rand("AKIA", 16),
        "aws_secret_key":    _rand("", 40),
        "api_key":           _rand("sk-", 32),
        "db_password":       _rand("dbpass_", 16),
        "admin_password":    _rand("admin_", 12),
        "jwt_secret":        _rand("jwt_", 32),
        "ssh_private_key_hint": "id_rsa_backup_2024",
    }
    for label, token in tokens.items():
        add_honeytoken(token, label)
        TOKENS[token] = label
    return tokens

def check_token(value: str, ip: str) -> str | None:
    for token, label in TOKENS.items():
        if token in value:
            trigger_honeytoken(token, ip)
            return label
    return None

def get_fake_env_file(tokens: dict) -> str:
    return f"""# Environment Configuration
APP_NAME=production-server
APP_ENV=production
APP_KEY={tokens.get('api_key','')}

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=root
DB_PASSWORD={tokens.get('db_password','')}

AWS_ACCESS_KEY_ID={tokens.get('aws_access_key','')}
AWS_SECRET_ACCESS_KEY={tokens.get('aws_secret_key','')}
AWS_DEFAULT_REGION=eu-central-1
AWS_BUCKET=prod-backup-bucket

JWT_SECRET={tokens.get('jwt_secret','')}
ADMIN_PASSWORD={tokens.get('admin_password','')}
"""

def get_fake_passwd() -> str:
    return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:admin,,,:/home/admin:/bin/bash
deploy:x:1001:1001::/home/deploy:/bin/bash
mysql:x:118:126:MySQL Server,,,:/nonexistent:/bin/false
"""

def get_fake_shadow() -> str:
    return """root:$6$rounds=500000$randomsalt$hashedpassword1234567890abcdef:19000:0:99999:7:::
admin:$6$rounds=500000$anothersalt$anotherhash1234567890abcdefgh:19000:0:99999:7:::
deploy:$6$rounds=500000$deploysalt$deployhash1234567890abcdefghi:19000:0:99999:7:::
"""
