# thorn test fixture: CFG002, CFG003

# CFG002: debug mode enabled
DEBUG = True
FLASK_DEBUG = 1
debug_mode = true

# CFG003: hardcoded localhost
DATABASE_HOST = "127.0.0.1"
REDIS_URL = "redis://localhost:6379"

# should NOT match
LOG_LEVEL = "INFO"
MAX_CONNECTIONS = 100
