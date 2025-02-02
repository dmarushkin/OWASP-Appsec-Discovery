import os
import subprocess
from logger import get_logger

logger = get_logger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL") 
GITLAB_PRIVATE_TOKEN = os.getenv("GITLAB_PRIVATE_TOKEN") 
GITLAB_URL = os.getenv("GITLAB_URL")

GITLAB_PROJECTS_PREFIX = os.getenv("GITLAB_PROJECTS_PREFIX").split(",")

GITLAB_SCAN_TYPES = os.getenv("GITLAB_SCAN_TYPES").split(",")

PARSERS = os.getenv("PARSERS").split(",")

MAX_WORKERS = int(os.getenv("MAX_WORKERS"))
CACHE_SIZE = int(os.getenv("CACHE_SIZE_GB")) * 1024 * 1024 * 1024

LLM_API_URL = os.getenv("LLM_API_URL")
LLM_API_KEY = os.getenv("LLM_API_KEY")
LLM_API_MODEL = os.getenv("LLM_API_MODEL")

LLM_LOCAL_MODEL = os.getenv("LLM_LOCAL_MODEL")
LLM_LOCAL_FILE = os.getenv("LLM_LOCAL_FILE")
LLM_PROMPT = os.getenv("LLM_PROMPT")
LLM_PROMPT_VER = os.getenv("LLM_PROMPT_VER")

MR_ALERTS = os.getenv("MR_ALERTS")

TG_ALERT_TOKEN = os.getenv("TG_ALERT_TOKEN")
TG_CHAT_ID = os.getenv("TG_CHAT_ID")

def set_auth():

    try:

        gitconf_obj = open("/root/.gitconfig", "w")
        gitconf_obj.write("[credential]\n        helper = store\n")
        gitconf_obj.close()

        gitcreds_obj = open("/root/.git-credentials", "w")
        gitcreds_obj.write(GITLAB_URL.replace('://', "://git:" + GITLAB_PRIVATE_TOKEN + "@") )
        gitcreds_obj.close()

        subprocess.run(["chmod", "600", "/root/.git-credentials"], check=True)

    except Exception as ex:
        logger.error(f"Error writing configs: {ex}")