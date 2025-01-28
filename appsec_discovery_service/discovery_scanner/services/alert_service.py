import requests
import json
from logger import get_logger

from config import MR_ALERTS, TG_ALERT_TOKEN, TG_CHAT_ID, GITLAB_URL
from services.gl_service import add_gitlab_comment_to_mr

logger = get_logger(__name__)

def render_and_send_alert(project, branch, mr_id, crit_objects):

    title = f"New sensitive objects in project {project}"

    message = f'Branch: {branch}\nMR: {GITLAB_URL}/{project}/-/merge_requests/{mr_id}/diffs\n'

    for code_obj in crit_objects.values():
        message += f'  {code_obj.object_name} scored as {code_obj.severity} with tags {str(code_obj.tags)}\n'

    if MR_ALERTS :
        
        send_mr_alert(project, mr_id, title, message)

        logger.info(f"Alert for {project}, mr {mr_id} sent to mm")

    if TG_ALERT_TOKEN and TG_CHAT_ID:
        send_tg_alert(title, message)
        logger.info(f"Alert for {project}, mr {mr_id} sent to tg")

        return True
    
    logger.error(f"Alert for {project}, mr {mr_id} does not sent")


def send_tg_alert(alert_title, alert_text):

    text = f"{alert_title}\n{alert_text}"

    url = f"https://api.telegram.org/bot{TG_ALERT_TOKEN}/sendMessage"

    payload = {
        'chat_id': TG_CHAT_ID,
        'text': text
    }

    response = requests.post(url, json=payload)
    
    # Checking the response
    if response.status_code == 200:
        logger.info("Alert created successfully")
    else:
        logger.info(f"Failed to create alert: {response.status_code}")
        logger.info(response.text)


def send_mr_alert(project_id, mr_id, alert_title, alert_text):

    comment = f"{alert_title}\n{alert_text}"
    
    res = add_gitlab_comment_to_mr(project_id, mr_id, comment)
   
    # Checking the response
    if res :
        logger.info("Mr Alert created successfully")

