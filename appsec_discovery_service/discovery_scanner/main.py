import multiprocessing as mp
import time
import random

from services.gl_service import (
    get_gitlab_projects_list, 
    get_gitlab_branches_by_project, 
    get_gitlab_mrs_by_project,
    clone_gitlab_project_code,
    get_gitlab_project_lang,
    get_gitlab_code_cache_size,
    get_cloned_projects,
    remove_cloned_project
)
from services.scan_service import (
    scan_branch,
    scan_mr,
    llm_score_branch
)
from services.db_service import (
    create_db_and_tables,
    get_db_session,
    update_project,
    upsert_project, 
    upsert_branch, 
    update_branch,
    upsert_mr,
    update_mr,
    get_branch,
    get_mr
)
from datetime import datetime, timedelta
from logger import get_logger
from config import GITLAB_PROJECTS_PREFIX, GITLAB_SCAN_TYPES, MAX_WORKERS, CACHE_SIZE, set_auth

logger = get_logger(__name__)


def update_projects(update_branches_mrs_queue):

    session = get_db_session()

    first_time_run = True

    while True:

        try:

            for prefix in GITLAB_PROJECTS_PREFIX: 

                projects = get_gitlab_projects_list(prefix)

                projects_in_prefix = 0

                for project_gl in projects:

                    project_db, _ = upsert_project(session, project_gl)

                    if first_time_run or project_db.processed_at is None or project_db.processed_at < project_db.updated_at :
                        update_branches_mrs_queue.put((project_gl,project_db))

                        projects_in_prefix += 1

                        project_db.processed_at = datetime.now()
                        update_project(session, project_db)

                logger.info(f"For prefix {prefix} loaded {projects_in_prefix} projects")

            first_time_run = False

        except Exception as e:
            logger.error(f"Got error in update projects: {e}")

        time.sleep(300)


def update_branches_mrs(update_branches_mrs_queue, 
                        mrs_new_wait, mrs_updated_wait, mrs_to_scan, mrs_in_scan, 
                        mains_new_wait, mains_updated_wait, mains_to_scan, mains_in_scan):

    session = get_db_session()

    while True:

        try:

            queue_size = update_branches_mrs_queue.qsize()

            logger.info(f"Update branches queue has {queue_size} waiting projects")

            project_gl, project_db = update_branches_mrs_queue.get()

            if 'mains' in GITLAB_SCAN_TYPES:

                branches = get_gitlab_branches_by_project(project_gl.id)

                for branch_gl in branches:
                    is_main = (branch_gl.name == project_gl.default_branch)
                    branch_db, _ = upsert_branch(session, branch_gl, project_db.id, project_db.full_path, is_main)

                    if is_main and ( branch_db.processed_at is None or branch_db.processed_at < branch_db.updated_at ):
                    
                        if branch_db.processed_at is None and branch_db.project_id not in mains_to_scan and branch_db.project_id not in mains_in_scan:
                            mains_new_wait[branch_db.project_id] = branch_db
                        else:
                            mains_updated_wait[branch_db.project_id] = branch_db

            if 'mrs' in GITLAB_SCAN_TYPES:              
            
                mrs_gl = get_gitlab_mrs_by_project(project_gl.id)

                for mr_gl in mrs_gl:

                    source_branch = get_branch(session, project_db.id, mr_gl.source_branch)
                    target_branch = get_branch(session, project_db.id, mr_gl.target_branch)

                    if source_branch and target_branch:
                        mr_db, _ = upsert_mr(session, mr_gl, project_db.id, project_db.full_path, source_branch, target_branch)

                        if mr_db.state == 'opened' and mr_db.updated_at > datetime.now() - timedelta(days=1) and ( mr_db.processed_at is None or mr_db.processed_at < mr_db.updated_at ):

                            mr_key = f"{mr_db.project_id}.{mr_db.mr_id}"

                            if mr_db.processed_at is None and mr_key not in mrs_to_scan and mr_key not in mrs_in_scan:
                                mrs_new_wait[mr_key] = mr_db
                            else:
                                mrs_updated_wait[mr_key] = mr_db
        except Exception as e:
            logger.error(f"Got error in update branches: {e}")

        if not queue_size:
            time.sleep(60)

def pull_code(mrs_new_wait, mrs_updated_wait, mrs_to_scan, mrs_in_scan, mains_new_wait, mains_updated_wait, mains_to_scan, mains_in_scan, projects_on_update):

    session = get_db_session()

    while True:

        try:

            # Update target branches commits
            
            if 'mrs' in GITLAB_SCAN_TYPES:

                for mr_key in mrs_updated_wait.keys():
                    
                    queue_mr = mrs_updated_wait[mr_key]
                    mr_in_work = get_mr(session, queue_mr.id)
                    
                    target_branch = get_branch(session, mr_in_work.project_id, mr_in_work.target_branch)

                    if mr_in_work.target_branch_commit != target_branch.commit:
                        mr_in_work.target_branch_commit = target_branch.commit
                        update_mr(session, mr_in_work)

                for mr_key in mrs_new_wait.keys():
                    
                    queue_mr = mrs_new_wait[mr_key]
                    mr_in_work = get_mr(session, queue_mr.id)
                    
                    target_branch = get_branch(session, mr_in_work.project_id, mr_in_work.target_branch)

                    if mr_in_work.target_branch_commit != target_branch.commit:
                        mr_in_work.target_branch_commit = target_branch.commit
                        update_mr(session, mr_in_work)

            # Clone mains

            if 'mains' in GITLAB_SCAN_TYPES:  

                logger.info(f"Pull code queue has {len(mains_new_wait)} new mains waiting")
                logger.info(f"Pull code queue has {len(mains_updated_wait)} updated mains waiting")

                # New mains

                for proj_key in reversed(mains_new_wait.keys()):

                    if CACHE_SIZE < get_gitlab_code_cache_size() or len(mains_to_scan) > 0 :
                        break

                    queue_branch = mains_new_wait[proj_key]
                    main_branch = get_branch(session, queue_branch.project_id, queue_branch.branch_name)

                    lang = get_gitlab_project_lang(main_branch.project_path, main_branch.branch_name)

                    if lang in ['go', 'js', 'mobile']:

                        clone_branch_res = clone_gitlab_project_code(main_branch.project_path, main_branch.branch_name, main_branch.project_id, main_branch.id, main_branch.commit)

                        if clone_branch_res:
                            
                            mains_to_scan[proj_key] = main_branch
                        
                        else:

                            main_branch.processed_at = datetime.now()
                            update_branch(session, main_branch)

                    mains_new_wait.pop(proj_key, None)

                # Updated mains

                for proj_key in reversed(mains_updated_wait.keys()):

                    if CACHE_SIZE < get_gitlab_code_cache_size() or len(mains_to_scan) > 0 :
                        break

                    queue_branch = mains_updated_wait[proj_key]
                    main_branch = get_branch(session, queue_branch.project_id, queue_branch.branch_name)

                    lang = get_gitlab_project_lang(main_branch.project_path, main_branch.branch_name)

                    if lang in ['go', 'js', 'mobile']:

                        clone_branch_res = clone_gitlab_project_code(main_branch.project_path, main_branch.branch_name, main_branch.project_id, main_branch.id, main_branch.commit)

                        if clone_branch_res:
                            
                            mains_to_scan[proj_key] = main_branch
                        
                        else:

                            main_branch.processed_at = datetime.now()
                            update_branch(session, main_branch)

                    mains_updated_wait.pop(proj_key, None)

            # Clone MRs

            if 'mrs' in GITLAB_SCAN_TYPES:

                logger.info(f"Pull code queue has {len(mrs_new_wait)} new mrs waiting")
                logger.info(f"Pull code queue has {len(mrs_updated_wait)} updated mrs waiting")

                # New mrs

                for mr_key in reversed(mrs_new_wait.keys()):

                    if CACHE_SIZE < get_gitlab_code_cache_size() or len(mrs_to_scan) > 0 :
                        break

                    queue_mr = mrs_new_wait[mr_key]
                    mr_in_work = get_mr(session, queue_mr.id)

                    lang = get_gitlab_project_lang(mr_in_work.project_path, mr_in_work.source_branch)

                    if lang in ['go', 'js']:

                        clone_source_branch_res = clone_gitlab_project_code(mr_in_work.project_path, mr_in_work.source_branch, mr_in_work.project_id, mr_in_work.source_branch_id, mr_in_work.source_branch_commit)
                        clone_target_branch_res = clone_gitlab_project_code(mr_in_work.project_path, mr_in_work.target_branch, mr_in_work.project_id, mr_in_work.target_branch_id, mr_in_work.target_branch_commit)

                        if clone_source_branch_res and clone_target_branch_res:

                            mrs_to_scan[mr_key] = mr_in_work

                        else:

                            mr_in_work.processed_at = datetime.now()
                            update_mr(session, mr_in_work)

                    mrs_new_wait.pop(mr_key, None)
                    
                # Updated mrs

                for mr_key in reversed(mrs_updated_wait.keys()):

                    if CACHE_SIZE < get_gitlab_code_cache_size() or len(mrs_to_scan) > 0 :
                        break

                    queue_mr = mrs_updated_wait[mr_key]
                    mr_in_work = get_mr(session, queue_mr.id)

                    lang = get_gitlab_project_lang(mr_in_work.project_path, mr_in_work.source_branch)

                    if lang in ['go', 'js']:

                        clone_source_branch_res = clone_gitlab_project_code(mr_in_work.project_path, mr_in_work.source_branch, mr_in_work.project_id, mr_in_work.source_branch_id, mr_in_work.source_branch_commit)
                        clone_target_branch_res = clone_gitlab_project_code(mr_in_work.project_path, mr_in_work.target_branch, mr_in_work.project_id, mr_in_work.target_branch_id, mr_in_work.target_branch_commit)

                        if clone_source_branch_res and clone_target_branch_res:

                            mrs_to_scan[mr_key] = mr_in_work

                        else:

                            mr_in_work.processed_at = datetime.now()
                            update_mr(session, mr_in_work)

                    mrs_updated_wait.pop(mr_key, None)

        except Exception as e:
            logger.error(f"Got error in clone code: {e}")

        time.sleep(10)


def scan_all(mains_to_scan, mains_in_scan, mains_to_score, mrs_to_scan, mrs_in_scan, projects_on_update):

    session = get_db_session()

    while True:

        time.sleep(random.randint(1, 20))

        try:

            if 'mains' in GITLAB_SCAN_TYPES and len(mains_to_scan) > 0 :

                logger.info(f"Mains scan queue has {len(mains_to_scan)} waiting for scan")
                logger.info(f"Mains scan queue has {len(mains_in_scan)} in scan")

                proj_keys = reversed([ proj_key for proj_key in mains_to_scan.keys() ])
            
                for proj_key in proj_keys:
                    
                    if proj_key not in projects_on_update:

                        queue_branch = mains_to_scan[proj_key]
                        main_branch = get_branch(session, queue_branch.project_id, queue_branch.branch_name)

                        mains_to_scan.pop(proj_key, None)
                        mains_in_scan[proj_key] = main_branch

                        scan_branch(session, main_branch)

                        main_branch.processed_at = datetime.now()
                        update_branch(session, main_branch)

                        mains_to_score[proj_key] = main_branch

                        mains_in_scan.pop(proj_key, None)

                        break

                continue

        except Exception as e:
            logger.error(f"Got error in scan mains: {e}")

        try:

            if 'mrs' in GITLAB_SCAN_TYPES and len(mrs_to_scan) > 0:

                logger.info(f"Mrs scan queue has {len(mrs_to_scan)} waiting for scan")
                logger.info(f"Mrs scan queue has {len(mrs_in_scan)} in scan")

                mr_keys = reversed([ mr_key for mr_key in mrs_to_scan.keys() ])

                for mr_key in mr_keys:
                    
                    if int(mr_key.split(".")[0]) not in projects_on_update:

                        mr_key = mrs_to_scan.keys()[-1]

                        queue_mr = mrs_to_scan[mr_key]
                        mr = get_mr(session, queue_mr.id)

                        mrs_to_scan.pop(mr_key, None)
                        mrs_in_scan[mr_key] = mr

                        source_branch = get_branch(session, mr.project_id, mr.source_branch)
                        target_branch = get_branch(session, mr.project_id, mr.target_branch)

                        scan_mr(session, mr.mr_id,
                            source_branch,
                            target_branch)
                        
                        mr.processed_at = datetime.now()
                        update_mr(session, mr)

                        mrs_in_scan.pop(mr_key, None)

                        break

                continue

        except Exception as e:
            logger.error(f"Got error in scan mrs: {e}")

        time.sleep(10)


def llm_score(mains_to_score):

    session = get_db_session()

    while True:

        try:

            if 'mains' in GITLAB_SCAN_TYPES and len(mains_to_score) > 0 :

                logger.info(f"Mains scan queue has {len(mains_to_score)} waiting for score")

                proj_keys = reversed([ proj_key for proj_key in mains_to_score.keys() ])
            
                for proj_key in proj_keys:
                    
                    queue_branch = mains_to_score[proj_key]
                    main_branch = get_branch(session, queue_branch.project_id, queue_branch.branch_name)

                    llm_score_branch(session, main_branch)

                    mains_to_score.pop(proj_key, None)

                    break

                continue

        except Exception as e:
            logger.error(f"Got error in llm score mains: {e}")

        time.sleep(10)    


def clean_cache(mrs_to_scan, mrs_in_scan, mains_to_scan, mains_in_scan):

    while True:

        try:

            project_on_disk = get_cloned_projects()
            projects_ids_in_work = {}

            all_mains_keys = mains_to_scan.keys() + mains_in_scan.keys()
            all_mrs_keys = mrs_to_scan.keys() + mrs_in_scan.keys()

            for project_id in all_mains_keys:
                projects_ids_in_work[str(project_id)] = 1
            
            for mr_key in all_mrs_keys:
                project_id = mr_key.split(".")[0]
                projects_ids_in_work[str(project_id)] = 1      

            logger.info(f"Cleaning local cached code for {len(project_on_disk)} projects, {len(projects_ids_in_work)} projects in work")

            for project_id in project_on_disk:

                if str(project_id) not in projects_ids_in_work :
                    
                    remove_cloned_project(project_id)

        except Exception as e:
            logger.error(f"Got error in scan mrs: {e}")
        
        time.sleep(60)


def main():

    create_db_and_tables()

    set_auth()

    manager = mp.Manager()

    mrs_new_wait = manager.dict()
    mrs_updated_wait = manager.dict()
    mrs_to_scan = manager.dict()
    mrs_in_scan = manager.dict()
    mains_new_wait = manager.dict()
    mains_updated_wait = manager.dict()
    mains_to_scan = manager.dict()
    mains_in_scan = manager.dict()
    mains_to_score = manager.dict()
    projects_on_update = manager.dict()

    update_branches_mrs_queue = mp.Queue()
    
    # load projects info
    update_projects_worker = mp.Process(target=update_projects, args=(update_branches_mrs_queue,))
    update_projects_worker.start()        

    # load branches and mrs 
    update_branches_mrs_worker = mp.Process(target=update_branches_mrs, args=(update_branches_mrs_queue, mrs_new_wait, mrs_updated_wait, mrs_to_scan, mrs_in_scan, mains_new_wait, mains_updated_wait, mains_to_scan, mains_in_scan))
    update_branches_mrs_worker.start()

    # pull code for scans
    pull_code_worker = mp.Process(target=pull_code, args=(mrs_new_wait, mrs_updated_wait, mrs_to_scan, mrs_in_scan, mains_new_wait, mains_updated_wait, mains_to_scan, mains_in_scan, projects_on_update))
    pull_code_worker.start()
    
    # clear cache for allready scanned projects
    clean_cache_worker = mp.Process(target=clean_cache, args=(mrs_to_scan, mrs_in_scan, mains_to_scan, mains_in_scan))
    clean_cache_worker.start()

    # scan workers
    for i in range(MAX_WORKERS):

        scan_all_worker = mp.Process(target=scan_all, args=(mains_to_scan, mains_in_scan, mains_to_score, mrs_to_scan, mrs_in_scan, projects_on_update))
        scan_all_worker.start()

    # clear cache for allready scanned projects
    llm_score_worker = mp.Process(target=llm_score, args=(mains_to_score,))
    llm_score_worker.start()

    # wait for subprocesses and handle piw dict
    clean_cache_worker.join()

if __name__ == "__main__":

    logger.info("Starting application...")

    main()