from logger import get_logger
from datetime import datetime

from typing import List

from models import Scan, DbCodeObject, DbCodeObjectProp, DbCodeObjectField
from appsec_discovery.models import CodeObject
from appsec_discovery.parsers import ParserFactory, Parser

from services.gl_service import (
    clone_gitlab_project_code,
    get_gitlab_project_lang
)
from services.db_service import (
    insert_scan, 
    get_scan,
    upsert_code_obj,
    get_score_rules,
    get_objects_to_score,
)

from services.score_service import llm_score_objects
from services.alert_service import render_and_send_alert

from config import PARSERS

logger = get_logger(__name__)

def scan_branch(session, branch):

    try:

        project_id = branch.project_id
        project_path = branch.project_path
        branch_name = branch.branch_name
        branch_id = branch.id
        branch_commit = branch.commit

        project_lang = get_gitlab_project_lang(project_path, branch_name) 

        if clone_gitlab_project_code(project_path, branch_name, project_id, branch_id, branch_commit) :
        
            if project_lang == 'go': 

                score_rules = get_score_rules(session)
                
                scan = Scan(
                    scanner='discovery',
                    rules_version='1.0.0',
                    parsers=PARSERS,
                    project_id=project_id,
                    branch_id=branch_id,
                    branch_commit=branch_commit,
                    project_path=project_path,
                    branch_name=branch_name,
                    scanned_at=datetime.now()
                )

                if not get_scan(session, scan):
                    
                    parsed_objects_list, result = run_discovery_scan(project_path, project_id, branch_id, branch_name, branch_commit, score_rules)

                    for parsed_object in parsed_objects_list:
                        upsert_code_obj(session, parsed_object)

                    if result == 'scanned':
                        insert_scan(session, scan)
                else:
                    logger.info(f"Already exist scan {scan.scanner} (ver {scan.rules_version} parsers {str(scan.parsers)} for {project_path}, branch {branch_name}")

        logger.info(f"Project {project_path}, branch {branch_name} processed")
        
        return True

    except Exception as e:

        logger.error(f"Failed to scan project {project_path}, branch {branch_name}: {e}")
    
        return False


def scan_mr(session, project_id, project_path, mr_id,
            source_branch_name, source_branch_id, source_branch_commit,
            target_branch_name, target_branch_id, target_branch_commit):

    try:

        project_lang = get_gitlab_project_lang(project_path, target_branch_name)
            
        if clone_gitlab_project_code(project_path, target_branch_name, project_id, target_branch_id, target_branch_commit) :

            if project_lang == 'go':

                new_objects = {}

                score_rules = get_score_rules(session)

                clone_gitlab_project_code(project_path, source_branch_name, project_id, source_branch_id, source_branch_commit)

                scan = Scan(
                    scanner='discovery',
                    rules_version='1.0.0',
                    parsers=PARSERS,
                    project_id=project_id,
                    branch_id=source_branch_id,
                    branch_commit=source_branch_commit,
                    project_path=project_path,
                    branch_name=source_branch_name,
                    scanned_at=datetime.now()
                )
                    
                source_objects_list, _ = run_discovery_scan(project_path, project_id, source_branch_id, source_branch_name, source_branch_commit, score_rules)
                target_objects_list, _ = run_discovery_scan(project_path, project_id, target_branch_id, target_branch_name, target_branch_commit, score_rules)
    
                diff_objects = get_diff(scan.scanner, source_objects_list, target_objects_list) 

                for parsed_object in diff_objects:
                    _, result = upsert_code_obj(session, parsed_object)
                    if result == 'inserted' and parsed_object.severity :
                        new_objects[parsed_object.hash] = parsed_object
                
                scan.scanned_at 
                insert_scan(session, scan)

                if new_objects:

                    logger.info(f"Found {len(new_objects) } objects to alert")

                    render_and_send_alert(project_path, source_branch_name, mr_id, new_objects)

        return True

    except Exception as e:
        logger.error(f"Failed to scan project {project_id}, mr {mr_id}: {e}")
        return False

def llm_score_branch(session, branch):

    try:

        project_id = branch.project_id
        project_path = branch.project_path
        branch_name = branch.branch_name
        branch_id = branch.id
        branch_commit = branch.commit
        
        scan = Scan(
            scanner='llm-scorer',
            rules_version='1.0.0',
            parsers=[],
            project_id=project_id,
            branch_id=branch_id,
            branch_commit=branch_commit,
            project_path=project_path,
            branch_name=branch_name,
            scanned_at=datetime.now()
        )

        if not get_scan(session, scan):

            objects_to_score = get_objects_to_score(session, project_id, branch_id)

            scored_objects = llm_score_objects(objects_to_score)

            for scored_object in scored_objects:
                scored_object.ai_processed_at = datetime.now()
                upsert_code_obj(session, scored_object)

                insert_scan(session, scan)
        else:
            logger.info(f"Already exist scan {scan.scanner} (ver {scan.rules_version} parsers {str(scan.parsers)} for {project_path}, branch {branch_name}")

        logger.info(f"Project {project_path}, branch {branch_name} processed")
        
        return True

    except Exception as e:

        logger.error(f"Failed to score project {project_path}, branch {branch_name}: {e}")
    
        return False
    

def get_diff(scanner, source_objects, target_objects):

    diff_objects = []

    to_keys = {}    

    for to in target_objects:
        to_keys[to.hash] = 1

    for so in source_objects:

        if so.hash not in to_keys:
            diff_objects.append(so)
                
    logger.info(f"Found {len(diff_objects)} new objects in {scanner} diff")

    return diff_objects

#######################################
##  Discovery                       ###
#######################################

def run_discovery_scan(project_path, project_id, branch_id, branch_name, branch_commit, score_rules):

    # Determine the local path for the clone
    project_local_path = f"{str(project_id)}/{str(branch_id)}/{branch_commit}"

    code_folder = f"code/{project_local_path}"

    parsed_objects: List[CodeObject] = []

    all_parsers = ParserFactory.get_parser_types()
    parsers_to_scan = []

    if 'all' in PARSERS:
        parsers_to_scan = all_parsers
    else:
        for parser in PARSERS:
            if parser in all_parsers:
                parsers_to_scan.append(parser)

    for parser in parsers_to_scan:

        ParserCls = ParserFactory.get_parser(parser)
        parser_instance: Parser = ParserCls(parser=parser, source_folder=code_folder)

        res = parser_instance.run_scan()

        if res:
            parsed_objects += res

        logger.info(f"Parser {parser} found {len(res)} objects in {project_path} ")

    db_objs = []

    for obj in parsed_objects:

        db_props = []
        for local_prop in obj.properties.values():
            db_prop = DbCodeObjectProp(
                prop_name=local_prop.prop_name, 
                prop_value=local_prop.prop_value,
                file=local_prop.file,
                line=local_prop.line,
                severity=local_prop.severity,
                tags=local_prop.tags,
            )
            db_props.append(db_prop)

        db_fields = []
        for local_field in obj.fields.values():
            db_field = DbCodeObjectField(
                field_name=local_field.field_name, 
                field_type=local_field.field_type,
                file=local_field.file,
                line=local_field.line,
                severity=local_field.severity,
                tags=local_field.tags,
            )
            db_fields.append(db_field)

        db_obj = DbCodeObject(
            project_id=project_id, 
            branch_id=branch_id,
            hash=obj.hash,
            object_name=obj.object_name,
            object_type=obj.object_type,
            parser=obj.parser,
            properties=db_props,
            fields=db_fields,
            file=obj.file,
            line=obj.line,
            severity=obj.severity,
            tags=obj.tags,
        )

        db_objs.append(db_obj)

    # filtered_objects = filter_objects(parsed_objects, score_rules)
    # scored_objects = self.score_objects(filtered_objects)

    return db_objs, 'scanned'

