from typing import Set
from sqlmodel import create_engine, SQLModel, Session, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import joinedload
from sqlalchemy.dialects.postgresql import insert
from models import Project, Branch, Scan, MR, DbObject, DbLLMScore, DbObjectField, DbScoreRule
from datetime import datetime, timezone, timedelta
from logger import get_logger
from config import DATABASE_URL
import time

logger = get_logger(__name__)

engine = create_engine(DATABASE_URL)

def create_db_and_tables():

    # wait db warming up
    time.sleep(15)
    SQLModel.metadata.create_all(engine)


def get_db_session():
    engine = create_engine(DATABASE_URL)
    session = Session(engine)
    return session

# Retry decorator
def retry_on_exception(retries: int = 5, delay: float = 2.0):
    def decorator(func):
        def wrapper(*args, **kwargs):
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except OperationalError as e:
                    if attempt < retries - 1:
                        logger.info(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay} seconds...")
                        time.sleep(delay)
                    else:
                        logger.info("All attempts failed.")
                        raise
        return wrapper
    return decorator

@retry_on_exception()
def upsert_project(session, project_gl):

    local_project = Project(
        project_name=project_gl.name,
        full_path=project_gl.path_with_namespace,
        description=project_gl.description,
        visibility=project_gl.visibility,
        default_branch=project_gl.default_branch,
        created_at=datetime.strptime(project_gl.created_at, "%Y-%m-%dT%H:%M:%S.%fZ"),
        updated_at=datetime.strptime(project_gl.last_activity_at, "%Y-%m-%dT%H:%M:%S.%fZ")
    )

    with session:
        statement = select(Project).where(Project.project_name == local_project.project_name)
        existing_project = session.exec(statement).first()

        if existing_project:
            if existing_project.updated_at < local_project.updated_at:
                logger.info(f"Updating existing project: {existing_project.full_path}, db: {existing_project.updated_at}, gl: {local_project.updated_at}")
                for key, value in local_project.model_dump(exclude_unset=True).items():
                    setattr(existing_project, key, value)
                result = 'updated'
            else:
                result = 'checked'
        else:
            logger.info(f"Inserting new project: {local_project.full_path}")
            existing_project = local_project
            session.add(existing_project)
            result = 'inserted'

        session.commit()
        session.refresh(existing_project)

        return existing_project, result

@retry_on_exception()
def update_project(session, project: Project):
    
    with session:
        statement = select(Project).where(Project.id == project.id)
        existing_project = session.exec(statement).first()

        # logger.info(f"Updating existing project: {existing_project.full_path}, p_id: {project.id}")
        
        for key, value in project.model_dump(exclude_unset=True).items():
            setattr(existing_project, key, value)
        result = 'updated'

        session.commit()
        session.refresh(existing_project)

        return existing_project, result

@retry_on_exception()
def get_project(session, project_id):

    with session:
        statement = select(Project).where(Project.id == project_id)
        existing_project = session.exec(statement).first()
        
        return existing_project

@retry_on_exception()
def get_projects(session):

    with session:
        projects = session.query(Project).all()
        logger.info(f"Load {len(projects)} from db")

        return projects

@retry_on_exception()
def upsert_branch(session, branch_gl, project_id, project_path, is_main):

    local_branch = Branch(
        branch_name=branch_gl.name,
        is_main=is_main,
        created_at=datetime.strptime(branch_gl.commit['committed_date'], "%Y-%m-%dT%H:%M:%S.%f%z").replace(tzinfo=timezone.utc).replace(tzinfo=None),
        commit=branch_gl.commit['id'],
        updated_at=datetime.strptime(branch_gl.commit['committed_date'], "%Y-%m-%dT%H:%M:%S.%f%z").replace(tzinfo=timezone.utc).replace(tzinfo=None),
        project_id=project_id,
        project_path=project_path
    )
    
    with session:
        statement = select(Branch).where(Branch.branch_name == local_branch.branch_name, Branch.project_id == local_branch.project_id)
        existing_branch = session.exec(statement).first()

        if existing_branch:
            if existing_branch.updated_at < local_branch.updated_at :
                logger.info(f"Updating existing branch: {existing_branch.branch_name}, p_id: {local_branch.project_id}")
                for key, value in local_branch.model_dump(exclude_unset=True).items():
                    setattr(existing_branch, key, value)
                result = 'updated'
            else:
                result = 'checked'
        else:
            logger.info(f"Inserting new branch: {local_branch.branch_name}")
            existing_branch = local_branch
            session.add(existing_branch)
            result = 'inserted'

        session.commit()
        session.refresh(existing_branch)

        return existing_branch, result

@retry_on_exception()
def update_branch(session, branch: Branch):
    
    with session:
        statement = select(Branch).where(Branch.id == branch.id)
        existing_branch = session.exec(statement).first()

        logger.info(f"Updating existing branch: {existing_branch.branch_name}, p_id: {branch.project_id}")
        for key, value in branch.model_dump(exclude_unset=True).items():
            setattr(existing_branch, key, value)
        result = 'updated'

        session.commit()
        session.refresh(existing_branch)

        return existing_branch, result

@retry_on_exception()
def get_branch(session, project_id, branch_name):

    with session:
        statement = select(Branch).where(Branch.branch_name == branch_name, Branch.project_id == project_id)
        existing_branch = session.exec(statement).first()
        
        return existing_branch
    
@retry_on_exception()
def get_mr(session, mr_id):

    with session:
        statement = select(MR).where(MR.id == mr_id)
        existing_mr = session.exec(statement).first()
        
        return existing_mr

@retry_on_exception()
def get_active_branches(session, project_id):

    with session:
        statement = select(Branch).where(
            Branch.project_id == project_id
        )

        branches = session.exec(statement).all()
        active_branches =  [ branch for branch in branches if ( branch.processed_at is None or branch.processed_at < branch.updated_at ) and branch.updated_at > datetime.now() - timedelta(days=1)]

        logger.info(f"Got {len(active_branches)} active branches by project {project_id}")

        return active_branches 

@retry_on_exception()
def upsert_mr(session, mr_gl, project_id, project_path, source_branch, target_branch):

    local_mr = MR(
        mr_id=mr_gl.iid,
        project_id=project_id,
        project_path=project_path,
        source_branch_id=source_branch.id,
        source_branch=source_branch.branch_name,
        source_branch_commit=source_branch.commit,
        target_branch_id=target_branch.id,
        target_branch=target_branch.branch_name,
        target_branch_commit=target_branch.commit,
        state=mr_gl.state,
        title=mr_gl.title,
        description=mr_gl.description,
        created_at=datetime.strptime(mr_gl.created_at, "%Y-%m-%dT%H:%M:%S.%fZ"),
        updated_at=datetime.strptime(mr_gl.updated_at, "%Y-%m-%dT%H:%M:%S.%fZ")
    )

    with session:
        statement = select(MR).where(
            MR.project_id == local_mr.project_id,
            MR.mr_id == local_mr.mr_id)
        
        existing_mr = session.exec(statement).first()

        if existing_mr:
            if existing_mr.source_branch_commit != local_mr.source_branch_commit :
                logger.info(f"Updating existing mr: {existing_mr.mr_id}, p_id: {local_mr.project_id}, project_path: {local_mr.project_path}")
                for key, value in local_mr.model_dump(exclude_unset=True).items():
                    setattr(existing_mr, key, value)
                result = 'updated'
            elif existing_mr.target_branch_commit != local_mr.target_branch_commit :
                logger.info(f"Updating existing mr target branch: {existing_mr.mr_id}, p_id: {local_mr.project_id}, project_path: {local_mr.project_path}")
                for key, value in local_mr.model_dump(exclude_unset=True).items():
                    setattr(existing_mr, key, value)
                result = 'checked'
            else:
                existing_mr.updated_at = local_mr.updated_at
                result = 'checked'
        else:
            logger.info(f"Inserting new mr: {local_mr.mr_id}, p_id: {local_mr.project_id}")
            existing_mr = local_mr
            session.add(existing_mr)
            result = 'inserted'

        session.commit()
        session.refresh(existing_mr)

        return existing_mr, result

@retry_on_exception()
def update_mr(session, mr: MR):
    
    with session:
        statement = select(MR).where(MR.id == mr.id)
        existing_mr = session.exec(statement).first()

        logger.info(f"Updating existing branch: {existing_mr.mr_id}, p_id: {existing_mr.project_id}")
        for key, value in mr.model_dump(exclude_unset=True).items():
            setattr(existing_mr, key, value)
        result = 'updated'

        session.commit()
        session.refresh(existing_mr)

        return existing_mr, result

@retry_on_exception()
def get_active_mrs(session, project_id):

    with session:
        statement = select(MR).where(
            MR.project_id == project_id
        )

        mrs = session.exec(statement).all()
        active_mrs =  [ mr for mr in mrs if (mr.processed_at is None or mr.processed_at < mr.updated_at ) and mr.updated_at > datetime.now() - timedelta(days=1) ]

        return active_mrs 

@retry_on_exception()
def insert_scan(session, scan: Scan):

    db_scan = Scan(
        scanner=scan.scanner,
        rules_version=scan.rules_version,
        project_path=scan.project_path,
        branch_name=scan.branch_name,
        branch_commit=scan.branch_commit,
        scanned_at=scan.scanned_at
    )

    with session:

        logger.info(f"Inserting new scan: {db_scan.scanner}")

        # Create a new branch record, considering is_main
        session.add(db_scan)
        session.commit()
        session.refresh(db_scan)
        return db_scan

@retry_on_exception()
def get_scan(session, scan: Scan):
    
    with session:
        statement = select(Scan).where(
            Scan.scanner == scan.scanner, 
            Scan.rules_version == scan.rules_version, 
            Scan.project_path == scan.project_path, 
            Scan.branch_name == scan.branch_name, 
            Scan.branch_commit == scan.branch_commit,
            Scan.parsers == scan.parsers,
        )
        
        existing_scan = session.exec(statement).first()
        return existing_scan
    
@retry_on_exception()
def upsert_obj(session, local_obj: DbObject):

    updated_at = datetime.now()

    with session:

        result = 'no'

        try:

            obj_table = DbObject.__table__

            local_obj.updated_at = updated_at
            local_obj.created_at = updated_at

            obj_data = local_obj.dict()

            obj_data_for_insert = {
                k: v for k, v in obj_data.items() 
                if k not in ("id")
            }

            obj_data_for_update = {
                k: v for k, v in obj_data.items() 
                if k not in ("id", "project_id", "branch_id", "name", "type", "created_at")
            }

            stmt_obj = insert(obj_table).values(**obj_data_for_insert)
            stmt_obj = stmt_obj.on_conflict_do_update(
                index_elements=[obj_table.c.project_id, obj_table.c.branch_id, obj_table.c.name, obj_table.c.type],
                set_=obj_data_for_update
            )
        
            session.execute(stmt_obj)
            session.commit()

            statement = select(DbObject).where(
                DbObject.project_id == local_obj.project_id,
                DbObject.branch_id == local_obj.branch_id,
                DbObject.name == local_obj.name,
                DbObject.type == local_obj.type,
            )
            existing_obj = session.exec(statement).first()
           
            result = 'upserted'

        except Exception as e:

            logger.error(f"Error with upserting object: {local_obj}, error: {e}")
            return local_obj, result
        
        try:

            incoming_field_names: Set[str] = set()

            field_table = DbObjectField.__table__
            
            for local_field in local_obj.fields:

                incoming_field_names.add(local_field.name)

                if local_field.object_id is None:
                    local_field.object_id = existing_obj.id

                field_data = local_field.dict()

                field_data_for_insert = {
                    k: v for k, v in field_data.items() 
                    if k not in ("id")
                }

                field_data_for_update = {
                    k: v for k, v in field_data.items() 
                    if k not in ("id", "object_id", "name")
                }
            
                stmt_field = insert(field_table).values(**field_data_for_insert)
                stmt_field = stmt_field.on_conflict_do_update(
                    index_elements=[field_table.c.object_id, field_table.c.name],
                    set_=field_data_for_update
                )
            
                session.execute(stmt_field)
                session.commit()
            
            for existing_field in existing_obj.fields:
                if existing_field.name not in incoming_field_names:
                    session.delete(existing_field)
                    session.commit()

            return existing_obj, result

        except Exception as e:

            logger.error(f"Error with upserting object fields: {local_obj}, error: {e}")
            return local_obj, result


@retry_on_exception()
def upsert_llm_score(session, local_obj: DbLLMScore):

    updated_at = datetime.now()

    with session:

        result = 'no'

        try:

            obj_table = DbLLMScore.__table__

            local_obj.updated_at = updated_at
            local_obj.created_at = updated_at

            obj_data = local_obj.dict()

            obj_data_for_insert = {
                k: v for k, v in obj_data.items() 
                if k not in ("id")
            }

            obj_data_for_update = {
                k: v for k, v in obj_data.items() 
                if k not in ("id", "field_id", "model", "prompt_ver", "created_at")
            }

            stmt_obj = insert(obj_table).values(**obj_data_for_insert)
            stmt_obj = stmt_obj.on_conflict_do_update(
                index_elements=[obj_table.c.field_id, obj_table.c.model, obj_table.c.prompt_ver],
                set_=obj_data_for_update
            )
        
            session.execute(stmt_obj)
            session.commit()

            statement = select(DbLLMScore).where(
                DbLLMScore.field_id == local_obj.field_id,
                DbLLMScore.model == local_obj.model,
                DbLLMScore.prompt_ver == local_obj.prompt_ver
            )

            existing_obj = session.exec(statement).first()
           
            result = 'upserted'

            return existing_obj, result

        except Exception as e:

            logger.error(f"Error with upserting llm score: {local_obj}, error: {e}")
            return local_obj, result


@retry_on_exception()
def get_score_rules(session):

    with session:

        statement = select(DbScoreRule)
        rules = session.exec(statement).all()

        return rules 


@retry_on_exception()
def get_objects_to_score(session, project_id, branch_id):

    with session:

        statement = select(DbObject).where(
            DbObject.project_id == project_id, 
            DbObject.branch_id == branch_id,
        ).options(
            joinedload(DbObject.fields)
        )

        results = session.scalars(statement).unique().all()
        result_objects = [ result for result in results ]

        return result_objects
    
