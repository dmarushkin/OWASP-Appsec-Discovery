from sqlmodel import create_engine, SQLModel, Session, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import selectinload
from models import Project, Branch, Scan, MR, DbCodeObject, DbScoreRule
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
def upsert_code_obj(session, local_code_obj: DbCodeObject):

    updated_at = datetime.now()

    with session:

        statement = select(DbCodeObject).where(
            DbCodeObject.project_id == local_code_obj.project_id, 
            DbCodeObject.branch_id == local_code_obj.branch_id, 
            DbCodeObject.object_name == local_code_obj.object_name)
        
        existing_code_obj: DbCodeObject = session.exec(statement).first()

        if existing_code_obj :
            
            existing_code_obj.updated_at = updated_at
            existing_code_obj.ai_processed_at = local_code_obj.ai_processed_at
            existing_code_obj.file = local_code_obj.file
            existing_code_obj.line = local_code_obj.line
            existing_code_obj.severity = local_code_obj.severity
            existing_code_obj.tags = local_code_obj.tags
            
            '''
            for l_field in local_code_obj.fields:

                l_field_exist = False

                for db_field in existing_code_obj.fields:
                    if l_field.field_name == db_field.field_name:

                        db_field.field_type = l_field.field_type
                        db_field.file = l_field.file
                        db_field.line = l_field.line
                        db_field.severity = l_field.severity
                        db_field.tags = l_field.tags

                        l_field_exist = True

                if not l_field_exist:
                    existing_code_obj.fields.append(l_field)

            for db_field in existing_code_obj.fields:
                db_field_exist = False 

                for l_field in local_code_obj.fields:
                    if l_field.field_name == db_field.field_name:

                        db_field_exist = True

                if not db_field_exist:
                    existing_code_obj.fields.remove(db_field)
            '''

            existing_code_obj.fields.clear()
            existing_code_obj.fields.extend(local_code_obj.fields)
            existing_code_obj.properties.clear()
            existing_code_obj.properties.extend(local_code_obj.properties)

            result = 'updated'

        else:

            existing_code_obj = local_code_obj
            existing_code_obj.updated_at = updated_at
            existing_code_obj.created_at = updated_at

            session.add(existing_code_obj)

            result = 'inserted'

        session.commit()
        session.refresh(existing_code_obj)

        return existing_code_obj, result
    

@retry_on_exception()
def get_score_rules(session):

    with session:

        statement = select(DbScoreRule)
        rules = session.exec(statement).all()

        return rules 


@retry_on_exception()
def get_objects_to_score(session, project_id, branch_id):

    with session:

        statement = select(DbCodeObject).where(
            DbCodeObject.project_id == project_id, 
            DbCodeObject.branch_id == branch_id,
        ).options(
            selectinload(DbCodeObject.fields),    
            selectinload(DbCodeObject.properties) 
        )

        objects_to_score = session.exec(statement).all()
        result_objects = [ obj for obj in objects_to_score ]

        return result_objects
    
