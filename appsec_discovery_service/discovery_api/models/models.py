from typing import List, Optional

from sqlmodel import SQLModel


####################################################
#   Auth models                                 ####
####################################################

class Token(SQLModel, table=False):
    access_token: str
    token_type: str

class UserData(SQLModel, table=False):
    username: str
    # service tokens (POST /tokens): scope "ingest" on project path prefixes; None for the admin
    scopes: Optional[List[str]] = None
    project_prefixes: Optional[List[str]] = None

    @property
    def is_service(self) -> bool:
        return self.scopes is not None

    def may_ingest(self, project_path: str) -> bool:
        """The admin may push to any external project, a service token to its prefixes only."""
        if not self.is_service:
            return True
        return "ingest" in (self.scopes or []) and any(
            project_path == p.rstrip("/") or project_path.startswith(p.rstrip("/") + "/")
            for p in self.project_prefixes or [])
