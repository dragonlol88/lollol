"""Authorization Manager with Bearer Authorization"""

__version__ = "0.0.1"

from ._authorize import PermissionManager
from ._authorize import LoginManager
from ._authorize import lookup_permission_obj
from ._utils import authorize_required
from ._utils import authorize_router
from ._utils import authorize_app
