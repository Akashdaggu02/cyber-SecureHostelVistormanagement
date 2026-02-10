class AccessControlManager:
    """
    Implements Access Control Matrix (ACM) / Access Control List (ACL)
    
    SECURITY: Role-Based Access Control (RBAC)
    
    Subjects (Roles):
    1. Visitor
    2. Student
    3. Warden
    
    Objects (Resources/Actions):
    1. Request Entry
    2. Approve Visitor
    3. View Logs
    """
    
    def __init__(self):
        """
        Initialize Access Control Matrix
        
        Matrix Structure:
                    | Request Entry | Approve Visitor | View Logs |
        -----------------------------------------------------------|
        Visitor     |      ✓        |        ✗        |     ✗     |
        Student     |      ✗        |        ✓        |     ✗     |
        Warden      |      ✗        |        ✓        |     ✓     |
        """
        
        self.access_matrix = {
            'Visitor': {
                'Request Entry': True,
                'Approve Visitor': False,
                'View Logs': False,
                'Create Visit Request': True,
                'View Own Status': True
            },
            'Student': {
                'Request Entry': False,
                'Approve Visitor': True,
                'View Logs': False,
                'View Assigned Requests': True,
                'Reject Request': True,
                'Generate Signature': True
            },
            'Warden': {
                'Request Entry': False,
                'Approve Visitor': True,
                'View Logs': True,
                'View All Requests': True,
                'Override Approval': True,
                'Verify Signature': True,
                'View Decrypted Data': True,
                'Reject Request': True
            }
        }
    
    def check_access(self, subject, object_resource):
        """
        Check if subject (role) has access to object (resource/action)
        
        Args:
            subject: Role name (Visitor, Student, Warden)
            object_resource: Resource or action name
        
        Returns:
            bool: True if access granted, False otherwise
        
        SECURITY: Enforces access control policies
        """
        if subject not in self.access_matrix:
            return False
        
        if object_resource not in self.access_matrix[subject]:
            return False
        
        return self.access_matrix[subject][object_resource]
    
    def get_permissions(self, subject):
        """
        Get all permissions for a subject
        
        Args:
            subject: Role name
        
        Returns:
            dict: All permissions for the role
        """
        return self.access_matrix.get(subject, {})
    
    def get_allowed_actions(self, subject):
        """
        Get list of allowed actions for a subject
        
        Args:
            subject: Role name
        
        Returns:
            list: List of allowed action names
        """
        permissions = self.get_permissions(subject)
        return [action for action, allowed in permissions.items() if allowed]
    
    def get_denied_actions(self, subject):
        """
        Get list of denied actions for a subject
        
        Args:
            subject: Role name
        
        Returns:
            list: List of denied action names
        """
        permissions = self.get_permissions(subject)
        return [action for action, allowed in permissions.items() if not allowed]
    
    def add_permission(self, subject, object_resource, allow=True):
        """
        Add or modify permission (for dynamic access control)
        
        Args:
            subject: Role name
            object_resource: Resource or action name
            allow: Whether to allow (True) or deny (False)
        """
        if subject not in self.access_matrix:
            self.access_matrix[subject] = {}
        
        self.access_matrix[subject][object_resource] = allow
    
    def remove_permission(self, subject, object_resource):
        """
        Remove a permission entry
        
        Args:
            subject: Role name
            object_resource: Resource or action name
        """
        if subject in self.access_matrix:
            if object_resource in self.access_matrix[subject]:
                del self.access_matrix[subject][object_resource]
    
    def get_access_matrix_display(self):
        """
        Get formatted access control matrix for display
        
        Returns:
            str: Formatted matrix as string
        """
        output = "\nAccess Control Matrix:\n"
        output += "=" * 80 + "\n\n"
        
        # Get all unique objects
        all_objects = set()
        for permissions in self.access_matrix.values():
            all_objects.update(permissions.keys())
        
        all_objects = sorted(all_objects)
        
        # Header
        output += f"{'Role':<15} | "
        output += " | ".join([f"{obj:<20}" for obj in all_objects])
        output += "\n"
        output += "-" * 80 + "\n"
        
        # Rows
        for subject in sorted(self.access_matrix.keys()):
            output += f"{subject:<15} | "
            for obj in all_objects:
                allowed = self.access_matrix[subject].get(obj, False)
                symbol = "✓" if allowed else "✗"
                output += f"{symbol:<20} | "
            output += "\n"
        
        output += "=" * 80 + "\n"
        
        return output
    
    def validate_access_or_deny(self, subject, object_resource):
        """
        Validate access and raise exception if denied
        
        Args:
            subject: Role name
            object_resource: Resource or action name
        
        Raises:
            PermissionError: If access is denied
        
        SECURITY: Strict access control enforcement
        """
        if not self.check_access(subject, object_resource):
            raise PermissionError(
                f"Access Denied: {subject} cannot perform '{object_resource}'"
            )
        
        return True