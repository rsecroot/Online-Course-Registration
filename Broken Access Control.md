**BUG Author: [Ravi Sharma]**

**Product Information:**

- Vendor Homepage: (https://phpgurukul.com/online-course-registration-free-download/)
- Affected Version: [<= v3.1]
- BUG Author: Ravi Sharma

**Vulnerability Details**

- Type: Broken Access Control / Missing Authorization
- Affected URL: http://localhost/onlinecourse/
- Vulnerable Parameter:  /onlinecourse/admin/*.php - Authorization Module

**Vulnerable Files:**

- File Name: /admin/, /onlinecourse/
- Path:  /onlinecourse/admin/index.php, /onlinecourse/index.php

**Vulnerability Type**

- Broken Access Control / Missing Authorization CWE: CWE-284, CWE-862, CWE-639
- Severity Level: CRITICAL (CVSS: 9.9)

**Root Cause:**
The application lacks authorization checks on administrative functions, only verifying that users are authenticated without validating their role or permissions. This allows any logged-in user to access admin pages by directly navigating to admin URLs.
_**Missing Role in Session - Lines 13-16**_
$_SESSION['login']=$_POST['regno'];
$_SESSION['id']=$num['studentRegno'];
$_SESSION['sname']=$num['studentName'];

_**// MISSING: $_SESSION['role']=$num['role'];**_

**Impact:**

- An authenticated attacker with student privileges can gain complete administrative access, view and modify all user data, manage courses, escalate privileges, and compromise the entire system.

**Vulnerability Details:**
-------------------------------------------------------------------------------------------------------------------------------------

**Description:**
A critical vulnerability has been found in PHP Gurukul Online Course Registration System v3.1 where the authorization mechanism fails to verify user roles before serving administrative content. The application only checks if a user is authenticated but does not verify their authorization level.

The vulnerability exists in the session management implementation. The login process (index.php) creates session variables but omits role assignment:

$_SESSION['login']=$_POST['regno'];
$_SESSION['id']=$num['studentRegno'];  
$_SESSION['sname']=$num['studentName'];
// Missing: $_SESSION['role']=$num['role'];

Any authenticated student can access administrative functions by directly navigating to admin URLs (e.g., /onlinecourse/admin/user-log.php, /onlinecourse/admin/manage-users.php) without role verification. This allows privilege escalation from student to administrator.

An authenticated attacker with student privileges can gain complete administrative access, view and modify all user data, manage courses, escalate privileges, and compromise the entire system.

**Vulnerable Code Example:**

<img width="510" height="120" alt="Screenshot 2025-12-31 at 15 03 10" src="https://github.com/user-attachments/assets/0f49a690-0ef8-4655-ab9b-184dc7f11104" />



**Step-by-Step Reproduction**
**Attack Scenario**

First Scenario: 
- Attacker logs in with regular user credentials
- Attacker modifies url path to access admin URLs (e.g., /onlinecourse/admin/user-log.php, /onlinecourse/admin/manage-students.php)
- Application serves admin content without checking user role
- Attacker gains full administrative capabilities

Second Scenario:
- Attacker logs in with regular user credentials
- Intercept the request in Burpsuite
- Modify the request "_GET /onlinecourse/my-profile.php_" to "_/onlinecourse/admin/user-log.php, /onlinecourse/admin/manage-students.php_"
- And Observe the response that application serves admin content without checking user role

**Screenshots**
[Attach screenshots showing:]
- Login as regular user credentials
- Modifies url path to access admin URLs (e.g., /onlinecourse/admin/user-log.php, /onlinecourse/admin/manage-students.php) (dashboard/admin panel access)

<img width="1378" height="1139" alt="Screenshot 2025-12-31 at 11 40 31" src="https://github.com/user-attachments/assets/f32913e1-2043-411e-8778-7157fbd6fbac" />

<img width="1482" height="959" alt="Screenshot 2025-12-31 at 11 41 04" src="https://github.com/user-attachments/assets/3a593806-ce93-4cce-9011-54f285a49cee" />

<img width="1486" height="932" alt="Screenshot 2025-12-31 at 11 42 29" src="https://github.com/user-attachments/assets/e841836d-fe15-4203-a523-d688a351f9e0" />


**_Second Scenario:_**

<img width="1962" height="1088" alt="Screenshot 2025-12-31 at 11 37 59" src="https://github.com/user-attachments/assets/d472bc3e-0373-4ddb-883b-a13b36b343df" />

<img width="1943" height="1002" alt="Screenshot 2025-12-31 at 11 39 19" src="https://github.com/user-attachments/assets/05e39f01-594f-4545-aa62-2a3ea102a74d" />


**Impact Assessment**
The absence of role-based access control allows any authenticated user to:
- Access all administrative functions
- Bypass all authorization boundaries
- Escalate privileges without any challenge
- Perform actions reserved for administrators

**Affected Components**
- All administrative functionality accessible without authorization (- /admin/semester.php - Full semester management including deletion capability)
- Admin authentication system (SESSION, SEMESTER, DEPARTMENT, COURSE, REGISTRATION, MANAGE STUDENTS, ENROLL HISTORY, STUDENT LOGS, NEWS)
- User deletion functionality

**Remediation Recommendations**
**Immediate Fix**
1. Implement role-based access control (RBAC)
2. Store user roles in session during authentication
3. Verify roles before serving any privileged content
4. Use a centralized authorization function
5. Apply principle of least privilege
6. Conduct security code review

**Secure Code Example**
```php
if(!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    http_response_code(403);
    die('Access Denied');
}

OR

<?php
// /onlinecourse/admin/index.php - SECURE VERSION
session_start();

// Step 1: Check authentication (logged in?)
if(!isset($_SESSION['user_id'])) {
    header("Location: ../login.php");
    exit();
}

// Step 2: Check authorization (is admin?) - CRITICAL FIX!
if(!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    // Log the unauthorized attempt
    error_log(sprintf(
        "[%s] Unauthorized access attempt to %s by user %s (role: %s) from IP %s",
        date('Y-m-d H:i:s'),
        $_SERVER['REQUEST_URI'],
        $_SESSION['username'] ?? 'unknown',
        $_SESSION['role'] ?? 'none',
        $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ));
    
    // Deny access
    http_response_code(403);
    die('Access Denied: Administrator privileges required');
}

// Now safe to proceed - user is authenticated AND authorized
$user_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if($user_id === false) {
    die('Invalid user ID');
}

// ... process edit user ...
?>

**References**

- OWASP Broken Access Control: https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/ 
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
