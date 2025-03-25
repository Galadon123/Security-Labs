# Insecure Direct Object Reference (IDOR) - Session Cookie Manipulation

## **Objective**

- Running the vulnerable `Application` in `Docker`
- Performing an `IDOR` attack through session cookie manipulation
- Understanding how attackers can bypass authentication and access unauthorized user profiles
- Identifying ways to detect and mitigate IDOR vulnerabilities in session management
- Demonstrating security best practices to prevent IDOR attacks in web applications

## **What is Session Cookie IDOR?**

Session Cookie IDOR is a specific type of web security vulnerability where an application uses weak or predictable session management mechanisms, allowing attackers to:
- Impersonate other users
- Access unauthorized user information
- Manipulate user profiles without proper authentication

![Session Cookie IDOR Diagram](assets/session-idor.svg)

## **How Does Session Cookie IDOR Work?**

### **1. Weak Session Generation**  
The attacker identifies that the application generates session cookies using a predictable or reversible method, such as:
- Base64 encoding of user email
- Simple hash of user information
- Lack of cryptographic signature

- **Example Session Cookie Generation:**  
  ```python
  def generate_session_cookie(email):
      return base64.b64encode(email.encode()).decode()
  ```

### **2. Cookie Manipulation**  
The attacker can:
- Decode the session cookie
- Modify the underlying user identifier
- Re-encode to create a new valid session cookie

### **3. Unauthorized Access**  
If the application does not implement robust session validation, the attacker gains access to another user's account or profile.

## **Types of Session Cookie IDOR Vulnerabilities**

![IDOR Session Types](assets/session-types.svg)

### 1. Email-Based Session Impersonation
Attackers can generate session cookies by knowing a user's email address, bypassing traditional login.

### 2. Profile Information Disclosure
Weak access controls allow viewing or modifying user profiles by manipulating requests.

### 3. Unauthorized Profile Editing
Attackers can change another user's profile information without proper authentication.

## **Impact of Session Cookie IDOR Vulnerabilities**

- **Identity Theft:** Impersonating other users
- **Privacy Breach:** Accessing personal user information
- **Data Manipulation:** Modifying user profiles without authorization
- **Authentication Bypass:** Circumventing login mechanisms

## **Hands-on with Session Cookie IDOR**

### **Setup and Installation**

1. **Pull the Docker Image**

   ```bash
   docker pull yourusername/idor-session-lab:latest
   ```

2. **Run the Docker Container**

   ```bash
   docker run -d -p 5000:5000 yourusername/idor-session-lab:latest
   ```

3. **Create a Load Balancer**

   Locate the `eth0` IP address and create a load balancer pointing to port 5000.

### **Exploring the Application**

This web application demonstrates session cookie IDOR vulnerabilities:
- User registration using email
- Weak session management
- Profile viewing and editing functionality

### **Exploiting the IDOR Vulnerability**

#### **1. Session Cookie Impersonation**

1. Register multiple user accounts with different emails
2. Observe the session cookie generation mechanism
3. Decode and manipulate session cookies to access other user profiles

#### **2. Profile Information Disclosure**

1. Login to one user account
2. Capture profile view/edit requests
3. Modify request parameters to access other users' profiles

#### **3. Unauthorized Profile Editing**

1. Identify the profile editing endpoint
2. Manipulate requests to modify another user's profile information

## **How to Prevent Session Cookie IDOR Vulnerabilities**

### 1. Implement Strong Session Management
- Use cryptographically secure session tokens
- Include server-side session validation
- Implement proper authentication checks for all sensitive actions

**Example Implementation:**
```python
import secrets

def generate_secure_session_token(user):
    return secrets.token_urlsafe()

def validate_session_token(token):
    # Validate against server-side session store
    session = SessionStore.get(token)
    return session is not None and not session.is_expired()
```

### 2. Use Secure, Httponly Cookies
- Set secure and HttpOnly flags
- Implement proper cookie scoping
- Use short-lived session tokens

```python
response.set_cookie(
    'session_token', 
    token, 
    httponly=True, 
    secure=True, 
    samesite='Strict'
)
```

### 3. Implement Multi-Factor Authentication
- Add additional verification layers
- Use time-based or context-based authentication challenges

### 4. Strict Access Control Checks
- Validate user permissions for every sensitive action
- Implement role-based access control (RBAC)

```python
def can_edit_profile(current_user, target_user):
    return current_user.id == target_user.id or current_user.is_admin()
```

### 5. Input Validation and Sanitization
- Validate all user inputs
- Implement strict type checking
- Sanitize and normalize input data

## **Conclusion**

Session Cookie IDOR vulnerabilities represent a significant security risk in web applications. By understanding the attack vectors and implementing robust security measures, developers can protect against unauthorized access and profile manipulation.

Remember that security is a continuous process requiring constant vigilance, testing, and improvement.
