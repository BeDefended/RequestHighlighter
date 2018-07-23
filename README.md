# Request Highlighter

Request Highlighter is a simple extension for Burp Suite tool (for both community and professional editions) that provides an automatic way to highlight HTTP requests based on headers content (eg. Host, User-Agent, Cookies, Auth token, custom headers etc.).
With Request Highlighter testers can easily identify and point out, within the Proxy history tab, requests belonging to different sessions, hosts, browsers or devices.

# Changelog

**0.3 20180723**
 - Removal of the highlight, from the proxy history, when user stop the highlighting
 - Introduce new context menu to show highlights present on a single request
 - Fix "repaint" after the highlighting of the proxy history

**0.2 20180716**
 - Add color selection
 - Add proxy history highlighting
 - Introduce gradle

**0.1 20180629**
 - First public release

# Installation

Request Highlighter can be installed through the Burp Suite BApp Store. From within Burp Suite, select the Extender tab, select the BApp Store, select Request Highlighter, and click install.

Manual installation: download the project from this repository and build it with gradle. 
Then in Burp Suite, select the Extender tab, click the Add button, and select the .jar file generated.

# Usage

1. Under the tab "Proxy" -> "HTTP History" select a request belonging to the type that you want to highlight

2. In the "Request" tab, select the header part containing the string of interest (eg. the session cookie, a specific user-agent, a custom header etc.) and right-click on it

    * NOTE: Currently **ONLY** headers (or parts of them) can be selected

3. On the context menu click on "Request Highlighter - add highlight" and select the color from the list of available ones

4. Every request (also inside the proxy history) that contains the string selected will be automatically highlighted with the selected color

    * NOTE: **BE AWARE of potential conflicts!** If a request matches with multiple strings, it will be highlighted with the color of the first string found in the request.

5. Repeat the process for every category of requests that you want to highlight (max 8)

6. To stop highlighting a specific type of requests: open the context menu and, under "Disable Request Highlighter" select the one that you want to disable. 
Otherwise select from the proxy history the request containing the highlight you want to disable, open the context menu and, under "Request Highlighter - Disable highlights in this request" select the one from the list.
