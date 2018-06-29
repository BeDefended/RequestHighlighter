# Request Highlighter (v0.1)

Request Highlighter is a simple extension for Burp Suite tool (both community and professional editions) that provides an automatic way to highlight HTTP requests based on headers content (eg. Host, User-Agent, Cookies, Auth token, custom headers etc.).
With Request Highlighter testers can easily identify and visualize, within the Proxy history tab, requests belonging to different sessions, hosts, browsers or devices.

# Installation

For Manual installation, download the project from this repository and compile it. Then in Burp Suite, select the Extender tab, click the Add button, and select the .jar file produced.

# Usage

1. Under the tab "Proxy" -> "HTTP History" select a request belonging to the type that you want to highlight

2. In the "Request" tab, select the header part containing the string of interest (eg. the session cookie, a specific user-agent, a custom header etc.) and right-click on it

    * NOTE: Currently **ONLY** headers (or parts of them) can be selected

3. On the context menu click on "Request Highlighter - add highlight"

4. Starting from now, every request that contains the string selected will be automatically highlighted with the same color

    * NOTE: **BE AWARE of potential conflicts!** If a request matches with multiple strings, it will be highlighted with the color of the last string found in the request.

5. Repeat the process for every category of requests that you want to highlight (max 8)

6. To stop highlighting a specific type of requests: open the context menu and, under "Disable Request Highlighter" select the one that you want to disable.
