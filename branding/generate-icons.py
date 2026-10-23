#!/usr/bin/env python3
"""Render the shared original phone + unlocked padlock mark; no downloaded artwork."""
from pathlib import Path
from PIL import Image, ImageDraw
import json, subprocess, tempfile
root=Path(__file__).resolve().parents[1]
def icon(size, background=True):
    s=1024
    im=Image.new('RGBA',(s,s),(20,68,152,255) if background else (0,0,0,0))
    d=ImageDraw.Draw(im)
    if background:
        for y in range(s):
            t=y/s
            d.line((0,y,s,y),fill=(int(26-14*t),int(112-57*t),int(240-101*t),255))
    d.rounded_rectangle((270,170,690,850),radius=76,fill=(255,255,255,255))
    d.rounded_rectangle((309,214,651,804),radius=43,fill=(22,78,170,255))
    d.rounded_rectangle((411,235,549,253),radius=9,fill='white')
    d.rounded_rectangle((427,757,533,772),radius=7,fill='white')
    # Open shackle and rounded lock body.
    d.arc((489,355,749,615),180,359,fill=(104,238,218,255),width=48)
    d.line((513,482,513,558),fill=(104,238,218,255),width=48)
    d.rounded_rectangle((445,527,797,740),radius=48,fill=(104,238,218,255))
    d.ellipse((601,581,643,623),fill=(13,59,125,255))
    d.rounded_rectangle((614,603,630,658),radius=8,fill=(13,59,125,255))
    return im.resize((size,size),Image.Resampling.LANCZOS)
def save(path,size,background=True):
    p=root/path;p.parent.mkdir(parents=True,exist_ok=True);icon(size,background).save(p)
save(Path('branding/companion-1024.png'),1024)
for name,size in [('StoreLogo',50),('Square44x44Logo',44),('Square150x150Logo',150)]:
    save(Path('CdfProbe/Assets')/(name+'.png'),size)
splash=Image.new('RGBA',(620,300),(0,0,0,0));splash.alpha_composite(icon(180,False),(220,60));splash.save(root/'CdfProbe/Assets/SplashScreen.png')
assets=root/'iPhone/App/Assets.xcassets'
app=assets/'AppIcon.appiconset';app.mkdir(parents=True,exist_ok=True)
icon(1024).convert('RGB').save(app/'AppIcon.png')
(app/'Contents.json').write_text(json.dumps({'images':[{'filename':'AppIcon.png','idiom':'universal','platform':'ios','size':'1024x1024'}],'info':{'author':'xcode','version':1}},indent=2))
(assets/'Contents.json').write_text('{"info":{"author":"xcode","version":1}}')
for density,size in [('mdpi',48),('hdpi',72),('xhdpi',96),('xxhdpi',144),('xxxhdpi',192)]:
    save(Path('Android/app/src/main/res')/('mipmap-'+density)/'ic_launcher.png',size)
save(Path('Android/app/src/main/res/drawable/companion_mark.png'),432,False)
adaptive=root/'Android/app/src/main/res/mipmap-anydpi-v26';adaptive.mkdir(parents=True,exist_ok=True)
(adaptive/'ic_launcher.xml').write_text('''<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
<background android:drawable="@color/icon_background"/>
<foreground><inset android:inset="18%" android:drawable="@drawable/companion_mark"/></foreground>
<monochrome android:drawable="@drawable/ic_notification"/>
</adaptive-icon>''')
(root/'Android/app/src/main/res/values/colors.xml').write_text('<resources><color name="icon_background">#144498</color></resources>')
(root/'Android/app/src/main/res/drawable/ic_notification.xml').write_text('''<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="24dp" android:height="24dp" android:viewportWidth="24" android:viewportHeight="24">
<path android:fillColor="#FFFFFFFF" android:pathData="M7,2L16,2Q18,2 18,4L18,8L16,8L16,4L7,4L7,20L16,20L16,19L18,19L18,20Q18,22 16,22L7,22Q5,22 5,20L5,4Q5,2 7,2M15,9Q15,6 18,6Q21,6 21,9L19,9Q19,8 18,8Q17,8 17,9L17,11L22,11L22,18L13,18L13,11L15,11Z"/>
</vector>''')
print('Generated Windows, iOS and Android icons.')
