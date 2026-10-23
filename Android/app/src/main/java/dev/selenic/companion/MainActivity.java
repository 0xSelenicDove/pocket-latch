package dev.selenic.companion;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.*;
import android.view.*;
import android.widget.*;
import androidx.fragment.app.FragmentActivity;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricManager;
import androidx.activity.result.ActivityResultLauncher;
import com.journeyapps.barcodescanner.*;
import org.json.JSONObject;
import java.util.*;

public final class MainActivity extends FragmentActivity {
    Vault vault; ScrollView scroll; LinearLayout body,settings; TextView connection,request,status; Button approve,deny,scan;
    Switch biometric,automatic; boolean rendering,authenticating;
    String shown="",autoStarted="";
    final Handler handler=new Handler(Looper.getMainLooper());
    final ActivityResultLauncher<ScanOptions> scanner=registerForActivityResult(new ScanContract(),result->{
        if(result.getContents()!=null) {
            try {
                JSONObject invitation=Protocol.invitation(result.getContents(),System.currentTimeMillis()/1000);
                new AlertDialog.Builder(this).setTitle("Pair with this PC?")
                    .setMessage("Only continue if you scanned the code shown on your own Windows PC. Registration requires authentication.")
                    .setPositiveButton("Pair",(d,w)->createPairing(invitation)).setNegativeButton("Cancel",null).show();
            } catch(Exception e){error(e);}
        }
    });
    final Runnable refresh=new Runnable(){public void run(){renderState();handler.postDelayed(this,500);}};
    @Override public void onCreate(Bundle b) {
        super.onCreate(b);vault=new Vault(this);
        scroll=new ScrollView(this);scroll.setFillViewport(true);scroll.setBackgroundColor(Color.rgb(244,247,252));
        body=new LinearLayout(this);body.setOrientation(LinearLayout.VERTICAL);body.setPadding(dp(24),dp(24),dp(24),dp(32));scroll.addView(body);
        scroll.setOnApplyWindowInsetsListener((v,insets)->{body.setPadding(dp(24),dp(24)+insets.getSystemWindowInsetTop(),dp(24),dp(32)+insets.getSystemWindowInsetBottom());return insets;});
        setContentView(scroll);
        ImageView logo=new ImageView(this);logo.setImageResource(R.mipmap.ic_launcher);body.addView(logo,new LinearLayout.LayoutParams(dp(48),dp(48)));
        title("PocketLatch",30);text("Your phone. Your choice.",16);
        title("Authentication request",20);request=text("No request waiting.",16);
        approve=button("Approve",()->approveCurrent(shown));deny=button("Deny",()->{CompanionService s=CompanionService.instance;if(s!=null&&s.current(shown))s.reject("You denied the request.");});
        title("Connection",20);connection=text("Waiting for Bluetooth…",16);
        status=text("Ready to pair.",15);
        title("Pair with Windows",20);
        scan=button("Pair your PC",()->scanner.launch(new ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("Scan the QR shown on your Windows PC").setBeepEnabled(false).setOrientationLocked(false)));
        button("Settings",()->settings.setVisibility(settings.getVisibility()==View.VISIBLE?View.GONE:View.VISIBLE));
        LinearLayout home=body;
        settings=new LinearLayout(this);settings.setOrientation(LinearLayout.VERTICAL);settings.setVisibility(View.GONE);
        body.addView(settings);body=settings;
        title("Authentication approval",20);
        biometric=toggle("Use biometrics or screen lock");automatic=toggle("Automatically approve requests");
        biometric.setOnCheckedChangeListener((v,on)->options());automatic.setOnCheckedChangeListener((v,on)->options());
        text("With both on, open the notification to authenticate. With biometrics off and automatic approval on, Windows sign-in and compatible app requests can be approved while this phone is locked.",14);
        button("Manual pairing",()->new AlertDialog.Builder(this).setTitle("Create a pairing code?")
            .setMessage("This replaces this phone’s current pairing. Enter the new code in Windows → Manual setup within two minutes.")
            .setPositiveButton("Create code",(d,w)->createPairing(null)).setNegativeButton("Cancel",null).show());
        button("Remove pairing",()->new AlertDialog.Builder(this).setTitle("Remove this phone’s pairing?")
            .setMessage("Also unpair it in Windows Settings. Your Windows PIN will still work.")
            .setPositiveButton("Remove",(d,w)->{stopService(new Intent(this,CompanionService.class));vault.clear();renderState();})
            .setNegativeButton("Cancel",null).show());
        button("Notification settings",()->startActivity(new Intent(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(android.provider.Settings.EXTRA_APP_PACKAGE,getPackageName())));
        text("Allow sign-in alerts on your lock screen and in Do Not Disturb. Keep the Bluetooth service running. After restarting your phone, open this app once. If Redmi battery management stops it, allow background activity for PocketLatch.",14);
        button("Reconnect Bluetooth",this::connect);
        body=home;
    }
    int dp(int n){return (int)(n*getResources().getDisplayMetrics().density);}
    TextView text(String value,int size){TextView t=new TextView(this);t.setText(value);t.setTextSize(size);t.setTextColor(Color.rgb(48,62,82));t.setPadding(0,dp(6),0,dp(8));body.addView(t);return t;}
    void title(String value,int size){TextView t=text(value,size);t.setTypeface(null,Typeface.BOLD);t.setPadding(0,dp(20),0,dp(8));}
    Button button(String label,Runnable action) {
        Button b=new Button(this);b.setText(label);b.setAllCaps(false);b.setTextColor(Color.WHITE);b.setTextSize(16);
        GradientDrawable bg=new GradientDrawable();bg.setColor(Color.rgb(20,99,223));bg.setCornerRadius(dp(14));b.setBackground(bg);
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,dp(52));p.setMargins(0,dp(6),0,dp(6));body.addView(b,p);b.setOnClickListener(v->action.run());return b;
    }
    Switch toggle(String label){Switch s=new Switch(this);s.setText(label);s.setTextSize(16);s.setPadding(0,dp(12),0,dp(12));body.addView(s);return s;}
    void error(Exception e){new AlertDialog.Builder(this).setTitle("Couldn’t complete that").setMessage(e.getMessage()==null?"Unlock your phone and try again.":e.getMessage()).setPositiveButton("OK",null).show();}
    void options(){
        if(rendering)return;
        try {
            CompanionService s=CompanionService.instance;
            if(s!=null&&s.session!=null)throw new Exception("Wait for the current request to finish.");
            vault.options(biometric.isChecked(),automatic.isChecked());if(s!=null)s.grant.clear();
        }catch(Exception e){error(e);}renderState();
    }
    void createPairing(JSONObject invitation){
        try {
            if(!getSystemService(KeyguardManager.class).isDeviceSecure())
                throw new Exception("Set up an Android screen-lock PIN, pattern, or password before pairing.");

            CompanionService s=CompanionService.instance;if(s!=null&&s.session!=null)throw new Exception("Finish the current request first.");
            JSONObject p=new JSONObject().put("secret",invitation==null?Protocol.b64(Protocol.random(32)):invitation.getString("secret"))
                .put("keys",Protocol.b64(Protocol.random(64))).put("deviceId",invitation==null?"":invitation.getString("deviceId"))
                .put("expires",invitation==null?System.currentTimeMillis()/1000+120:invitation.getLong("expires"))
                .put("enrolled",false).put("qr",invitation!=null);
            vault.save(p);
            if(s!=null)s.resetPairing();connect();
            if(invitation==null){
                StringBuilder hex=new StringBuilder();for(byte b:Protocol.bytes(p,"secret",32))hex.append(String.format("%02x",b));
                String code=hex.toString();
                AlertDialog codeDialog=new AlertDialog.Builder(this).setTitle("Manual pairing code").setMessage(code)
                    .setPositiveButton("Copy code",(d,w)->{
                        ClipData clip=ClipData.newPlainText("Pairing code",code);
                        PersistableBundle extras=new PersistableBundle();extras.putBoolean("android.content.extra.IS_SENSITIVE",true);clip.getDescription().setExtras(extras);
                        ClipboardManager clipboard=getSystemService(ClipboardManager.class);clipboard.setPrimaryClip(clip);
                        handler.postDelayed(()->{
                            if(clipboard.hasPrimaryClip() && clipboard.getPrimaryClip().getItemCount()>0 &&
                                code.contentEquals(clipboard.getPrimaryClip().getItemAt(0).coerceToText(this))) clipboard.clearPrimaryClip();
                        },120000);
                    }).setNegativeButton("Close",null).create();
                codeDialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
                codeDialog.show();
            }
        }catch(Exception e){error(e);}
    }
    void connect(){
        ArrayList<String> missing=new ArrayList<>();
        String[] permissions=Build.VERSION.SDK_INT>=31?new String[]{Manifest.permission.BLUETOOTH_SCAN,Manifest.permission.BLUETOOTH_CONNECT}:new String[]{Manifest.permission.ACCESS_FINE_LOCATION};
        for(String p:permissions)if(checkSelfPermission(p)!=PackageManager.PERMISSION_GRANTED)missing.add(p);
        if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED)missing.add(Manifest.permission.POST_NOTIFICATIONS);
        if(!missing.isEmpty()){requestPermissions(missing.toArray(new String[0]),10);return;}
        try{startForegroundService(new Intent(this,CompanionService.class));}catch(Exception e){error(e);}
    }
    @Override public void onRequestPermissionsResult(int code,String[] permissions,int[] results){
        super.onRequestPermissionsResult(code,permissions,results);
        if(code==10){boolean granted=true;for(int r:results)granted&=r==PackageManager.PERMISSION_GRANTED;if(granted)connect();else status.setText("Allow Nearby devices and notifications to receive sign-in requests.");}
    }
    @Override public void onNewIntent(Intent i){super.onNewIntent(i);setIntent(i);}
    @Override public void onResume(){super.onResume();handler.post(refresh);try{if(vault.wake()!=null)connect();}catch(Exception e){error(e);}}
    @Override public void onPause(){handler.removeCallbacks(refresh);super.onPause();}
    void renderState(){
        if(vault==null)return;rendering=true;biometric.setChecked(vault.biometric());automatic.setChecked(vault.automatic());rendering=false;
        try {org.json.JSONObject pair=vault.wake();scan.setVisibility(pair!=null&&pair.optBoolean("enrolled")?View.GONE:View.VISIBLE);}catch(Exception ignored){}
        CompanionService s=CompanionService.instance;boolean waiting=s!=null&&s.pending!=null;
        String previous=shown;
        shown=waiting?s.pendingId:"";
        if(waiting && !shown.equals(previous))scroll.post(()->scroll.smoothScrollTo(0,0));
        request.setText(waiting?(Protocol.approvalPrompt(s.pending.optString("operation"),s.pending.optString("scenario")) + "\n" + (s.pending.optString("operation").equals("register")?"Confirm pairing on your PC.":Protocol.approvalDetail(s.pending.optString("scenario")))):"No request waiting.");
        approve.setVisibility(waiting?View.VISIBLE:View.GONE);deny.setVisibility(waiting?View.VISIBLE:View.GONE);
        biometric.setEnabled(!waiting);automatic.setEnabled(!waiting);
        if(s!=null){connection.setText(s.connectionStatus);status.setText(s.status);}
        if(waiting && !authenticating && !shown.equals(autoStarted)){
            boolean notificationApprove=shown.equals(getIntent().getStringExtra("request"))&&getIntent().getBooleanExtra("approve",false);
            boolean automaticRequest=vault.automatic()&&s.pending.optString("operation").equals("prepareUnlock");
            boolean qr=false;try{qr=s.pending.optString("operation").equals("register")&&vault.wake().optBoolean("qr");}catch(Exception ignored){}
            if(notificationApprove||automaticRequest||qr){autoStarted=shown;approveCurrent(shown);}
        }
    }
    void approveCurrent(String id){
        CompanionService s=CompanionService.instance;
        if(s==null||!s.current(id)||authenticating)return;
        android.util.Log.i("CompanionRequest","Approve selected");
        if(!s.needsAuthentication()){s.approve(id,false);return;}
        int types=BiometricManager.Authenticators.BIOMETRIC_STRONG|BiometricManager.Authenticators.DEVICE_CREDENTIAL;
        if(BiometricManager.from(this).canAuthenticate(types)!=BiometricManager.BIOMETRIC_SUCCESS){
            error(new Exception("Set up a fingerprint, supported face authentication, or screen lock in Android Settings."));return;
        }
        authenticating=true;
        BiometricPrompt prompt=new BiometricPrompt(this,getMainExecutor(),new BiometricPrompt.AuthenticationCallback(){
            @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r){authenticating=false;android.util.Log.i("CompanionRequest","Device authentication completed");s.approve(id,true);}
            @Override public void onAuthenticationError(int code,CharSequence text){authenticating=false;status.setText(text);if(s.current(id))s.reject("Authentication cancelled.");}
        });
        prompt.authenticate(new BiometricPrompt.PromptInfo.Builder().setTitle("Approve Windows request")
            .setSubtitle("Authenticate to approve your paired PC").setAllowedAuthenticators(types).build());
    }
}
