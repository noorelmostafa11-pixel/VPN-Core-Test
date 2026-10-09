"""Build a self-contained Android experiment APK using installed SDK tools."""
import argparse,os,pathlib,shutil,subprocess,tempfile,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def run(*args):subprocess.run([str(a) for a in args],check=True)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',action='append',required=True,type=pathlib.Path);p.add_argument('--sdk',default=os.environ.get('ANDROID_HOME'));p.add_argument('--fixture-assets',type=pathlib.Path);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
    if not a.sdk:p.error('Android SDK required')
    sdk=pathlib.Path(a.sdk);jar=sdk/'platforms/android-35/android.jar';tools=sdk/'build-tools/35.0.0';a.output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td);classes=td/'classes';classes.mkdir();manifest=td/'AndroidManifest.xml'
        manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.noorelmostafa.vpnexperiment">
 <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
 <uses-permission android:name="android.permission.INTERNET"/><uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
 <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/><uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE"/>
 <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
 <application android:label="VPN Core Native TUN experiment" android:debuggable="true" android:extractNativeLibs="true" android:allowBackup="false" android:usesCleartextTraffic="true">
  <activity android:name="com.noorelmostafa.vpnexperiment.MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
  <service android:name="com.noorelmostafa.vpncore.VpnCoreVpnService" android:permission="android.permission.BIND_VPN_SERVICE" android:exported="false" android:foregroundServiceType="specialUse"><intent-filter><action android:name="android.net.VpnService"/></intent-filter><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="In-process native VPN tunnel"/></service>
 </application>
</manifest>''')
        sources=[* (ROOT/'sdk/android/src').rglob('*.java'),*(ROOT/'sdk/android/service').rglob('*.java'),*(ROOT/'sdk/android/experiment').rglob('*.java')]
        run('javac','-source','8','-target','8','-encoding','UTF-8','-classpath',jar,'-d',classes,*sources)
        dex=td/'dex';dex.mkdir();run(tools/'d8','--min-api','23','--lib',jar,'--output',dex,*classes.rglob('*.class'))
        resources=td/'resources.apk';args=[tools/'aapt2','link','-I',jar,'--manifest',manifest,'-o',resources]
        if a.fixture_assets:args+=['-A',a.fixture_assets]
        run(*args)
        unsigned=td/'unsigned.apk';shutil.copy2(resources,unsigned)
        with zipfile.ZipFile(unsigned,'a',zipfile.ZIP_DEFLATED) as z:
            z.write(dex/'classes.dex','classes.dex')
            for build in a.build:
                import json
                meta=json.loads((build/'build-provenance.json').read_text());abi=meta['target'].removeprefix('android-')
                for name in ('libvpn-core.so','libvpn-tls.so','libvpn-jni.so'):z.write(build/name,'lib/'+abi+'/'+name)
        aligned=td/'aligned.apk';run(tools/'zipalign','-P','16','-f','4',unsigned,aligned)
        key=td/'experiment.p12';run('keytool','-genkeypair','-keystore',key,'-storepass','vpn-experiment','-keypass','vpn-experiment','-alias','experiment','-keyalg','RSA','-keysize','2048','-validity','365','-dname','CN=VPN Core Experiment')
        run(tools/'apksigner','sign','--ks',key,'--ks-pass','pass:vpn-experiment','--out',a.output,aligned)
        run(tools/'apksigner','verify','--verbose',a.output)
    print('Experimental APK: '+str(a.output))
if __name__=='__main__':main()
