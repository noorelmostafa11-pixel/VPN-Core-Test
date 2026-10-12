"""Package the current Windows build; source history remains in Git."""
import pathlib,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[1]
subprocess.run([sys.executable,str(root/"scripts/Package-Target.py"),"--build",str(root/"bin"),*sys.argv[1:]],check=True)
