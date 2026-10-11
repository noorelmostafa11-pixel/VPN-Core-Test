import pathlib,runpy
runpy.run_path(str(pathlib.Path(__file__).resolve().parents[1]/'scripts/Validate-Go.py'),run_name='__main__')
