import os.path
import subprocess
import argparse

EXCLUDES = {
    'lexer.c',
    'lexer.h',
    'parser.c',
    'parser.h',
    'topt.h',
    'topt.c',
    'zbopt.h',
    'zbopt.c',
    'zitopt.h',
    'zitopt.c',
    'zopt.h',
    'zopt.c',
}

ZMAP_SOURCE_DIRS = [
    'lib',
    'src',
]

def visit(sources, dirname, names):
    for name in names:
        path = os.path.join(dirname, name)
        if not (name.endswith('.c') or name.endswith('.h')):
            continue
        if name in EXCLUDES or name.endswith('compat.c'):
            continue
        sources.append(path)

def main():
    parser = argparse.ArgumentParser(description="Format ZMap code")
    parser.add_argument('--format', dest='f', action='store_true', default=False)
    parser.add_argument('--zmap-source-root', default=".")
    a = parser.parse_args()

    sources = list()
    for directory in ZMAP_SOURCE_DIRS:
        path = os.path.join(a.zmap_source_root, directory)
        os.path.walk(path, visit, sources)
    if a.f:
        args = [
            "clang-format",
            "-style=file",
            "-i"
        ]
        args = args + sources
    else:
        check_script = os.path.join(a.zmap_source_root, "scripts", "check_style.sh")
        args = [ check_script ] + sources
    return subprocess.call(args)

if __name__ == '__main__':
    main()

